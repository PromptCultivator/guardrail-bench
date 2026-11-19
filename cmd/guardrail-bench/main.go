package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PromptCultivator/guardrail-bench/internal/client"
	"github.com/PromptCultivator/guardrail-bench/internal/dataset"
	"github.com/PromptCultivator/guardrail-bench/internal/mutator"
	"github.com/PromptCultivator/guardrail-bench/internal/report"
	"github.com/PromptCultivator/guardrail-bench/internal/runner"
	"github.com/PromptCultivator/guardrail-bench/internal/scorer"
	"github.com/PromptCultivator/guardrail-bench/pkg/trifecta"
)

// RunBundle pairs a canonical RunArtifact with its computed ScoreReport so
// `guardrail-bench run` emits self-contained, immediately auditable JSON.
type RunBundle struct {
	Run   runner.RunArtifact `json:"run"`
	Score scorer.ScoreReport `json:"score"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	subcmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch subcmd {
	case "validate":
		err = runValidate(args)
	case "decontaminate":
		err = runDecontaminate(args)
	case "mutate":
		err = runMutate(args)
	case "run":
		err = runBench(args)
	case "score":
		err = runScore(args)
	case "report":
		err = runReport(args)
	case "gate":
		err = runGate(args)
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", subcmd)
		printUsage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `guardrail-bench — vendor-neutral LLM & agent guardrail evaluation harness

Usage:
  guardrail-bench <command> [flags]

Commands:
  validate        Verify a dataset JSONL file against its SHA-256 manifest
  decontaminate   Run pre-flight SHA-256 and token 5-gram Jaccard decontamination gate
  mutate          Deterministically apply seeded evasion encodings to a dataset JSONL
  run             Execute a guardrail adapter across a dataset (with K repeats & open-loop pacing)
  score           Compute statistical efficacy, Char-IoU, RSLR, VFR, bootstrap CIs, and TCO
  report          Render Markdown ADR comparison tables or JSON summary
  gate            Enforce PR regression gates (Recall@1%%FPR, VFR==0, p99 latency)
`)
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "path to manifest JSON file")
	baseDir := fs.String("base-dir", ".", "base directory for resolving relative dataset paths")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" {
		return fmt.Errorf("--manifest is required")
	}
	m, err := dataset.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	samples, err := dataset.VerifyManifest(m, *baseDir)
	if err != nil {
		return err
	}
	fmt.Printf("OK: %s (%d rows, sha256=%s)\n", m.Name, len(samples), m.SHA256)
	return nil
}

func runDecontaminate(args []string) error {
	fs := flag.NewFlagSet("decontaminate", flag.ContinueOnError)
	datasetPath := fs.String("dataset", "", "path to evaluation dataset JSONL")
	refsPath := fs.String("refs", "", "path to reference training corpus JSONL")
	ngramSize := fs.Int("ngram", dataset.DefaultNGramSize, "token n-gram size")
	threshold := fs.Float64("threshold", dataset.DefaultJaccardThreshold, "Jaccard near-duplicate threshold")
	outClean := fs.String("out-clean", "", "optional output path for decontaminated JSONL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *datasetPath == "" || *refsPath == "" {
		return fmt.Errorf("--dataset and --refs are required")
	}

	evalSamples, err := dataset.LoadJSONL(*datasetPath)
	if err != nil {
		return err
	}
	refs, err := loadReferenceJSONL(*refsPath)
	if err != nil {
		return err
	}

	rep, clean := dataset.Decontaminate(evalSamples, refs, *ngramSize, *threshold)
	if *outClean != "" {
		if err := dataset.WriteJSONL(*outClean, clean); err != nil {
			return err
		}
	}

	raw, err := report.EncodeJSON(rep)
	if err != nil {
		return err
	}
	_, _ = os.Stdout.Write(raw)
	if !rep.Passed {
		return fmt.Errorf(
			"decontamination gate failed: %d verbatim overlaps, %d near-duplicates (threshold=%.2f)",
			len(rep.VerbatimOverlaps),
			len(rep.NearDuplicates),
			rep.Threshold,
		)
	}
	return nil
}

func runMutate(args []string) error {
	fs := flag.NewFlagSet("mutate", flag.ContinueOnError)
	datasetPath := fs.String("dataset", "", "path to input dataset JSONL")
	outPath := fs.String("out", "", "path to write mutated dataset JSONL")
	seed := fs.Uint64("seed", 42, "deterministic PRNG seed")
	transformsCSV := fs.String("transforms", "base64,double_base64,hex,zwj,homoglyph", "comma-separated mutator transforms")
	fraction := fs.Float64("fraction", 1.0, "stratified fraction in (0, 1.0]")
	onlyMalicious := fs.Bool("only-malicious", true, "mutate only is_malicious=true samples")
	includeOriginals := fs.Bool("include-originals", true, "include original rows before mutated variants")
	wrapEncoded := fs.Bool("wrap-encoded", false, "wrap encoded payloads in a decode directive prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *datasetPath == "" || *outPath == "" {
		return fmt.Errorf("--dataset and --out are required")
	}

	var transforms []mutator.Transform
	for _, part := range strings.Split(*transformsCSV, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		tr, err := mutator.ParseTransform(part)
		if err != nil {
			return err
		}
		transforms = append(transforms, tr)
	}

	samples, err := dataset.LoadJSONL(*datasetPath)
	if err != nil {
		return err
	}
	mutated, err := mutator.MutateDataset(samples, mutator.Options{
		Seed:               *seed,
		Transforms:         transforms,
		StratifiedFraction: *fraction,
		OnlyMalicious:      *onlyMalicious,
		IncludeOriginals:   *includeOriginals,
		WrapEncodedPrompt:  *wrapEncoded,
	})
	if err != nil {
		return err
	}
	if err := dataset.WriteJSONL(*outPath, mutated); err != nil {
		return err
	}
	fmt.Printf("Wrote %d samples to %s (seed=%d)\n", len(mutated), *outPath, *seed)
	return nil
}

func runBench(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	adapter := fs.String("adapter", "trifecta_extproc", "adapter ID (e.g. trifecta_extproc, llamafirewall, bedrock_checks)")
	target := fs.String("target", "", "gRPC adapter address (host:port or unix:///path); optional for in-process trifecta_extproc")
	datasetPath := fs.String("dataset", "", "path to evaluation dataset JSONL")
	manifestPath := fs.String("manifest", "", "optional dataset manifest JSON for pre-flight SHA-256 verification")
	seed := fs.Uint64("seed", 42, "deterministic PRNG seed")
	repeats := fs.Int("repeats", 1, "number of repeats K per sample for VFR stability probing")
	concurrency := fs.Int("concurrency", 1, "worker pool concurrency")
	rps := fs.Float64("rps", 0, "target open-loop Poisson requests/sec (0 = unthrottled)")
	timeout := fs.Duration("timeout", 10*time.Second, "per-RPC timeout")
	bootstrap := fs.Int("bootstrap", scorer.DefaultBootstrapResamples, "bootstrap resamples B for 95% CIs")
	includeTimings := fs.Bool("include-timings", false, "include volatile wall-clock/e2e timings in JSON output")
	sseGuarded := fs.String("sse-guarded-url", "", "optional guarded SSE endpoint for streaming tax probe")
	ssePassthrough := fs.String("sse-passthrough-url", "", "optional passthrough SSE endpoint for streaming tax probe")
	sseRequests := fs.Int("sse-requests", 50, "number of SSE probe requests per endpoint")
	outPath := fs.String("out", "", "optional output JSON path (defaults to stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *datasetPath == "" && *manifestPath == "" {
		return fmt.Errorf("--dataset or --manifest is required")
	}

	var samples []dataset.Sample
	var dsSHA, dsPath string
	if *manifestPath != "" {
		m, err := dataset.LoadManifest(*manifestPath)
		if err != nil {
			return err
		}
		samples, err = dataset.VerifyManifest(m, ".")
		if err != nil {
			return err
		}
		dsSHA = m.SHA256
		dsPath = m.Path
	} else {
		var err error
		dsPath = *datasetPath
		dsSHA, err = dataset.FileSHA256(dsPath)
		if err != nil {
			return err
		}
		samples, err = dataset.LoadJSONL(dsPath)
		if err != nil {
			return err
		}
	}

	var adpClient client.AdapterClient
	var err error
	if *target != "" {
		adpClient, err = client.DialGRPC(*target)
		if err != nil {
			return err
		}
	} else if strings.EqualFold(*adapter, "trifecta_extproc") {
		adpClient = client.NewInProcessTrifectaClient(trifecta.DefaultEngineConfig())
	} else {
		return fmt.Errorf("--target is required for out-of-process adapter %q", *adapter)
	}
	defer func() { _ = adpClient.Close() }()

	ctx := context.Background()
	art, err := runner.Run(ctx, adpClient, samples, runner.Options{
		AdapterName:   *adapter,
		DatasetPath:   dsPath,
		DatasetSHA256: dsSHA,
		Seed:          *seed,
		Repeats:       *repeats,
		Concurrency:   *concurrency,
		TargetRPS:     *rps,
		Timeout:       *timeout,
	})
	if err != nil {
		return err
	}

	if *sseGuarded != "" && *ssePassthrough != "" {
		sseRep, err := runner.MeasureSSEStreamingTax(ctx, *sseGuarded, *ssePassthrough, *sseRequests, 5, *timeout)
		if err != nil {
			return fmt.Errorf("SSE streaming tax probe failed: %w", err)
		}
		if art.Latency != nil {
			art.Latency.SSEStreamingTax = sseRep
		}
	}

	if !*includeTimings {
		art = art.WithoutTimings()
	}

	scoreRep := scorer.Score(art, scorer.ScoreOptions{
		Seed:               *seed,
		BootstrapResamples: *bootstrap,
	})

	bundle := RunBundle{Run: art, Score: scoreRep}
	raw, err := report.EncodeJSON(bundle)
	if err != nil {
		return err
	}
	return writeOutput(*outPath, raw)
}

func runScore(args []string) error {
	fs := flag.NewFlagSet("score", flag.ContinueOnError)
	inputPath := fs.String("input", "", "path to run JSON artifact")
	seed := fs.Uint64("seed", 42, "deterministic bootstrap PRNG seed")
	bootstrap := fs.Int("bootstrap", scorer.DefaultBootstrapResamples, "number of bootstrap resamples B")
	outPath := fs.String("out", "", "optional output JSON path (defaults to stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" {
		return fmt.Errorf("--input is required")
	}

	art, err := loadRunArtifact(*inputPath)
	if err != nil {
		return err
	}
	rep := scorer.Score(art, scorer.ScoreOptions{
		Seed:               *seed,
		BootstrapResamples: *bootstrap,
	})
	raw, err := report.EncodeJSON(rep)
	if err != nil {
		return err
	}
	return writeOutput(*outPath, raw)
}

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	inputsCSV := fs.String("input", "", "comma-separated score or run-bundle JSON paths")
	format := fs.String("format", "markdown", "output format: markdown or json")
	outPath := fs.String("out", "", "optional output path (defaults to stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputsCSV == "" {
		return fmt.Errorf("--input is required")
	}

	var scores []scorer.ScoreReport
	for _, p := range strings.Split(*inputsCSV, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		sc, err := loadScoreReport(p)
		if err != nil {
			return err
		}
		scores = append(scores, sc)
	}

	var out []byte
	var err error
	switch strings.ToLower(*format) {
	case "markdown", "md":
		out = []byte(report.RenderMarkdown(scores))
	case "json":
		out, err = report.EncodeJSON(scores)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported report format %q (expected markdown or json)", *format)
	}
	return writeOutput(*outPath, out)
}

func runGate(args []string) error {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	baselinePath := fs.String("baseline", "", "path to baseline score/run JSON")
	candidatePath := fs.String("candidate", "", "path to candidate score/run JSON")
	maxRecallDrop := fs.Float64("max-recall-drop", 0.01, "max allowed Recall@1%FPR drop (fraction)")
	maxNotInjectDrop := fs.Float64("max-notinject-drop", 0.01, "max allowed NotInject accuracy drop (fraction)")
	maxTrifectaDrop := fs.Float64("max-trifecta-drop", 0.01, "max allowed Track 3 trifecta block-rate drop")
	maxRSLRInc := fs.Float64("max-rslr-increase", 0.01, "max allowed Track 2 RSLR increase")
	maxP99Reg := fs.Float64("max-p99-regression", 0.15, "max allowed p99 latency regression ratio")
	requireZeroVFR := fs.Bool("require-zero-vfr", true, "require VFR == 0 on deterministic adapters")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *baselinePath == "" || *candidatePath == "" {
		return fmt.Errorf("--baseline and --candidate are required")
	}

	base, err := loadScoreReport(*baselinePath)
	if err != nil {
		return fmt.Errorf("load baseline: %w", err)
	}
	cand, err := loadScoreReport(*candidatePath)
	if err != nil {
		return fmt.Errorf("load candidate: %w", err)
	}

	policy := report.GatePolicy{
		MaxRecallAt1PctDrop:            *maxRecallDrop,
		MaxNotInjectDrop:               *maxNotInjectDrop,
		MaxTrifectaBlockDrop:           *maxTrifectaDrop,
		MaxRSLRIncrease:                *maxRSLRInc,
		MaxP99RegressionRatio:          *maxP99Reg,
		RequireZeroVFRForDeterministic: *requireZeroVFR,
	}

	res := report.EvaluateGate(base, cand, policy)
	raw, err := report.EncodeJSON(res)
	if err != nil {
		return err
	}
	_, _ = os.Stdout.Write(raw)
	if !res.Passed {
		return fmt.Errorf("PR regression gate failed for adapter %q", res.AdapterName)
	}
	return nil
}

func loadRunArtifact(path string) (runner.RunArtifact, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return runner.RunArtifact{}, err
	}
	// Support both RunBundle {"run": ..., "score": ...} and bare RunArtifact JSON.
	var probe struct {
		Run *runner.RunArtifact `json:"run"`
	}
	if err := json.Unmarshal(raw, &probe); err == nil && probe.Run != nil && probe.Run.AdapterName != "" {
		return *probe.Run, nil
	}
	var art runner.RunArtifact
	if err := json.Unmarshal(raw, &art); err != nil {
		return runner.RunArtifact{}, fmt.Errorf("parse RunArtifact %s: %w", path, err)
	}
	if art.AdapterName == "" {
		return runner.RunArtifact{}, fmt.Errorf("file %s does not contain a valid RunArtifact", path)
	}
	return art, nil
}

func loadScoreReport(path string) (scorer.ScoreReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return scorer.ScoreReport{}, err
	}
	// Support both RunBundle {"run": ..., "score": ...} and bare ScoreReport JSON.
	var probe struct {
		Score *scorer.ScoreReport `json:"score"`
	}
	if err := json.Unmarshal(raw, &probe); err == nil && probe.Score != nil && probe.Score.AdapterName != "" {
		return *probe.Score, nil
	}
	var sc scorer.ScoreReport
	if err := json.Unmarshal(raw, &sc); err != nil {
		return scorer.ScoreReport{}, fmt.Errorf("parse ScoreReport %s: %w", path, err)
	}
	if sc.AdapterName == "" {
		return scorer.ScoreReport{}, fmt.Errorf("file %s does not contain a valid ScoreReport", path)
	}
	return sc, nil
}

func writeOutput(outPath string, data []byte) error {
	if outPath == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(outPath, data, 0o644)
}

func loadReferenceJSONL(path string) ([]dataset.ReferenceRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open reference corpus %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var refs []dataset.ReferenceRecord
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var r dataset.ReferenceRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("reference line %d: %w", lineNo, err)
		}
		if r.ID == "" {
			r.ID = fmt.Sprintf("ref-%d", lineNo)
		}
		if r.Corpus == "" {
			r.Corpus = "declared_training_corpus"
		}
		refs = append(refs, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return refs, nil
}
