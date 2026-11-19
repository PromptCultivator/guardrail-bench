package guardrailbench_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PromptCultivator/guardrail-bench/internal/dataset"
)

func TestCLIMutateDecontaminateAndPythonSplitsParity(t *testing.T) {
	t.Parallel()

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs repoRoot: %v", err)
	}
	tmpDir := t.TempDir()

	// Build guardrail-bench CLI binary into temp dir.
	binPath := filepath.Join(tmpDir, "guardrail-bench")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/guardrail-bench")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build guardrail-bench failed: %v\n%s", err, out)
	}

	// 1. Verify smoke_50 manifest via CLI.
	valCmd := exec.Command(binPath, "validate",
		"--manifest", filepath.Join(repoRoot, "datasets", "manifests", "smoke_50.manifest.json"),
		"--base-dir", repoRoot,
	)
	if out, err := valCmd.CombinedOutput(); err != nil {
		t.Fatalf("cli validate failed: %v\n%s", err, out)
	}

	// 2. Two CLI runs of `mutate --seed 42` must produce byte-identical JSONL.
	mut1 := filepath.Join(tmpDir, "mut1.jsonl")
	mut2 := filepath.Join(tmpDir, "mut2.jsonl")
	fixturePath := filepath.Join(repoRoot, "datasets", "fixtures", "smoke_50.jsonl")
	for _, outPath := range []string{mut1, mut2} {
		cmd := exec.Command(binPath, "mutate",
			"--dataset", fixturePath,
			"--out", outPath,
			"--seed", "42",
			"--fraction", "0.5",
			"--only-malicious",
			"--include-originals",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cli mutate (%s) failed: %v\n%s", outPath, err, out)
		}
	}
	b1, err := os.ReadFile(mut1)
	if err != nil {
		t.Fatalf("read mut1: %v", err)
	}
	b2, err := os.ReadFile(mut2)
	if err != nil {
		t.Fatalf("read mut2: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("CLI mutate --seed 42 produced non-identical JSONL across two runs")
	}

	// 3. CLI decontaminate catches 92%-Jaccard near-duplicate and passes 80%-Jaccard control.
	refTokens := make([]string, 29)
	for i := range refTokens {
		refTokens[i] = fmt.Sprintf("alpha%02d", i)
	}
	refPath := filepath.Join(tmpDir, "refs.jsonl")
	refLine, _ := json.Marshal(dataset.ReferenceRecord{
		ID:     "train-1",
		Corpus: "mock_train",
		Text:   strings.Join(refTokens, " "),
	})
	if err := os.WriteFile(refPath, append(refLine, '\n'), 0o644); err != nil {
		t.Fatalf("write refs: %v", err)
	}

	evalPath := filepath.Join(tmpDir, "eval.jsonl")
	evalSamples := []dataset.Sample{
		{
			SampleID:         "near-92",
			Track:            dataset.TrackPromptInjection,
			AttackFamily:     "direct_override",
			Encoding:         "plain",
			IsMalicious:      true,
			GroundTruthSpans: []dataset.Span{},
			Turns: []dataset.Turn{{
				TurnIndex:           0,
				Direction:           "DIRECTION_INPUT",
				Role:                "user",
				Text:                strings.Join(refTokens[:27], " "), // 23/25 = 0.92
				ExpectedBlockAtTurn: true,
			}},
		},
		{
			SampleID:         "ctrl-80",
			Track:            dataset.TrackPromptInjection,
			AttackFamily:     "benign_general",
			Encoding:         "plain",
			IsMalicious:      false,
			GroundTruthSpans: []dataset.Span{},
			Turns: []dataset.Turn{{
				TurnIndex:           0,
				Direction:           "DIRECTION_INPUT",
				Role:                "user",
				Text:                strings.Join(refTokens[:24], " "), // 20/25 = 0.80
				ExpectedBlockAtTurn: false,
			}},
		},
	}
	if err := dataset.WriteJSONL(evalPath, evalSamples); err != nil {
		t.Fatalf("write eval: %v", err)
	}

	cleanPath := filepath.Join(tmpDir, "clean.jsonl")
	decontamFailCmd := exec.Command(binPath, "decontaminate",
		"--dataset", evalPath,
		"--refs", refPath,
		"--out-clean", cleanPath,
	)
	if out, err := decontamFailCmd.CombinedOutput(); err == nil {
		t.Fatalf("expected CLI decontaminate to fail on 92%% near-duplicate, got exit 0:\n%s", out)
	}

	// Decontaminating the cleaned output (only 80% control remains) must pass!
	decontamPassCmd := exec.Command(binPath, "decontaminate",
		"--dataset", cleanPath,
		"--refs", refPath,
	)
	if out, err := decontamPassCmd.CombinedOutput(); err != nil {
		t.Fatalf("expected CLI decontaminate on 80%% control to pass: %v\n%s", err, out)
	}

	// 4. Cross-language parity: Python build_splits.py --mode offline-synthetic -> Go strict VerifyManifest.
	pySplitsDir := filepath.Join(tmpDir, "py_splits")
	pyManifestsDir := filepath.Join(tmpDir, "py_manifests")
	pyCmd := exec.Command("uv", "run", "python",
		filepath.Join(repoRoot, "datasets", "scripts", "build_splits.py"),
		"--mode", "offline-synthetic",
		"--seed", "42",
		"--splits-dir", pySplitsDir,
		"--manifests-dir", pyManifestsDir,
	)
	pyCmd.Dir = repoRoot
	if out, err := pyCmd.CombinedOutput(); err != nil {
		t.Fatalf("build_splits.py failed: %v\n%s", err, out)
	}

	for _, name := range []string{"track1_injection", "track2_redaction", "track3_mcp_trifecta"} {
		mPath := filepath.Join(pyManifestsDir, name+".manifest.json")
		m, err := dataset.LoadManifest(mPath)
		if err != nil {
			t.Fatalf("LoadManifest(%s): %v", name, err)
		}
		if _, err := dataset.VerifyManifest(m, repoRoot); err != nil {
			t.Fatalf("VerifyManifest(%s) failed strict Go schema check: %v", name, err)
		}
	}
}
