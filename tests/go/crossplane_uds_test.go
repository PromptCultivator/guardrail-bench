package guardrailbench_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PromptCultivator/guardrail-bench/internal/client"
	"github.com/PromptCultivator/guardrail-bench/internal/dataset"
	"github.com/PromptCultivator/guardrail-bench/internal/report"
	"github.com/PromptCultivator/guardrail-bench/internal/runner"
	"github.com/PromptCultivator/guardrail-bench/internal/scorer"
	"github.com/PromptCultivator/guardrail-bench/pkg/trifecta"
)

// TestCrossPlaneGoOrchestratorToPythonUDSWorkers proves Plane 1 (Go runner/scorer/report)
// drives Plane 2 (Python asyncio gRPC UDS workers) for LlamaFirewall and PIGuard alongside
// native Go trifecta_extproc and produces comparative NotInject over-defense accuracy.
func TestCrossPlaneGoOrchestratorToPythonUDSWorkers(t *testing.T) {
	t.Parallel()

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs repoRoot: %v", err)
	}
	fixturePath := filepath.Join(repoRoot, "datasets", "fixtures", "smoke_50.jsonl")
	samples, err := dataset.LoadJSONL(fixturePath)
	if err != nil {
		t.Fatalf("LoadJSONL: %v", err)
	}

	// Keep socket directory short for macOS 104-byte sun_path limit.
	sockDir, err := os.MkdirTemp("/tmp", "gb-xplane-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer func() { _ = os.RemoveAll(sockDir) }()

	runPythonWorker := func(adapterID string) scorer.ScoreReport {
		sockPath := filepath.Join(sockDir, adapterID+".sock")
		target := "unix://" + sockPath

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := exec.CommandContext(ctx, "uv", "run", "python", "-m", "bench_worker.server",
			"--adapter", adapterID,
			"--listen", target,
			"--mock",
		)
		cmd.Dir = repoRoot
		if err := cmd.Start(); err != nil {
			t.Fatalf("start python worker (%s): %v", adapterID, err)
		}
		defer func() {
			cancel()
			_ = cmd.Wait()
		}()

		grpcClient, err := client.DialGRPC(target)
		if err != nil {
			t.Fatalf("DialGRPC(%s): %v", target, err)
		}
		defer func() { _ = grpcClient.Close() }()

		// Wait for Python UDS gRPC server readiness.
		deadline := time.Now().Add(10 * time.Second)
		var healthErr error
		for time.Now().Before(deadline) {
			hCtx, hCancel := context.WithTimeout(ctx, 250*time.Millisecond)
			_, healthErr = grpcClient.Health(hCtx)
			hCancel()
			if healthErr == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if healthErr != nil {
			t.Fatalf("python worker %s failed Health check: %v", adapterID, healthErr)
		}

		art, err := runner.Run(ctx, grpcClient, samples, runner.Options{
			AdapterName:   adapterID,
			DatasetPath:   fixturePath,
			DatasetSHA256: "smoke50",
			Seed:          42,
			Repeats:       2,
			Concurrency:   2,
			Timeout:       5 * time.Second,
		})
		if err != nil {
			t.Fatalf("runner.Run(%s): %v", adapterID, err)
		}
		if art.ErrorCount != 0 {
			t.Fatalf("python worker %s returned %d RPC errors", adapterID, art.ErrorCount)
		}
		return scorer.Score(art, scorer.ScoreOptions{Seed: 42, BootstrapResamples: 200})
	}

	lfScore := runPythonWorker("llamafirewall")
	pgScore := runPythonWorker("piguard")

	trifectaClient := client.NewInProcessTrifectaClient(trifecta.DefaultEngineConfig())
	trifectaArt, err := runner.Run(context.Background(), trifectaClient, samples, runner.Options{
		AdapterName:   "trifecta_extproc",
		DatasetPath:   fixturePath,
		DatasetSHA256: "smoke50",
		Seed:          42,
		Repeats:       2,
		Concurrency:   2,
		Timeout:       5 * time.Second,
	})
	if err != nil {
		t.Fatalf("runner.Run(trifecta_extproc): %v", err)
	}
	trifectaScore := scorer.Score(trifectaArt, scorer.ScoreOptions{Seed: 42, BootstrapResamples: 200})

	// Verify deterministic stability (VFR == 0) across all three engines.
	for _, sc := range []scorer.ScoreReport{lfScore, pgScore, trifectaScore} {
		if sc.Stability.VFR != 0.0 {
			t.Fatalf("adapter %s had non-zero VFR=%.4f", sc.AdapterName, sc.Stability.VFR)
		}
	}

	// Verify comparative NotInject over-defense accuracy is populated for all three engines.
	if pgScore.Track1.NotInject.Total != 6 || lfScore.Track1.NotInject.Total != 6 || trifectaScore.Track1.NotInject.Total != 6 {
		t.Fatalf("expected 6 NotInject rows scored across all adapters")
	}
	if pgScore.Track1.NotInject.Accuracy.Point < lfScore.Track1.NotInject.Accuracy.Point {
		t.Fatalf("expected PIGuard NotInject accuracy (%.2f) >= LlamaFirewall (%.2f)",
			pgScore.Track1.NotInject.Accuracy.Point, lfScore.Track1.NotInject.Accuracy.Point)
	}

	md := report.RenderMarkdown([]scorer.ScoreReport{lfScore, pgScore, trifectaScore})
	t.Logf("\n%s", md)
	for _, name := range []string{"llamafirewall", "piguard", "trifecta_extproc"} {
		if !strings.Contains(md, name) {
			t.Fatalf("comparative Markdown report missing adapter %q", name)
		}
	}
}
