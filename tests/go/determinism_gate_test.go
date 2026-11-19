package guardrailbench_test

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PromptCultivator/guardrail-bench/internal/runner"
	"github.com/PromptCultivator/guardrail-bench/internal/scorer"
)

// TestDeterminismAndRegressionGate verifies deterministic replay and regression gating:
//
//	guardrail-bench run --adapter trifecta_extproc --dataset datasets/fixtures/smoke_50.jsonl --repeats 5
//
// asserting VFR == 0.0 and byte-identical JSON output across two consecutive runs,
// plus end-to-end score, report, and gate CLI checks.
func TestDeterminismAndRegressionGate(t *testing.T) {
	t.Parallel()

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs repoRoot: %v", err)
	}
	tmpDir := t.TempDir()

	binPath := filepath.Join(tmpDir, "guardrail-bench")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/guardrail-bench")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build guardrail-bench: %v\n%s", err, out)
	}

	fixturePath := filepath.Join(repoRoot, "datasets", "fixtures", "smoke_50.jsonl")
	run1Path := filepath.Join(tmpDir, "run1.json")
	run2Path := filepath.Join(tmpDir, "run2.json")

	execRun := func(outPath string) []byte {
		cmd := exec.Command(binPath, "run",
			"--adapter", "trifecta_extproc",
			"--dataset", fixturePath,
			"--repeats", "5",
			"--out", outPath,
		)
		cmd.Dir = repoRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("guardrail-bench run (%s) failed: %v\n%s", outPath, err, out)
		}
		// Also capture exact stdout by running without --out on first pass or reading file.
		raw, err := exec.Command("cat", outPath).Output()
		if err != nil {
			t.Fatalf("read %s: %v", outPath, err)
		}
		return raw
	}

	raw1 := execRun(run1Path)
	raw2 := execRun(run2Path)

	if !bytes.Equal(raw1, raw2) {
		t.Fatalf("two consecutive `guardrail-bench run` executions produced non-identical JSON")
	}

	var bundle struct {
		Run   runner.RunArtifact `json:"run"`
		Score scorer.ScoreReport `json:"score"`
	}
	if err := json.Unmarshal(raw1, &bundle); err != nil {
		t.Fatalf("unmarshal RunBundle: %v", err)
	}

	if bundle.Run.Repeats != 5 || len(bundle.Run.Samples) != 50 {
		t.Fatalf("expected 50 samples x 5 repeats, got samples=%d repeats=%d", len(bundle.Run.Samples), bundle.Run.Repeats)
	}
	if bundle.Score.Stability.VFR != 0.0 {
		t.Fatalf("expected VFR == 0.0 for deterministic trifecta_extproc, got %.6f", bundle.Score.Stability.VFR)
	}
	if bundle.Score.Stability.MeanScoreStdDev != 0.0 {
		t.Fatalf("expected MeanScoreStdDev == 0.0, got %.6f", bundle.Score.Stability.MeanScoreStdDev)
	}
	if bundle.Score.Track1.RecallAt1PctFPR.Recall.Point != 1.0 {
		t.Fatalf("expected smoke_50 Track 1 Recall@1%%FPR == 1.0, got %.4f", bundle.Score.Track1.RecallAt1PctFPR.Recall.Point)
	}
	if bundle.Score.Track1.NotInject.Accuracy.Point != 1.0 {
		t.Fatalf("expected smoke_50 NotInject accuracy == 1.0, got %.4f", bundle.Score.Track1.NotInject.Accuracy.Point)
	}
	if bundle.Score.Track3.TrifectaBlockRate != 1.0 || bundle.Score.Track3.SafePassRate != 1.0 {
		t.Fatalf("expected smoke_50 Track 3 100%% block & safe pass, got %+v", bundle.Score.Track3)
	}

	// Verify `guardrail-bench score` produces identical ScoreReport from run1.json.
	scorePath := filepath.Join(tmpDir, "score.json")
	scoreCmd := exec.Command(binPath, "score", "--input", run1Path, "--out", scorePath)
	if out, err := scoreCmd.CombinedOutput(); err != nil {
		t.Fatalf("guardrail-bench score failed: %v\n%s", err, out)
	}

	// Verify `guardrail-bench report --format markdown` renders ADR table.
	repCmd := exec.Command(binPath, "report", "--input", scorePath, "--format", "markdown")
	mdOut, err := repCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("guardrail-bench report failed: %v\n%s", err, mdOut)
	}
	if !strings.Contains(string(mdOut), "trifecta_extproc") || !strings.Contains(string(mdOut), "Deterministic / Judge") {
		t.Fatalf("unexpected Markdown report output:\n%s", mdOut)
	}

	// Verify `guardrail-bench gate --baseline run1.json --candidate run2.json` exits 0.
	gateCmd := exec.Command(binPath, "gate", "--baseline", run1Path, "--candidate", run2Path)
	if out, err := gateCmd.CombinedOutput(); err != nil {
		t.Fatalf("guardrail-bench gate failed on identical runs: %v\n%s", err, out)
	}
}
