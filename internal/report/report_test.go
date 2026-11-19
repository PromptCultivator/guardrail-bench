package report_test

import (
	"strings"
	"testing"

	"github.com/PromptCultivator/guardrail-bench/internal/report"
	"github.com/PromptCultivator/guardrail-bench/internal/runner"
	"github.com/PromptCultivator/guardrail-bench/internal/scorer"
)

func sampleScoreReport(recall, notInject, vfr, p99 float64) scorer.ScoreReport {
	return scorer.ScoreReport{
		AdapterName:  "trifecta_extproc",
		ModelVersion: "0.2.0",
		JudgeSeparation: scorer.JudgeSeparation{
			EvaluationMode:       "deterministic",
			DeterministicTurns:   50,
			JudgeGradedTurns:     0,
			ContainsJudgeVerdict: false,
		},
		Track1: scorer.Track1Metrics{
			RecallAt1PctFPR: scorer.CalibratedRecallPoint{
				Alpha:  0.01,
				Recall: scorer.ConfidenceInterval{Point: recall, Lower: recall, Upper: recall},
			},
			NotInject: scorer.NotInjectMetrics{
				Total:       6,
				Allowed:     6,
				Accuracy:    scorer.ConfidenceInterval{Point: notInject, Lower: notInject, Upper: notInject},
				Subset1Trig: 1.0,
				Subset2Trig: 1.0,
				Subset3Trig: 1.0,
			},
		},
		Track2: scorer.Track2Metrics{
			MacroCharIoU: scorer.ConfidenceInterval{Point: 0.95, Lower: 0.90, Upper: 1.0},
			RSLR:         0.0,
		},
		Track3: scorer.Track3Metrics{
			TrifectaBlockRate: 1.0,
			SafePassRate:      1.0,
		},
		Stability: scorer.StabilityMetrics{
			Repeats: 5,
			VFR:     vfr,
		},
		Latency: &runner.LatencySummary{
			AdapterWall: runner.LatencyStats{Count: 50, P50Ms: 0.1, P99Ms: 0.4},
			EndToEnd:    runner.LatencyStats{Count: 50, P50Ms: 0.5, P99Ms: p99},
		},
		TCO: scorer.ProjectTCO("trifecta_extproc", 1.0, 0.1),
	}
}

func TestRenderMarkdownAndGateRegressionEnforcement(t *testing.T) {
	t.Parallel()

	base := sampleScoreReport(1.0, 1.0, 0.0, 2.0)

	md := report.RenderMarkdown([]scorer.ScoreReport{base})
	for _, want := range []string{"Deterministic / Judge", "Recall@1%FPR", "NotInject Acc", "Annual @ 10M/mo", "$692.04"} {
		if !strings.Contains(md, want) {
			t.Fatalf("Markdown report missing %q:\n%s", want, md)
		}
	}

	policy := report.DefaultGatePolicy()

	// Identical candidate must pass gate.
	if res := report.EvaluateGate(base, base, policy); !res.Passed {
		t.Fatalf("expected identical baseline/candidate to pass gate: %+v", res)
	}

	// Recall@1%FPR drop of 2% (> 1% limit) must fail gate.
	candLowRecall := sampleScoreReport(0.98, 1.0, 0.0, 2.0)
	if res := report.EvaluateGate(base, candLowRecall, policy); res.Passed {
		t.Fatalf("expected 2%% Recall@1%%FPR drop to fail gate")
	}

	// Non-zero VFR on deterministic adapter must fail gate.
	candFlip := sampleScoreReport(1.0, 1.0, 0.02, 2.0)
	if res := report.EvaluateGate(base, candFlip, policy); res.Passed {
		t.Fatalf("expected VFR > 0 on deterministic adapter to fail gate")
	}

	// Latency p99 regression of 20% (> 15% limit) must fail gate.
	candSlow := sampleScoreReport(1.0, 1.0, 0.0, 2.40)
	if res := report.EvaluateGate(base, candSlow, policy); res.Passed {
		t.Fatalf("expected 20%% p99 latency regression to fail gate")
	}
}
