package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/PromptCultivator/guardrail-bench/internal/scorer"
)

// EncodeJSON deterministically formats any report struct with 2-space indentation and no HTML escaping.
func EncodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RenderMarkdown produces a Markdown comparison table across one or more scored adapters,
// keeping deterministic vs. model-judge verdicts in separate columns (Invariant #4) and always
// pairing attack recall with over-defense NotInject accuracy (Invariant #3).
func RenderMarkdown(reports []scorer.ScoreReport) string {
	sorted := append([]scorer.ScoreReport(nil), reports...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].AdapterName != sorted[j].AdapterName {
			return sorted[i].AdapterName < sorted[j].AdapterName
		}
		return sorted[i].ModelVersion < sorted[j].ModelVersion
	})

	var b strings.Builder
	b.WriteString("## guardrail-bench Evaluation Summary\n\n")

	// Table 1: Efficacy, Over-Defense & Stability (with explicit Deterministic vs Model-Judge separation)
	b.WriteString("### Efficacy, Over-Defense & Stability\n\n")
	b.WriteString("| Adapter | Version | Deterministic / Judge | Recall@1%FPR (95% CI) | NotInject Acc (1/2/3-trig) | Char-IoU | RSLR | MCP Trifecta Block / Safe | VFR | σ̄_s |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|\n")

	for _, r := range sorted {
		mode := r.JudgeSeparation.EvaluationMode
		r1 := r.Track1.RecallAt1PctFPR.Recall
		ni := r.Track1.NotInject
		t2 := r.Track2
		t3 := r.Track3

		fmt.Fprintf(&b, "| `%s` | `%s` | %s (%d det / %d judge) | %.1f%% [%.1f%%, %.1f%%] | %.1f%% (%.0f%%/%.0f%%/%.0f%%) | %.1f%% | %.1f%% | %.1f%% / %.1f%% | %.4f | %.4f |\n",
			r.AdapterName,
			r.ModelVersion,
			mode,
			r.JudgeSeparation.DeterministicTurns,
			r.JudgeSeparation.JudgeGradedTurns,
			r1.Point*100, r1.Lower*100, r1.Upper*100,
			ni.Accuracy.Point*100, ni.Subset1Trig*100, ni.Subset2Trig*100, ni.Subset3Trig*100,
			t2.MacroCharIoU.Point*100,
			t2.RSLR*100,
			t3.TrifectaBlockRate*100, t3.SafePassRate*100,
			r.Stability.VFR,
			r.Stability.MeanScoreStdDev,
		)
	}

	// Table 2: Latency & Annualized TCO Projections
	b.WriteString("\n### Tail Latency & Annualized TCO\n\n")
	b.WriteString("| Adapter | Wall p50 / p99 (ms) | E2E p50 / p99 (ms) | SSE ΔTTFT p99 (ms) | Mean TU | Annual @ 0.5M/mo | Annual @ 1M/mo | Annual @ 5M/mo | Annual @ 10M/mo |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")

	for _, r := range sorted {
		wallCol := "n/a"
		e2eCol := "n/a"
		sseCol := "n/a"
		if r.Latency != nil && r.Latency.EndToEnd.Count > 0 {
			wallCol = fmt.Sprintf("%.2f / %.2f", r.Latency.AdapterWall.P50Ms, r.Latency.AdapterWall.P99Ms)
			e2eCol = fmt.Sprintf("%.2f / %.2f", r.Latency.EndToEnd.P50Ms, r.Latency.EndToEnd.P99Ms)
			if r.Latency.SSEStreamingTax != nil {
				sseCol = fmt.Sprintf("%.2f", r.Latency.SSEStreamingTax.DeltaTTFTP99Ms)
			}
		}

		tcoByVol := make(map[int64]float64, len(r.TCO.Projections))
		for _, p := range r.TCO.Projections {
			tcoByVol[p.MonthlyRequests] = p.AnnualCostUSD
		}

		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %.2f | $%.2f | $%.2f | $%.2f | $%.2f |\n",
			r.AdapterName,
			wallCol,
			e2eCol,
			sseCol,
			r.TCO.MeanTextUnits,
			tcoByVol[500_000],
			tcoByVol[1_000_000],
			tcoByVol[5_000_000],
			tcoByVol[10_000_000],
		)
	}

	return b.String()
}
