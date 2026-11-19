package scorer

import (
	"math"
	"strings"
)

// DefaultMonthlyVolumes are the canonical monthly request volumes V ∈ {0.5M, 1M, 5M, 10M}.
var DefaultMonthlyVolumes = []int64{
	500_000,
	1_000_000,
	5_000_000,
	10_000_000,
}

// AdapterRateCard captures verified API per-1k-TU pricing and monthly infrastructure capacity costs.
type AdapterRateCard struct {
	AdapterID            string  `json:"adapter_id"`
	RatePer1kTextUnits   float64 `json:"rate_per_1k_text_units_usd"`
	BaseMonthlyInfraUSD  float64 `json:"base_monthly_infra_usd"`
	ReplicasBase         int     `json:"replicas_base"`
	SustainedRPSPerUnit  float64 `json:"sustained_rps_per_replica"`
	PeakToAvgMultiplier  float64 `json:"peak_to_avg_multiplier"`
	PricingNotes         string  `json:"pricing_notes"`
}

// VolumeTCO projects monthly and annualized cost for one monthly request volume V.
type VolumeTCO struct {
	MonthlyRequests   int64   `json:"monthly_requests"`
	VolumeLabel       string  `json:"volume_label"`
	MonthlyAPICostUSD float64 `json:"monthly_api_cost_usd"`
	MonthlyInfraUSD   float64 `json:"monthly_infra_usd"`
	AnnualCostUSD     float64 `json:"annual_cost_usd"`
	ReplicasRequired  int     `json:"replicas_required"`
}

// TCOReport bundles empirical mean text units and annualized TCO across standard volumes.
type TCOReport struct {
	RateCard      AdapterRateCard `json:"rate_card"`
	MeanTextUnits float64         `json:"mean_text_units"`
	Projections   []VolumeTCO     `json:"projections"`
}

const secondsPerMonth = 30.4375 * 24 * 3600 // ~2,629,800s

// RateCardForAdapter returns the verified 2026 cost model documented in ARCHITECTURE.md.
func RateCardForAdapter(adapterName string) AdapterRateCard {
	key := strings.ToLower(strings.TrimSpace(adapterName))
	switch key {
	case "bedrock_checks":
		return AdapterRateCard{
			AdapterID:           "bedrock_checks",
			RatePer1kTextUnits:  0.18, // USD 0.08 prompt attack + USD 0.10 PII per 1k TU
			BaseMonthlyInfraUSD: 0.0,
			ReplicasBase:        0,
			SustainedRPSPerUnit: 0,
			PeakToAvgMultiplier: 3.0,
			PricingNotes:        "AWS InvokeGuardrailChecks: $0.08/1k TU prompt attack + $0.10/1k TU PII",
		}
	case "bedrock_apply":
		return AdapterRateCard{
			AdapterID:           "bedrock_apply",
			RatePer1kTextUnits:  0.25, // USD 0.15 content + USD 0.10 PII per 1k TU
			BaseMonthlyInfraUSD: 0.0,
			ReplicasBase:        0,
			SustainedRPSPerUnit: 0,
			PeakToAvgMultiplier: 3.0,
			PricingNotes:        "AWS ApplyGuardrail: $0.15/1k TU content + $0.10/1k TU PII (regex free)",
		}
	case "trifecta_extproc":
		return AdapterRateCard{
			AdapterID:           "trifecta_extproc",
			RatePer1kTextUnits:  0.0,
			BaseMonthlyInfraUSD: 57.67, // ARM64 Graviton Fargate HA baseline (2 tasks)
			ReplicasBase:        2,
			SustainedRPSPerUnit: 1500.0, // Native Go ext_proc easily sustains >1.5k req/s per task
			PeakToAvgMultiplier: 3.0,
			PricingNotes:        "ARM64 Graviton Fargate HA baseline ($57.67/mo for 2 tasks)",
		}
	case "granite_guardian":
		return AdapterRateCard{
			AdapterID:           "granite_guardian",
			RatePer1kTextUnits:  0.0,
			BaseMonthlyInfraUSD: 884.76, // 1x g5.2xlarge ($1.212/hr * 730h/mo) vLLM replica
			ReplicasBase:        1,
			SustainedRPSPerUnit: 18.0,
			PeakToAvgMultiplier: 3.0,
			PricingNotes:        "Self-hosted vLLM GPU (g5.2xlarge @ $1.212/hr amortized by req/s)",
		}
	case "llamafirewall":
		return AdapterRateCard{
			AdapterID:           "llamafirewall",
			RatePer1kTextUnits:  0.0,
			BaseMonthlyInfraUSD: 211.70, // 1x c7g.2xlarge ($0.29/hr * 730h/mo) HA compute baseline
			ReplicasBase:        2,
			SustainedRPSPerUnit: 65.0,
			PeakToAvgMultiplier: 3.0,
			PricingNotes:        "Compute-amortized CPU/ONNX deployment (2x c7g.xlarge @ $0.145/hr)",
		}
	case "piguard":
		return AdapterRateCard{
			AdapterID:           "piguard",
			RatePer1kTextUnits:  0.0,
			BaseMonthlyInfraUSD: 211.70,
			ReplicasBase:        2,
			SustainedRPSPerUnit: 75.0,
			PeakToAvgMultiplier: 3.0,
			PricingNotes:        "Compute-amortized DeBERTa/MOF classifier (2x c7g.xlarge)",
		}
	case "nemo_presidio":
		return AdapterRateCard{
			AdapterID:           "nemo_presidio",
			RatePer1kTextUnits:  0.0,
			BaseMonthlyInfraUSD: 262.80, // 2x m7g.xlarge ($0.18/hr * 730h/mo)
			ReplicasBase:        2,
			SustainedRPSPerUnit: 40.0,
			PeakToAvgMultiplier: 3.0,
			PricingNotes:        "Compute-amortized Presidio + NeMo Guardrails workers",
		}
	default:
		return AdapterRateCard{
			AdapterID:           adapterName,
			RatePer1kTextUnits:  0.0,
			BaseMonthlyInfraUSD: 57.67,
			ReplicasBase:        2,
			SustainedRPSPerUnit: 500.0,
			PeakToAvgMultiplier: 3.0,
			PricingNotes:        "Default HA container compute baseline",
		}
	}
}

// ProjectTCO computes annualized TCO across DefaultMonthlyVolumes using:
//
//	AnnualCost(V) = 12 * ( V * (ū / 1000) * r_unit + C_infra,monthly(V) )
func ProjectTCO(adapterName string, meanTextUnits float64, measuredP50WallMs float64) TCOReport {
	rc := RateCardForAdapter(adapterName)
	if meanTextUnits <= 0 {
		meanTextUnits = 1.0
	}

	// If we have empirical adapter latency for a self-hosted model, refine sustained RPS conservatively.
	rpsPerReplica := rc.SustainedRPSPerUnit
	if measuredP50WallMs > 0 && rc.BaseMonthlyInfraUSD > 0 && rc.AdapterID != "trifecta_extproc" {
		empRPS := 1000.0 / measuredP50WallMs
		if empRPS < rpsPerReplica {
			rpsPerReplica = empRPS
		}
	}

	projections := make([]VolumeTCO, 0, len(DefaultMonthlyVolumes))
	for _, vol := range DefaultMonthlyVolumes {
		monthlyAPI := float64(vol) * (meanTextUnits / 1000.0) * rc.RatePer1kTextUnits

		replicas := rc.ReplicasBase
		monthlyInfra := rc.BaseMonthlyInfraUSD
		if rc.BaseMonthlyInfraUSD > 0 && rpsPerReplica > 0 && rc.ReplicasBase > 0 {
			avgRPS := float64(vol) / secondsPerMonth
			peakRPS := avgRPS * rc.PeakToAvgMultiplier
			needed := int(math.Ceil(peakRPS / rpsPerReplica))
			if needed > replicas {
				unitCost := rc.BaseMonthlyInfraUSD / float64(rc.ReplicasBase)
				replicas = needed
				monthlyInfra = unitCost * float64(replicas)
			}
		}

		annual := 12.0 * (monthlyAPI + monthlyInfra)
		projections = append(projections, VolumeTCO{
			MonthlyRequests:   vol,
			VolumeLabel:       formatVolumeLabel(vol),
			MonthlyAPICostUSD: round2(monthlyAPI),
			MonthlyInfraUSD:   round2(monthlyInfra),
			AnnualCostUSD:     round2(annual),
			ReplicasRequired:  replicas,
		})
	}

	return TCOReport{
		RateCard:      rc,
		MeanTextUnits: round6(meanTextUnits),
		Projections:   projections,
	}
}

func formatVolumeLabel(v int64) string {
	switch v {
	case 500_000:
		return "0.5M/mo"
	case 1_000_000:
		return "1M/mo"
	case 5_000_000:
		return "5M/mo"
	case 10_000_000:
		return "10M/mo"
	default:
		return "custom"
	}
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
