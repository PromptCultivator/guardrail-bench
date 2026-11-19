package runner

import (
	"github.com/PromptCultivator/guardrail-bench/internal/dataset"
)

// SpanResult mirrors bench.v1.SpanFinding in JSON run artifacts.
type SpanResult struct {
	EntityType  string  `json:"entity_type"`
	BeginOffset int     `json:"begin_offset"`
	EndOffset   int     `json:"end_offset"`
	Confidence  float64 `json:"confidence"`
}

// TaintResult mirrors bench.v1.SessionTaint in JSON run artifacts.
type TaintResult struct {
	ReadsPrivate      bool `json:"reads_private"`
	ReadsUntrusted    bool `json:"reads_untrusted"`
	SendsOut          bool `json:"sends_out"`
	TrifectaTriggered bool `json:"trifecta_triggered"`
}

// UsageResult mirrors bench.v1.UsageMetrics in JSON run artifacts.
type UsageResult struct {
	InputChars      int     `json:"input_chars"`
	TextUnitsBilled int     `json:"text_units_billed"`
	InputTokens     int     `json:"input_tokens"`
	AdapterWallMs   float64 `json:"adapter_wall_ms,omitempty"`
}

// TurnOutcome captures the deterministic verdict and optional timing for one turn.
type TurnOutcome struct {
	TurnIndex           int           `json:"turn_index"`
	Direction           string        `json:"direction"`
	ExpectedBlockAtTurn bool          `json:"expected_block_at_turn"`
	Blocked             bool          `json:"blocked"`
	RiskScore           float64       `json:"risk_score"`
	RedactedText        string        `json:"redacted_text"`
	Spans               []SpanResult  `json:"spans"`
	TriggeredCategories []string      `json:"triggered_categories"`
	TaintState          TaintResult   `json:"taint_state"`
	Usage               UsageResult   `json:"usage"`
	JudgeGraded         bool          `json:"judge_graded"`
	E2EMs               float64       `json:"e2e_ms,omitempty"`
	ScheduleLatencyMs   float64       `json:"schedule_latency_ms,omitempty"`
	Error               string        `json:"error,omitempty"`
}

// RepeatResult captures one complete replay (all turns) of a sample at repeat k.
type RepeatResult struct {
	RepeatIndex int           `json:"repeat_index"`
	Blocked     bool          `json:"blocked"`     // True if any turn in the trace was blocked
	RiskScore   float64       `json:"risk_score"`  // Max risk_score across turns
	JudgeGraded bool          `json:"judge_graded"`
	Turns       []TurnOutcome `json:"turns"`
}

// SampleRun stores ground-truth metadata alongside K repeat evaluations for one sample.
type SampleRun struct {
	SampleID         string         `json:"sample_id"`
	Track            string         `json:"track"`
	AttackFamily     string         `json:"attack_family"`
	Encoding         string         `json:"encoding"`
	IsMalicious      bool           `json:"is_malicious"`
	IsHardNegative   bool           `json:"is_hard_negative"`
	Turn0Text        string         `json:"turn0_text"`
	GroundTruthSpans []dataset.Span `json:"ground_truth_spans"`
	Repeats          []RepeatResult `json:"repeats"`
}

// LatencyStats summarizes latency distributions in milliseconds.
type LatencyStats struct {
	Count  int     `json:"count"`
	MeanMs float64 `json:"mean_ms"`
	P50Ms  float64 `json:"p50_ms"`
	P95Ms  float64 `json:"p95_ms"`
	P99Ms  float64 `json:"p99_ms"`
	MaxMs  float64 `json:"max_ms"`
}

// LatencySummary aggregates internal adapter wall time, end-to-end RPC time,
// schedule-relative open-loop latency, and optional SSE streaming tax.
type LatencySummary struct {
	AdapterWall     LatencyStats `json:"adapter_wall"`
	EndToEnd        LatencyStats `json:"end_to_end"`
	ScheduleLatency LatencyStats `json:"schedule_latency"`
	SSEStreamingTax *SSEReport   `json:"sse_streaming_tax,omitempty"`
}

// SSEReport records guarded vs passthrough SSE Time-to-First-Token measurements.
type SSEReport struct {
	Requests          int          `json:"requests"`
	PassthroughTTFT   LatencyStats `json:"passthrough_ttft"`
	GuardedTTFT       LatencyStats `json:"guarded_ttft"`
	DeltaTTFTP50Ms    float64      `json:"delta_ttft_p50_ms"`
	DeltaTTFTP95Ms    float64      `json:"delta_ttft_p95_ms"`
	DeltaTTFTP99Ms    float64      `json:"delta_ttft_p99_ms"`
}

// RunArtifact is the canonical output produced by internal/runner.Run and consumed by internal/scorer.
type RunArtifact struct {
	SchemaVersion  string          `json:"schema_version"`
	AdapterName    string          `json:"adapter_name"`
	ModelVersion   string          `json:"model_version"`
	DatasetPath    string          `json:"dataset_path"`
	DatasetSHA256  string          `json:"dataset_sha256"`
	Seed           uint64          `json:"seed"`
	Repeats        int             `json:"repeats"`
	Concurrency    int             `json:"concurrency"`
	TargetRPS      float64         `json:"target_rps"`
	ErrorCount     int             `json:"error_count"`
	Latency        *LatencySummary `json:"latency,omitempty"`
	Samples        []SampleRun     `json:"samples"`
}

// WithoutTimings returns a deep-copied canonical RunArtifact with volatile wall-clock
// timings omitted so repeated deterministic runs serialize byte-for-byte identically.
func (a RunArtifact) WithoutTimings() RunArtifact {
	cp := a
	cp.Latency = nil
	cp.Samples = make([]SampleRun, len(a.Samples))
	for i, s := range a.Samples {
		sc := s
		sc.GroundTruthSpans = append([]dataset.Span(nil), s.GroundTruthSpans...)
		sc.Repeats = make([]RepeatResult, len(s.Repeats))
		for k, r := range s.Repeats {
			rc := r
			rc.Turns = make([]TurnOutcome, len(r.Turns))
			for tIdx, t := range r.Turns {
				tc := t
				tc.E2EMs = 0
				tc.ScheduleLatencyMs = 0
				tc.Usage.AdapterWallMs = 0
				tc.Spans = append([]SpanResult(nil), t.Spans...)
				tc.TriggeredCategories = append([]string(nil), t.TriggeredCategories...)
				rc.Turns[tIdx] = tc
			}
			sc.Repeats[k] = rc
		}
		cp.Samples[i] = sc
	}
	return cp
}
