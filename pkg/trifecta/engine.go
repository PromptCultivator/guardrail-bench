package trifecta

import (
	"math"
	"sort"
	"time"
	"unicode/utf8"
)

// EngineConfig configures the standalone Trifecta guardrail engine.
type EngineConfig struct {
	Decoder DecoderConfig
}

// DefaultEngineConfig returns production defaults.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		Decoder: DefaultDecoderConfig(),
	}
}

// EvalInput is the transport-agnostic request passed to Engine.Evaluate.
type EvalInput struct {
	SampleID  string
	SessionID string
	TurnIndex int
	Direction Direction
	Role      string
	Text      string
	MCPTool   *ToolAnnotations
}

// UsageMetrics summarizes deterministic character, text-unit, token, and wall-time counts.
type UsageMetrics struct {
	InputChars      int
	TextUnitsBilled int
	InputTokens     int
	AdapterWallMs   float64
}

// EvalResult is the deterministic output produced by Engine.Evaluate.
type EvalResult struct {
	Blocked             bool
	RiskScore           float64
	RedactedText        string
	Spans               []SpanFinding
	TriggeredCategories []string
	TaintState          SessionTaint
	Usage               UsageMetrics
	JudgeGraded         bool
	DecodeTruncated     bool
}

// Engine is the standalone Go guardrail engine powering the Envoy ext_proc baseline.
type Engine struct {
	cfg   EngineConfig
	taint *TaintTracker
}

// NewEngine creates a standalone Trifecta engine instance.
func NewEngine(cfg EngineConfig) *Engine {
	return &Engine{
		cfg:   cfg,
		taint: NewTaintTracker(),
	}
}

// ResetSession clears per-session monotonic taint flags.
func (e *Engine) ResetSession(sessionID string) {
	e.taint.Reset(sessionID)
}

// SessionState returns a snapshot of the session's current taint flags.
func (e *Engine) SessionState(sessionID string) SessionTaint {
	return e.taint.Get(sessionID)
}

// Evaluate runs bounded recursive decoding, secret/PII/source-code detection,
// prompt-injection classification, and monotonic MCP Lethal Trifecta enforcement.
// Output ordering is strictly deterministic.
func (e *Engine) Evaluate(in EvalInput) EvalResult {
	start := time.Now()

	dec := Decode(in.Text, e.cfg.Decoder)
	spans := DetectSensitiveSpans(in.Text, dec)
	injections := DetectPromptInjection(dec)

	hasSecretsOrPII := len(spans) > 0
	taintState, trifectaBlocked, taintReasons := e.taint.Transition(
		in.SessionID,
		in.Direction,
		in.MCPTool,
		in.Text,
		dec,
		hasSecretsOrPII,
	)

	catSet := make(map[string]struct{})
	addCat := func(c string) {
		if c != "" {
			catSet[c] = struct{}{}
		}
	}

	var risk float64
	blocked := false

	// 1. Lethal Trifecta halt (highest priority on outbound tool calls or EchoLeak assistant outputs).
	if trifectaBlocked {
		blocked = true
		risk = math.Max(risk, 1.0)
		for _, r := range taintReasons {
			addCat(r)
		}
	}

	// 2. Prompt injection directives.
	for _, inj := range injections {
		risk = math.Max(risk, inj.Confidence)
		addCat(inj.RuleID)
		if inj.ViaLayer != "plain" {
			addCat("encoded_evasion_" + inj.ViaLayer)
		}
		// Block imperative injections on user inputs and explicit indirect tool directives.
		if in.Direction == DirectionInput || in.Direction == DirectionUnspecified ||
			(in.Direction == DirectionToolResult && inj.RuleID == "prompt_injection_indirect_directive") {
			blocked = true
		}
	}

	// 3. Sensitive spans (PII, secrets, proprietary source code, encoded secrets).
	for _, sp := range spans {
		addCat("dlp_" + sp.EntityType)
		if sp.ViaEncoding != "" {
			addCat("encoded_secret_" + sp.ViaEncoding)
		}
		// Block DLP leaks on user prompts (Track 2) and outbound tool calls/outputs.
		// Local trusted TOOL_RESULT reads taint `reads_private` without blocking the local read.
		switch in.Direction {
		case DirectionInput, DirectionUnspecified:
			blocked = true
			risk = math.Max(risk, sp.Confidence)
		case DirectionToolCall:
			// Only block outbound open-world tool calls carrying sensitive data;
			// closed-world local writes (e.g. memory.store_memory) are permitted unless trifecta trips.
			if in.MCPTool == nil || EffectiveHints(*in.MCPTool).OpenWorld {
				blocked = true
				risk = math.Max(risk, sp.Confidence)
			}
		case DirectionOutput:
			if HasExternalImageExfil(in.Text, dec) || sp.EntityType == "AWS_ACCESS_KEY" ||
				sp.EntityType == "AWS_SECRET_KEY" || sp.EntityType == "GITHUB_TOKEN" ||
				sp.EntityType == "JWT_TOKEN" || sp.EntityType == "PEM_PRIVATE_KEY" {
				blocked = true
				risk = math.Max(risk, sp.Confidence)
			}
		case DirectionToolResult:
			// Taint recorded; do not block trusted internal reads, contribute small informational score.
			risk = math.Max(risk, 0.10)
		}
	}

	// Ensure monotonic non-blocking taint transitions carry informative continuous risk scores
	// for downstream FPR/PR-AUC telemetry without causing false blocks.
	if !blocked {
		legs := 0
		if taintState.ReadsPrivate {
			legs++
		}
		if taintState.ReadsUntrusted {
			legs++
		}
		if taintState.SendsOut {
			legs++
		}
		if legs == 2 {
			risk = math.Max(risk, 0.25)
		} else if legs == 1 {
			risk = math.Max(risk, 0.05)
		}
	}

	categories := make([]string, 0, len(catSet))
	for c := range catSet {
		categories = append(categories, c)
	}
	sort.Strings(categories)

	redacted := Redact(in.Text, spans)
	inputChars := utf8.RuneCountInString(in.Text)
	textUnits := (inputChars + 999) / 1000
	if textUnits == 0 && inputChars > 0 {
		textUnits = 1
	}
	// Minimum 1 billed text unit for non-empty/zero-char API parity.
	if textUnits == 0 {
		textUnits = 1
	}

	wallMs := float64(time.Since(start).Nanoseconds()) / 1e6

	return EvalResult{
		Blocked:             blocked,
		RiskScore:           risk,
		RedactedText:        redacted,
		Spans:               spans,
		TriggeredCategories: categories,
		TaintState:          taintState,
		Usage: UsageMetrics{
			InputChars:      inputChars,
			TextUnitsBilled: textUnits,
			InputTokens:     (inputChars + 3) / 4,
			AdapterWallMs:   wallMs,
		},
		JudgeGraded:     false,
		DecodeTruncated: dec.Truncated,
	}
}
