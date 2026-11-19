package dataset

import (
	"fmt"
	"unicode/utf8"

	benchv1 "github.com/PromptCultivator/guardrail-bench/internal/gen/bench/v1"
)

// Track identifies one of the three canonical evaluation tracks.
const (
	TrackPromptInjection = "prompt_injection"
	TrackRedaction       = "redaction"
	TrackMCPTrifecta     = "mcp_trifecta"
)

// ValidTracks lists every supported track name.
var ValidTracks = map[string]bool{
	TrackPromptInjection: true,
	TrackRedaction:       true,
	TrackMCPTrifecta:     true,
}

// ValidEncodings lists every supported encoding label.
var ValidEncodings = map[string]bool{
	"plain":         true,
	"base64":        true,
	"double_base64": true,
	"hex":           true,
	"zwj":           true,
	"homoglyph":     true,
}

// ValidRoles lists valid message roles in dataset turns.
var ValidRoles = map[string]bool{
	"user":      true,
	"system":    true,
	"assistant": true,
	"tool":      true,
}

// Span represents a ground-truth sensitive span in UTF-8 character (rune) offsets [BeginOffset, EndOffset).
type Span struct {
	EntityType  string `json:"entity_type"`
	BeginOffset int    `json:"begin_offset"`
	EndOffset   int    `json:"end_offset"`
}

// ToolAnnotations mirrors MCP tool metadata with optional hint pointers so unset hints remain distinguishable.
type ToolAnnotations struct {
	ToolName        string `json:"tool_name"`
	ServerName      string `json:"server_name"`
	ReadOnlyHint    *bool  `json:"read_only_hint,omitempty"`
	DestructiveHint *bool  `json:"destructive_hint,omitempty"`
	IdempotentHint  *bool  `json:"idempotent_hint,omitempty"`
	OpenWorldHint   *bool  `json:"open_world_hint,omitempty"`
	TrustedServer   bool   `json:"trusted_server"`
}

// Turn represents a single turn in a single-turn or multi-turn evaluation trace.
type Turn struct {
	TurnIndex           int              `json:"turn_index"`
	Direction           string           `json:"direction"`
	Role                string           `json:"role"`
	Text                string           `json:"text"`
	MCPTool             *ToolAnnotations `json:"mcp_tool,omitempty"`
	ExpectedBlockAtTurn bool             `json:"expected_block_at_turn"`
}

// Sample is the canonical JSONL record shared across Tracks 1, 2, and 3.
type Sample struct {
	SampleID         string `json:"sample_id"`
	Track            string `json:"track"`
	AttackFamily     string `json:"attack_family"`
	Encoding         string `json:"encoding"`
	IsMalicious      bool   `json:"is_malicious"`
	IsHardNegative   bool   `json:"is_hard_negative"`
	GroundTruthSpans []Span `json:"ground_truth_spans"`
	Turns            []Turn `json:"turns"`
}

// ValidateSample enforces strict schema invariants on a single dataset row.
func ValidateSample(s Sample) error {
	if s.SampleID == "" {
		return fmt.Errorf("sample_id is required")
	}
	if !ValidTracks[s.Track] {
		return fmt.Errorf("sample %s: unsupported track %q", s.SampleID, s.Track)
	}
	if s.AttackFamily == "" {
		return fmt.Errorf("sample %s: attack_family is required", s.SampleID)
	}
	if !ValidEncodings[s.Encoding] {
		return fmt.Errorf("sample %s: unsupported encoding %q", s.SampleID, s.Encoding)
	}
	if s.IsMalicious && s.IsHardNegative {
		return fmt.Errorf("sample %s: cannot be both is_malicious and is_hard_negative", s.SampleID)
	}
	if len(s.Turns) == 0 {
		return fmt.Errorf("sample %s: turns must be non-empty", s.SampleID)
	}

	for i, turn := range s.Turns {
		if turn.TurnIndex != i {
			return fmt.Errorf("sample %s: turn[%d] has turn_index=%d (expected %d)",
				s.SampleID, i, turn.TurnIndex, i)
		}
		dir, ok := benchv1.Direction_value[turn.Direction]
		if !ok || benchv1.Direction(dir) == benchv1.Direction_DIRECTION_UNSPECIFIED {
			return fmt.Errorf("sample %s: turn[%d] has invalid direction %q",
				s.SampleID, i, turn.Direction)
		}
		if !ValidRoles[turn.Role] {
			return fmt.Errorf("sample %s: turn[%d] has invalid role %q",
				s.SampleID, i, turn.Role)
		}
		if turn.Text == "" {
			return fmt.Errorf("sample %s: turn[%d] has empty text", s.SampleID, i)
		}
		if !utf8.ValidString(turn.Text) {
			return fmt.Errorf("sample %s: turn[%d] contains invalid UTF-8", s.SampleID, i)
		}
		if turn.MCPTool != nil {
			if turn.MCPTool.ToolName == "" || turn.MCPTool.ServerName == "" {
				return fmt.Errorf("sample %s: turn[%d] mcp_tool requires non-empty tool_name and server_name",
					s.SampleID, i)
			}
		}
	}

	turn0RuneLen := utf8.RuneCountInString(s.Turns[0].Text)
	for i, sp := range s.GroundTruthSpans {
		if sp.EntityType == "" {
			return fmt.Errorf("sample %s: ground_truth_spans[%d] has empty entity_type", s.SampleID, i)
		}
		if sp.BeginOffset < 0 || sp.EndOffset <= sp.BeginOffset || sp.EndOffset > turn0RuneLen {
			return fmt.Errorf("sample %s: ground_truth_spans[%d] [%d, %d) out of bounds for rune length %d",
				s.SampleID, i, sp.BeginOffset, sp.EndOffset, turn0RuneLen)
		}
	}

	return nil
}

// ValidateDataset validates all samples and checks sample_id uniqueness.
func ValidateDataset(samples []Sample) error {
	seen := make(map[string]struct{}, len(samples))
	for i, s := range samples {
		if err := ValidateSample(s); err != nil {
			return fmt.Errorf("row %d: %w", i+1, err)
		}
		if _, exists := seen[s.SampleID]; exists {
			return fmt.Errorf("row %d: duplicate sample_id %q", i+1, s.SampleID)
		}
		seen[s.SampleID] = struct{}{}
	}
	return nil
}

// TurnToEvaluateRequest converts a dataset Turn into the wire protobuf EvaluateRequest.
func TurnToEvaluateRequest(sampleID, sessionID string, turn Turn) (*benchv1.EvaluateRequest, error) {
	dirVal, ok := benchv1.Direction_value[turn.Direction]
	if !ok || benchv1.Direction(dirVal) == benchv1.Direction_DIRECTION_UNSPECIFIED {
		return nil, fmt.Errorf("invalid direction %q", turn.Direction)
	}
	req := &benchv1.EvaluateRequest{
		SampleId:  sampleID,
		SessionId: sessionID,
		TurnIndex: int32(turn.TurnIndex),
		Direction: benchv1.Direction(dirVal),
		Role:      turn.Role,
		Text:      turn.Text,
	}
	if turn.MCPTool != nil {
		tool := &benchv1.ToolAnnotations{
			ToolName:      turn.MCPTool.ToolName,
			ServerName:    turn.MCPTool.ServerName,
			TrustedServer: turn.MCPTool.TrustedServer,
		}
		if turn.MCPTool.ReadOnlyHint != nil {
			v := *turn.MCPTool.ReadOnlyHint
			tool.ReadOnlyHint = &v
		}
		if turn.MCPTool.DestructiveHint != nil {
			v := *turn.MCPTool.DestructiveHint
			tool.DestructiveHint = &v
		}
		if turn.MCPTool.IdempotentHint != nil {
			v := *turn.MCPTool.IdempotentHint
			tool.IdempotentHint = &v
		}
		if turn.MCPTool.OpenWorldHint != nil {
			v := *turn.MCPTool.OpenWorldHint
			tool.OpenWorldHint = &v
		}
		req.McpTool = tool
	}
	return req, nil
}
