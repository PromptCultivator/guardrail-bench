package trifecta

import (
	"regexp"
	"sync"
)

// Direction identifies the flow direction of an evaluated message or tool event.
type Direction int

const (
	DirectionUnspecified Direction = iota
	DirectionInput
	DirectionOutput
	DirectionToolCall
	DirectionToolResult
)

// ToolAnnotations represents MCP tool metadata supplied alongside a tool call or result.
// Pointer fields distinguish explicitly provided hints from omitted hints.
type ToolAnnotations struct {
	ToolName        string
	ServerName      string
	ReadOnlyHint    *bool
	DestructiveHint *bool
	IdempotentHint  *bool
	OpenWorldHint   *bool
	TrustedServer   bool
}

// EffectiveToolHints holds resolved MCP capability flags after applying specification defaults
// and untrusted-server enforcement.
type EffectiveToolHints struct {
	ReadOnly    bool
	Destructive bool
	Idempotent  bool
	OpenWorld   bool
	Untrusted   bool
}

// SessionTaint captures the monotonic 3-leg Lethal Trifecta state for an agent session.
type SessionTaint struct {
	ReadsPrivate      bool
	ReadsUntrusted    bool
	SendsOut          bool
	TrifectaTriggered bool
}

var (
	// EchoLeak-style external Markdown image exfiltration: ![alt](https://...)
	reMarkdownExternalImage = regexp.MustCompile(`(?i)!\[[^\]]*\]\(\s*https?://[^)\s]+\s*\)`)
	// Reference-style Markdown image: ![alt][ref] combined with [ref]: https://...
	reMarkdownRefImageUse = regexp.MustCompile(`!\[[^\]]*\]\[[^\]]+\]`)
	reMarkdownRefURLDef   = regexp.MustCompile(`(?im)^\s*\[[^\]]+\]:\s*https?://\S+`)
	// HTML img tag exfiltration: <img ... src="https://...">
	reHTMLExternalImage = regexp.MustCompile(`(?i)<img\b[^>]*\bsrc\s*=\s*['"]?https?://`)
)

// EffectiveHints resolves MCP tool annotations according to the MCP specification.
//
// Strict Invariant: When tool.TrustedServer == false, readOnlyHint=true and
// openWorldHint=false MUST NOT be trusted; MCP conservative defaults
// (readOnly=false, destructive=true, idempotent=false, openWorld=true) are enforced.
func EffectiveHints(tool ToolAnnotations) EffectiveToolHints {
	// MCP spec defaults when hints are omitted or server is untrusted.
	eff := EffectiveToolHints{
		ReadOnly:    false,
		Destructive: true,
		Idempotent:  false,
		OpenWorld:   true,
		Untrusted:   !tool.TrustedServer,
	}
	if !tool.TrustedServer {
		return eff
	}
	if tool.ReadOnlyHint != nil {
		eff.ReadOnly = *tool.ReadOnlyHint
	}
	if tool.DestructiveHint != nil {
		eff.Destructive = *tool.DestructiveHint
	}
	if tool.IdempotentHint != nil {
		eff.Idempotent = *tool.IdempotentHint
	}
	if tool.OpenWorldHint != nil {
		eff.OpenWorld = *tool.OpenWorldHint
	}
	return eff
}

// HasExternalImageExfil returns true if text (or any decoded view) attempts EchoLeak-style
// external image rendering exfiltration.
func HasExternalImageExfil(text string, dec DecodeResult) bool {
	check := func(s string) bool {
		if reMarkdownExternalImage.MatchString(s) || reHTMLExternalImage.MatchString(s) {
			return true
		}
		if reMarkdownRefImageUse.MatchString(s) && reMarkdownRefURLDef.MatchString(s) {
			return true
		}
		return false
	}
	if check(text) {
		return true
	}
	for _, view := range dec.AllTexts() {
		if check(view) {
			return true
		}
	}
	return false
}

// TaintTracker maintains thread-safe monotonic per-session Lethal Trifecta state.
type TaintTracker struct {
	mu       sync.RWMutex
	sessions map[string]SessionTaint
}

// NewTaintTracker constructs an empty monotonic taint tracker.
func NewTaintTracker() *TaintTracker {
	return &TaintTracker{
		sessions: make(map[string]SessionTaint),
	}
}

// Reset removes all recorded taint state for sessionID.
func (t *TaintTracker) Reset(sessionID string) {
	if sessionID == "" {
		return
	}
	t.mu.Lock()
	delete(t.sessions, sessionID)
	t.mu.Unlock()
}

// Get returns the current taint state for sessionID.
func (t *TaintTracker) Get(sessionID string) SessionTaint {
	if sessionID == "" {
		return SessionTaint{}
	}
	t.mu.RLock()
	st := t.sessions[sessionID]
	t.mu.RUnlock()
	return st
}

// Transition updates the monotonic taint lattice for sessionID based on the incoming turn.
// It returns the updated SessionTaint, whether this turn triggered/completed the Lethal Trifecta,
// and any triggered reason categories.
func (t *TaintTracker) Transition(
	sessionID string,
	dir Direction,
	tool *ToolAnnotations,
	text string,
	dec DecodeResult,
	hasSensitiveData bool,
) (SessionTaint, bool, []string) {
	var turnPrivate, turnUntrusted, turnSendsOut bool
	var reasons []string

	switch dir {
	case DirectionToolResult:
		if tool != nil {
			eff := EffectiveHints(*tool)
			if eff.OpenWorld {
				turnUntrusted = true
			} else {
				turnPrivate = true
			}
		}
		if hasSensitiveData {
			turnPrivate = true
		}

	case DirectionToolCall:
		if tool != nil {
			eff := EffectiveHints(*tool)
			if eff.OpenWorld && !eff.ReadOnly {
				turnSendsOut = true
				if eff.Untrusted {
					reasons = append(reasons, "mcp_untrusted_outbound_tool")
				}
			}
		}

	case DirectionOutput:
		if HasExternalImageExfil(text, dec) {
			turnSendsOut = true
			reasons = append(reasons, "echoleak_markdown_image")
		}
	}

	if sessionID == "" {
		next := SessionTaint{
			ReadsPrivate:   turnPrivate,
			ReadsUntrusted: turnUntrusted,
			SendsOut:       turnSendsOut,
		}
		if next.ReadsPrivate && next.ReadsUntrusted && next.SendsOut {
			next.TrifectaTriggered = true
			reasons = append(reasons, "mcp_lethal_trifecta")
		}
		return next, next.TrifectaTriggered, reasons
	}

	t.mu.Lock()
	cur := t.sessions[sessionID]
	next := SessionTaint{
		ReadsPrivate:      cur.ReadsPrivate || turnPrivate,
		ReadsUntrusted:    cur.ReadsUntrusted || turnUntrusted,
		SendsOut:          cur.SendsOut || turnSendsOut,
		TrifectaTriggered: cur.TrifectaTriggered,
	}
	triggeredNow := false
	if next.ReadsPrivate && next.ReadsUntrusted && next.SendsOut {
		next.TrifectaTriggered = true
		triggeredNow = true
		reasons = append(reasons, "mcp_lethal_trifecta")
	}
	t.sessions[sessionID] = next
	t.mu.Unlock()

	return next, triggeredNow, reasons
}
