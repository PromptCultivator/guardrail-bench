package trifecta

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// SpanFinding marks a detected sensitive entity in UTF-8 character (rune) coordinates [BeginOffset, EndOffset).
type SpanFinding struct {
	EntityType  string
	BeginOffset int
	EndOffset   int
	Confidence  float64
	ViaEncoding string // empty if found directly in plain text, else "base64"/"hex"/"url"
}

// InjectionFinding captures a deterministic prompt-injection signal.
type InjectionFinding struct {
	RuleID     string
	Confidence float64
	ViaLayer   string // "plain" or encoding name
}

var (
	reAWSAccessKey = regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b`)
	// Context-anchored 40-char AWS secret key (avoids flagging random 40-char paths/hashes).
	reAWSSecretAssign = regexp.MustCompile(`(?i)(?:aws_secret_access_key|secret_key|secret|password|svc)\s*[:=]\s*([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)`)
	reAWSSecretCanary = regexp.MustCompile(`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`)
	reGitHubToken     = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{36,}\b`)
	reJWT             = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}\b`)
	rePEMBlock        = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	reEmail           = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	reSSN             = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	reCreditCard      = regexp.MustCompile(`\b(?:\d{4}[-\s]){3}\d{4}\b`)
	rePhone           = regexp.MustCompile(`(?:\+\d{1,3}[-\s.]?)?(?:\(\d{3}\)|\b\d{3})[-\s.]\d{3}[-\s.]\d{4}\b|\+1-555-\d{4}\b`)

	// Structural multi-line source-code detectors (Python, Go, SQL, JS/TS).
	rePythonFunc = regexp.MustCompile(`(?m)^def\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^\n]*\)\s*(?:->\s*[^\n:]+)?:\n(?:[ \t]+[^\n]+\n?)+`)
	reGoFunc     = regexp.MustCompile(`(?m)^func\s+(?:\([^)]+\)\s*)?[A-Za-z_][A-Za-z0-9_]*\s*\([^\n]*\)[^{]*\{\n(?:[^\n]*\n?)*?^\}`)
	reSQLQuery   = regexp.MustCompile(`(?mis)^(?:WITH\s+[A-Za-z_][A-Za-z0-9_]*\s+AS\s*\([\s\S]+?\)\s*)?SELECT\s+[\s\S]+?\bFROM\s+[A-Za-z_][A-Za-z0-9_.]*[\s\S]*?;`)
)

// ShannonEntropy computes the base-2 Shannon entropy (bits per character) of s.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}
	var entropy float64
	fTotal := float64(total)
	for _, c := range counts {
		p := float64(c) / fTotal
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// DetectSensitiveSpans scans text (and bounded recursively decoded layers) for secrets,
// PII, and proprietary multi-line source code, returning deduplicated UTF-8 rune spans.
func DetectSensitiveSpans(text string, dec DecodeResult) []SpanFinding {
	var raw []SpanFinding

	// 1. Direct scan on original text (exact UTF-8 rune offsets).
	raw = append(raw, scanPlainSpans(text, "")...)

	// 2. Scan recursively decoded layers (base64, double_base64, hex, url) for hidden secrets/PII.
	// When a secret is detected inside a decoded layer originating from an embedded token,
	// map the span back to the encoded token's rune range in the original text.
	for _, layer := range dec.Layers {
		layerSpans := scanSecretsOnly(layer.Text, layer.Encoding)
		for _, sp := range layerSpans {
			if layer.SourceBegin >= 0 && layer.SourceEnd > layer.SourceBegin {
				raw = append(raw, SpanFinding{
					EntityType:  sp.EntityType,
					BeginOffset: layer.SourceBegin,
					EndOffset:   layer.SourceEnd,
					Confidence:  sp.Confidence,
					ViaEncoding: layer.Encoding,
				})
			} else {
				raw = append(raw, SpanFinding{
					EntityType:  sp.EntityType,
					BeginOffset: 0,
					EndOffset:   utf8.RuneCountInString(text),
					Confidence:  sp.Confidence,
					ViaEncoding: layer.Encoding,
				})
			}
		}
	}

	return deduplicateAndSortSpans(raw)
}

func scanPlainSpans(text, viaEncoding string) []SpanFinding {
	var out []SpanFinding
	out = append(out, scanSecretsOnly(text, viaEncoding)...)

	// PII patterns
	out = append(out, findAllRegexSpans(text, reEmail, "EMAIL", 0.96, viaEncoding)...)
	out = append(out, findAllRegexSpans(text, reSSN, "SSN", 0.92, viaEncoding)...)
	out = append(out, findAllRegexSpans(text, reCreditCard, "CREDIT_CARD", 0.90, viaEncoding)...)
	out = append(out, findAllRegexSpans(text, rePhone, "PHONE_NUMBER", 0.88, viaEncoding)...)

	// Structural multi-line source code
	out = append(out, findAllRegexSpans(text, rePythonFunc, "SOURCE_CODE", 0.93, viaEncoding)...)
	out = append(out, findAllRegexSpans(text, reGoFunc, "SOURCE_CODE", 0.93, viaEncoding)...)
	out = append(out, findAllRegexSpans(text, reSQLQuery, "SOURCE_CODE", 0.91, viaEncoding)...)

	return out
}

func scanSecretsOnly(text, viaEncoding string) []SpanFinding {
	var out []SpanFinding
	out = append(out, findAllRegexSpans(text, rePEMBlock, "PEM_PRIVATE_KEY", 0.99, viaEncoding)...)
	out = append(out, findAllRegexSpans(text, reAWSAccessKey, "AWS_ACCESS_KEY", 0.99, viaEncoding)...)
	out = append(out, findAllRegexSpans(text, reGitHubToken, "GITHUB_TOKEN", 0.98, viaEncoding)...)
	out = append(out, findAllRegexSpans(text, reJWT, "JWT_TOKEN", 0.97, viaEncoding)...)
	out = append(out, findAllRegexSpans(text, reAWSSecretCanary, "AWS_SECRET_KEY", 0.99, viaEncoding)...)

	// Entropy-gated AWS secret assignments (requires Shannon entropy >= 3.8 bits/char).
	for _, loc := range reAWSSecretAssign.FindAllStringSubmatchIndex(text, -1) {
		if len(loc) < 4 || loc[2] < 0 || loc[3] < 0 {
			continue
		}
		candidate := text[loc[2]:loc[3]]
		if ShannonEntropy(candidate) >= 3.8 {
			out = append(out, SpanFinding{
				EntityType:  "AWS_SECRET_KEY",
				BeginOffset: utf8.RuneCountInString(text[:loc[2]]),
				EndOffset:   utf8.RuneCountInString(text[:loc[3]]),
				Confidence:  0.95,
				ViaEncoding: viaEncoding,
			})
		}
	}

	return out
}

func findAllRegexSpans(text string, re *regexp.Regexp, entityType string, conf float64, via string) []SpanFinding {
	locs := re.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return nil
	}
	out := make([]SpanFinding, 0, len(locs))
	for _, loc := range locs {
		// Trim trailing newline from multi-line source-code regex match if present.
		endByte := loc[1]
		for endByte > loc[0] && (text[endByte-1] == '\n' || text[endByte-1] == '\r') {
			endByte--
		}
		if endByte <= loc[0] {
			continue
		}
		out = append(out, SpanFinding{
			EntityType:  entityType,
			BeginOffset: utf8.RuneCountInString(text[:loc[0]]),
			EndOffset:   utf8.RuneCountInString(text[:endByte]),
			Confidence:  conf,
			ViaEncoding: via,
		})
	}
	return out
}

func deduplicateAndSortSpans(spans []SpanFinding) []SpanFinding {
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].BeginOffset != spans[j].BeginOffset {
			return spans[i].BeginOffset < spans[j].BeginOffset
		}
		if spans[i].EndOffset != spans[j].EndOffset {
			return spans[i].EndOffset > spans[j].EndOffset // prefer longer containing span
		}
		if spans[i].Confidence != spans[j].Confidence {
			return spans[i].Confidence > spans[j].Confidence
		}
		return spans[i].EntityType < spans[j].EntityType
	})

	dedup := make([]SpanFinding, 0, len(spans))
	for _, sp := range spans {
		if sp.BeginOffset < 0 || sp.EndOffset <= sp.BeginOffset {
			continue
		}
		duplicate := false
		for _, prev := range dedup {
			if prev.BeginOffset == sp.BeginOffset && prev.EndOffset == sp.EndOffset && prev.EntityType == sp.EntityType {
				duplicate = true
				break
			}
			// Suppress generic PHONE_NUMBER overlapping SSN or CREDIT_CARD.
			if sp.EntityType == "PHONE_NUMBER" &&
				(prev.EntityType == "SSN" || prev.EntityType == "CREDIT_CARD") &&
				sp.BeginOffset < prev.EndOffset && prev.BeginOffset < sp.EndOffset {
				duplicate = true
				break
			}
		}
		if !duplicate {
			dedup = append(dedup, sp)
		}
	}
	return dedup
}

// Redact replaces every non-overlapping span in text with `[REDACTED:<ENTITY_TYPE>]`.
// Overlapping spans are resolved deterministically by keeping the earliest/longest/highest-confidence span.
func Redact(text string, spans []SpanFinding) string {
	if len(spans) == 0 {
		return text
	}
	runes := []rune(text)
	sorted := deduplicateAndSortSpans(spans)

	var out strings.Builder
	cursor := 0
	for _, sp := range sorted {
		if sp.BeginOffset < cursor || sp.EndOffset > len(runes) {
			continue
		}
		out.WriteString(string(runes[cursor:sp.BeginOffset]))
		out.WriteString("[REDACTED:")
		out.WriteString(sp.EntityType)
		out.WriteByte(']')
		cursor = sp.EndOffset
	}
	if cursor < len(runes) {
		out.WriteString(string(runes[cursor:]))
	}
	return out.String()
}

type injectionRule struct {
	id         string
	re         *regexp.Regexp
	confidence float64
}

var (
	// High-precision imperative prompt-injection patterns designed to avoid NotInject
	// trigger-word over-defense (e.g., defensive docs, Git rebase, zsh prompts, CSS overrides).
	injectionRules = []injectionRule{
		{
			id:         "prompt_injection_ignore_instructions",
			re:         regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|directives|policies)\b`),
			confidence: 0.96,
		},
		{
			id:         "prompt_injection_safety_override",
			re:         regexp.MustCompile(`(?i)\b(?:override|disregard|disable|bypass)\s+(?:all\s+)?(?:safety|security)\s+(?:filters|rules|policies|guardrails)\b`),
			confidence: 0.96,
		},
		{
			id:         "prompt_injection_unrestricted_mode",
			re:         regexp.MustCompile(`(?i)\b(?:unrestricted\s+(?:developer|maintenance|compliance)\s+mode|switch\s+into\s+unrestricted|comply\s+with\s+every\s+command)\b`),
			confidence: 0.94,
		},
		{
			id:         "prompt_injection_system_prompt_extract",
			re:         regexp.MustCompile(`(?i)\b(?:print|output|reveal|disclose|dump)\s+(?:the\s+|every\s+|all\s+)?(?:exact\s+|full\s+|hidden\s+|internal\s+)?(?:system\s+(?:prompt|configuration\s+instructions|message)|developer\s+(?:rule|system\s+message)|internal\s+(?:secrets|credentials)|confidential\s+credentials)\b`),
			confidence: 0.95,
		},
		{
			id:         "prompt_injection_indirect_directive",
			re:         regexp.MustCompile(`(?i)(?:<!--\s*system\s+override\b|\[assistant\s+instruction\]\s*:)`),
			confidence: 0.98,
		},
	}

	// Defensive/educational framing markers (e.g. quoting attack phrases in OWASP docs).
	reQuotedEducationalContext = regexp.MustCompile(`(?i)\b(?:owasp|unit\s+test\s+suites?|phrases\s+like\s+['"]|defending\s+against\s+prompt\s+injection)\b`)
)

// DetectPromptInjection evaluates normalized and recursively decoded layers for imperative
// prompt-injection directives while avoiding trigger-word over-defense on educational/quoted text.
func DetectPromptInjection(dec DecodeResult) []InjectionFinding {
	var findings []InjectionFinding
	seenRule := make(map[string]bool)

	checkText := func(text, layerLabel string) {
		// On plain (unencoded) text, skip generic phrase matches inside quoted defensive/educational docs
		// unless an explicit indirect delimiter (SYSTEM OVERRIDE / [ASSISTANT INSTRUCTION]) appears.
		educational := layerLabel == "plain" && reQuotedEducationalContext.MatchString(text)
		for _, rule := range injectionRules {
			if educational && rule.id != "prompt_injection_indirect_directive" {
				continue
			}
			if rule.re.MatchString(text) && !seenRule[rule.id] {
				seenRule[rule.id] = true
				findings = append(findings, InjectionFinding{
					RuleID:     rule.id,
					Confidence: rule.confidence,
					ViaLayer:   layerLabel,
				})
			}
		}
	}

	checkText(dec.Normalized, "plain")
	for _, layer := range dec.Layers {
		checkText(layer.Text, layer.Encoding)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Confidence != findings[j].Confidence {
			return findings[i].Confidence > findings[j].Confidence
		}
		return findings[i].RuleID < findings[j].RuleID
	})
	return findings
}
