package trifecta

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	// DefaultMaxDepth caps recursive encoding layers (e.g. triple base64).
	DefaultMaxDepth = 3
	// DefaultMaxDecodedBytes caps total decoded buffer bytes per evaluation (1 MiB) to prevent zip-bomb DoS.
	DefaultMaxDecodedBytes = 1 << 20
	// DefaultMaxCandidates caps candidate encoded tokens inspected per evaluation to bound CPU time.
	DefaultMaxCandidates = 64
)

// DecoderConfig bounds recursive decoding depth, memory, and CPU work.
type DecoderConfig struct {
	MaxDepth        int
	MaxDecodedBytes int
	MaxCandidates   int
}

// DefaultDecoderConfig returns safe production DoS-bounded defaults.
func DefaultDecoderConfig() DecoderConfig {
	return DecoderConfig{
		MaxDepth:        DefaultMaxDepth,
		MaxDecodedBytes: DefaultMaxDecodedBytes,
		MaxCandidates:   DefaultMaxCandidates,
	}
}

// DecodedLayer captures one decoded view produced from the input text.
type DecodedLayer struct {
	Depth       int
	Encoding    string // "url", "base64", "hex"
	SourceBegin int    // UTF-8 rune start index in original input (or -1 if derived from whole input)
	SourceEnd   int    // UTF-8 rune end index in original input (or -1 if derived from whole input)
	Text        string // NFKC + zero-width stripped decoded text
}

// DecodeResult contains the normalized root view and all bounded recursive decoded layers.
type DecodeResult struct {
	Original   string
	Normalized string
	Layers     []DecodedLayer
	Truncated  bool
	BytesUsed  int
}

// AllTexts returns the normalized input followed by every decoded layer text in deterministic order.
func (r DecodeResult) AllTexts() []string {
	out := make([]string, 0, 1+len(r.Layers))
	out = append(out, r.Normalized)
	for _, l := range r.Layers {
		out = append(out, l.Text)
	}
	return out
}

var (
	// Percent-encoded sequences like %2F or %3D.
	urlEncodedRe = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
)

// NormalizeUnicode applies Unicode NFKC normalization and strips stealth zero-width characters.
func NormalizeUnicode(s string) string {
	// Fast path: pure ASCII without stealth characters needs zero allocation.
	pureASCII := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			pureASCII = false
			break
		}
	}
	if pureASCII {
		return s
	}

	nfkc := norm.NFKC.String(s)
	var b strings.Builder
	b.Grow(len(nfkc))
	for _, r := range nfkc {
		if isStealthZeroWidth(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isStealthZeroWidth(r rune) bool {
	switch r {
	case '\u200b', // ZERO WIDTH SPACE
		'\u200c', // ZERO WIDTH NON-JOINER
		'\u200d', // ZERO WIDTH JOINER
		'\u2060', // WORD JOINER
		'\ufeff', // ZERO WIDTH NO-BREAK SPACE / BOM
		'\u00ad': // SOFT HYPHEN
		return true
	default:
		return false
	}
}

// Decode recursively normalizes and decodes URL, Base64, and Hex payloads within strict
// depth, byte-buffer, and candidate budgets.
func Decode(input string, cfg DecoderConfig) DecodeResult {
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = DefaultMaxDepth
	}
	if cfg.MaxDecodedBytes <= 0 {
		cfg.MaxDecodedBytes = DefaultMaxDecodedBytes
	}
	if cfg.MaxCandidates <= 0 {
		cfg.MaxCandidates = DefaultMaxCandidates
	}

	normalized := NormalizeUnicode(input)
	res := DecodeResult{
		Original:   input,
		Normalized: normalized,
	}

	// Guard against multi-megabyte raw inputs causing regex/decoding CPU spikes.
	maxScanBytes := cfg.MaxDecodedBytes * 2
	scanRoot := normalized
	if len(scanRoot) > maxScanBytes {
		scanRoot = truncateValidUTF8(scanRoot, maxScanBytes)
		res.Truncated = true
	}

	type workItem struct {
		text        string
		depth       int
		sourceBegin int
		sourceEnd   int
		useOrigSpan bool
	}

	// Map original rune spans when inspecting depth 0.
	queue := []workItem{{text: scanRoot, depth: 0, sourceBegin: -1, sourceEnd: -1, useOrigSpan: true}}
	seen := map[string]struct{}{scanRoot: {}}
	candidatesProcessed := 0

	addLayer := func(depth int, encoding, decoded string, srcBegin, srcEnd int) bool {
		if decoded == "" {
			return false
		}
		if len(decoded)+res.BytesUsed > cfg.MaxDecodedBytes {
			remaining := cfg.MaxDecodedBytes - res.BytesUsed
			res.Truncated = true
			if remaining <= 0 {
				return false
			}
			decoded = truncateValidUTF8(decoded, remaining)
			if decoded == "" {
				return false
			}
		}
		clean := NormalizeUnicode(decoded)
		if !isPlausibleText(clean) {
			return false
		}
		if _, dup := seen[clean]; dup {
			return false
		}
		seen[clean] = struct{}{}
		res.BytesUsed += len(clean)
		res.Layers = append(res.Layers, DecodedLayer{
			Depth:       depth,
			Encoding:    encoding,
			SourceBegin: srcBegin,
			SourceEnd:   srcEnd,
			Text:        clean,
		})
		if depth < cfg.MaxDepth {
			queue = append(queue, workItem{
				text:        clean,
				depth:       depth,
				sourceBegin: srcBegin,
				sourceEnd:   srcEnd,
				useOrigSpan: false,
			})
		}
		return true
	}

	// Lazily computed rune count for original input when locating embedded encoded spans.
	origRuneLen := -1
	getOrigRuneLen := func() int {
		if origRuneLen < 0 {
			origRuneLen = utf8.RuneCountInString(input)
		}
		return origRuneLen
	}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		if item.depth >= cfg.MaxDepth {
			continue
		}
		nextDepth := item.depth + 1

		// 1. URL percent-decoding if %XX present.
		if urlEncodedRe.MatchString(item.text) {
			if candidatesProcessed >= cfg.MaxCandidates {
				res.Truncated = true
				break
			}
			candidatesProcessed++
			if unesc, err := url.QueryUnescape(item.text); err == nil && unesc != item.text {
				addLayer(nextDepth, "url", unesc, item.sourceBegin, item.sourceEnd)
			} else if unescPath, err := url.PathUnescape(item.text); err == nil && unescPath != item.text {
				addLayer(nextDepth, "url", unescPath, item.sourceBegin, item.sourceEnd)
			}
		}

		// 2. Linear O(N) scan for hex and base64 candidates (avoids regex NFA overhead on large payloads).
		matches := scanEncodedCandidates(item.text, cfg.MaxCandidates)

		hexDecodedAt := make(map[int]bool)
		for _, m := range matches {
			if candidatesProcessed >= cfg.MaxCandidates {
				res.Truncated = true
				break
			}
			if m.kind == "base64" && hexDecodedAt[m.startByte] {
				continue
			}

			srcBegin, srcEnd := item.sourceBegin, item.sourceEnd
			if item.useOrigSpan {
				srcBegin, srcEnd = locateOriginalRuneSpan(input, getOrigRuneLen(), m.token, m.startByte, m.endByte)
			}

			switch m.kind {
			case "hex":
				if len(m.token) > cfg.MaxDecodedBytes*2 {
					res.Truncated = true
					continue
				}
				candidatesProcessed++
				decoded, err := hex.DecodeString(m.token)
				if err == nil && utf8.Valid(decoded) && isPlausibleText(string(decoded)) {
					if addLayer(nextDepth, "hex", string(decoded), srcBegin, srcEnd) {
						hexDecodedAt[m.startByte] = true
					}
				}

			case "base64":
				// Skip tokens that look like normal snake_case / hyphenated words or URLs without base64 signal.
				if !looksLikeBase64(m.token) {
					continue
				}
				// Guard decoded allocation size before decoding.
				estimatedBytes := (len(m.token) * 3) / 4
				if estimatedBytes > cfg.MaxDecodedBytes-res.BytesUsed {
					res.Truncated = true
					continue
				}
				candidatesProcessed++
				if decoded, ok := tryDecodeBase64(m.token); ok {
					addLayer(nextDepth, "base64", decoded, srcBegin, srcEnd)
				}
			}
		}

		// Check if deeper encoded payload remains when we hit MaxDepth so Truncated signals depth cap.
		if nextDepth == cfg.MaxDepth {
			for _, l := range res.Layers {
				if l.Depth == cfg.MaxDepth && hasEncodedCandidate(l.Text) {
					res.Truncated = true
					break
				}
			}
		}
	}

	return res
}

type tokenMatch struct {
	startByte int
	endByte   int
	token     string
	kind      string
}

func isWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func isBase64BodyByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
		b == '+' || b == '/' || b == '_' || b == '-'
}

// scanEncodedCandidates performs an O(N) byte scan for hex and base64 tokens.
func scanEncodedCandidates(s string, maxCandidates int) []tokenMatch {
	n := len(s)
	limit := maxCandidates * 2
	if limit < 16 {
		limit = 16
	}
	var out []tokenMatch

	// Scan for base64 runs (and detect pure even-length hex tokens in the same pass).
	i := 0
	for i < n && len(out) < limit {
		if !isBase64BodyByte(s[i]) {
			i++
			continue
		}
		start := i
		allHex := true
		for i < n && isBase64BodyByte(s[i]) {
			if !isHexByte(s[i]) {
				allHex = false
			}
			i++
		}
		eqCount := 0
		for i < n && s[i] == '=' && eqCount < 2 {
			allHex = false
			eqCount++
			i++
		}
		end := i
		if end-start < 16 {
			continue
		}
		tok := s[start:end]
		if allHex && (end-start)%2 == 0 {
			leftOK := start == 0 || !isWordByte(s[start-1])
			rightOK := end == n || !isWordByte(s[end])
			if leftOK && rightOK {
				out = append(out, tokenMatch{startByte: start, endByte: end, token: tok, kind: "hex"})
			}
		}
		out = append(out, tokenMatch{startByte: start, endByte: end, token: tok, kind: "base64"})
	}

	sort.Slice(out, func(a, b int) bool {
		if out[a].startByte != out[b].startByte {
			return out[a].startByte < out[b].startByte
		}
		if out[a].endByte != out[b].endByte {
			return out[a].endByte < out[b].endByte
		}
		return out[a].kind > out[b].kind // "hex" before "base64"
	})
	return out
}

func locateOriginalRuneSpan(orig string, origRuneLen int, token string, normStartByte, normEndByte int) (int, int) {
	if idx := strings.Index(orig, token); idx >= 0 {
		begin := utf8.RuneCountInString(orig[:idx])
		end := begin + utf8.RuneCountInString(token)
		if end <= origRuneLen {
			return begin, end
		}
	}
	// Fallback: map from byte range bounds safely.
	if normStartByte >= 0 && normEndByte <= len(orig) && normStartByte < normEndByte {
		begin := utf8.RuneCountInString(orig[:normStartByte])
		end := utf8.RuneCountInString(orig[:normEndByte])
		if end <= origRuneLen {
			return begin, end
		}
	}
	return -1, -1
}

func hasEncodedCandidate(s string) bool {
	for _, m := range scanEncodedCandidates(s, 8) {
		switch m.kind {
		case "hex":
			if dec, err := hex.DecodeString(m.token); err == nil && utf8.Valid(dec) && isPlausibleText(string(dec)) {
				return true
			}
		case "base64":
			if looksLikeBase64(m.token) {
				if _, ok := tryDecodeBase64(m.token); ok {
					return true
				}
			}
		}
	}
	return false
}

func looksLikeBase64(tok string) bool {
	if len(tok) < 16 {
		return false
	}
	// Reject path-like tokens with multiple slashes that aren't base64 (e.g. /v1/chat/completions).
	if strings.HasPrefix(tok, "/") || strings.Count(tok, "/") > len(tok)/6 {
		return false
	}
	// Reject pure snake_case identifiers with underscores and no digits/mixed-case/padding.
	hasUpper, hasLower, hasDigit, hasB64Sym := false, false, false, false
	for _, r := range tok {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '+' || r == '/' || r == '=':
			hasB64Sym = true
		}
	}
	classes := 0
	if hasUpper {
		classes++
	}
	if hasLower {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasB64Sym {
		classes++
	}
	if classes >= 2 || strings.HasSuffix(tok, "=") || len(tok) >= 48 {
		return true
	}
	return false
}

func tryDecodeBase64(tok string) (string, bool) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(tok)
		if err != nil || len(decoded) < 8 {
			continue
		}
		if !utf8.Valid(decoded) {
			continue
		}
		str := string(decoded)
		if isPlausibleText(str) {
			return str, true
		}
	}
	return "", false
}

func isPlausibleText(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	total := 0
	printable := 0
	alphaNum := 0
	for _, r := range s {
		total++
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsPrint(r) {
			printable++
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			alphaNum++
		}
	}
	if total == 0 || alphaNum == 0 {
		return false
	}
	return float64(printable)/float64(total) >= 0.90
}

func truncateValidUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes <= 0 {
		return ""
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
