package dataset

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	initialScannerBuf = 64 * 1024
	maxScannerLine    = 4 * 1024 * 1024 // 4 MiB max single JSONL record
)

// ParseJSONL parses and strictly validates UTF-8 JSONL samples from r.
func ParseJSONL(r io.Reader) ([]Sample, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, initialScannerBuf), maxScannerLine)

	var samples []Sample
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			return nil, fmt.Errorf("line %d: unexpected blank line in JSONL", lineNo)
		}

		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()

		var s Sample
		if err := dec.Decode(&s); err != nil {
			return nil, fmt.Errorf("line %d: invalid JSONL record: %w", lineNo, err)
		}
		// Ensure no trailing non-whitespace tokens on the same line.
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			return nil, fmt.Errorf("line %d: trailing data after JSON object", lineNo)
		}
		if s.GroundTruthSpans == nil {
			s.GroundTruthSpans = []Span{}
		}
		samples = append(samples, s)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan JSONL: %w", err)
	}
	if err := ValidateDataset(samples); err != nil {
		return nil, err
	}
	return samples, nil
}

// LoadJSONL reads, parses, and strictly validates a JSONL dataset file.
func LoadJSONL(path string) ([]Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open dataset %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return ParseJSONL(f)
}

// EncodeJSONL deterministically serializes validated samples to UTF-8 JSONL bytes.
func EncodeJSONL(samples []Sample) ([]byte, error) {
	if err := ValidateDataset(samples); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for i, s := range samples {
		if s.GroundTruthSpans == nil {
			s.GroundTruthSpans = []Span{}
		}
		if err := enc.Encode(s); err != nil {
			return nil, fmt.Errorf("encode sample %d (%s): %w", i, s.SampleID, err)
		}
	}
	return buf.Bytes(), nil
}

// WriteJSONL atomically writes deterministic UTF-8 JSONL to path.
func WriteJSONL(path string, samples []Sample) error {
	data, err := EncodeJSONL(samples)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir for %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write dataset %s: %w", path, err)
	}
	return nil
}
