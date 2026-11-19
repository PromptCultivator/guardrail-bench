package dataset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// ManifestSource pins an upstream dataset source and its immutable commit hash.
type ManifestSource struct {
	Name      string `json:"name"`
	URL       string `json:"url,omitempty"`
	License   string `json:"license,omitempty"`
	CommitSHA string `json:"commit_sha"`
	Notes     string `json:"notes,omitempty"`
}

// Manifest pins dataset provenance, row counts, and SHA-256 file integrity.
type Manifest struct {
	Name        string           `json:"name"`
	Version     string           `json:"version"`
	Path        string           `json:"path"`
	SHA256      string           `json:"sha256"`
	RowCount    int              `json:"row_count"`
	TrackCounts map[string]int   `json:"track_counts"`
	Sources     []ManifestSource `json:"sources"`
}

// FileSHA256 computes the lowercase hex SHA-256 digest of a file.
func FileSHA256(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s for sha256: %w", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// LoadManifest reads and strictly parses a dataset manifest JSON file.
func LoadManifest(path string) (Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	if m.Name == "" || m.Path == "" || m.SHA256 == "" {
		return Manifest{}, fmt.Errorf("manifest %s missing required fields (name, path, sha256)", path)
	}
	return m, nil
}

// VerifyManifest verifies a dataset file against its pinned manifest (SHA-256, schema, row_count, track_counts).
// If baseDir is non-empty and m.Path is relative, datasetPath is resolved relative to baseDir.
func VerifyManifest(m Manifest, baseDir string) ([]Sample, error) {
	datasetPath := m.Path
	if !filepath.IsAbs(datasetPath) && baseDir != "" {
		datasetPath = filepath.Join(baseDir, datasetPath)
	}

	gotSHA, err := FileSHA256(datasetPath)
	if err != nil {
		return nil, err
	}
	if gotSHA != m.SHA256 {
		return nil, fmt.Errorf("manifest SHA-256 mismatch for %s: got %s, want %s",
			datasetPath, gotSHA, m.SHA256)
	}

	samples, err := LoadJSONL(datasetPath)
	if err != nil {
		return nil, err
	}
	if len(samples) != m.RowCount {
		return nil, fmt.Errorf("manifest row_count mismatch for %s: got %d, want %d",
			datasetPath, len(samples), m.RowCount)
	}

	gotCounts := make(map[string]int)
	for _, s := range samples {
		gotCounts[s.Track]++
	}

	// Deterministic sorted check across union of track keys.
	keySet := make(map[string]struct{}, len(gotCounts)+len(m.TrackCounts))
	for k := range gotCounts {
		keySet[k] = struct{}{}
	}
	for k := range m.TrackCounts {
		keySet[k] = struct{}{}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if gotCounts[k] != m.TrackCounts[k] {
			return nil, fmt.Errorf("manifest track_counts[%q] mismatch: got %d, want %d",
				k, gotCounts[k], m.TrackCounts[k])
		}
	}

	return samples, nil
}

// BuildManifest computes a Manifest from an existing validated JSONL file and its samples.
func BuildManifest(name, version, relPath, absPath string, samples []Sample, sources []ManifestSource) (Manifest, error) {
	digest, err := FileSHA256(absPath)
	if err != nil {
		return Manifest{}, err
	}
	counts := make(map[string]int)
	for _, s := range samples {
		counts[s.Track]++
	}
	return Manifest{
		Name:        name,
		Version:     version,
		Path:        relPath,
		SHA256:      digest,
		RowCount:    len(samples),
		TrackCounts: counts,
		Sources:     sources,
	}, nil
}
