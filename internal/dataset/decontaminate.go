package dataset

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

const (
	// DefaultNGramSize is the canonical token shingle length for near-duplicate checks.
	DefaultNGramSize = 5
	// DefaultJaccardThreshold flags evaluation rows with token 5-gram Jaccard >= 0.90.
	DefaultJaccardThreshold = 0.90
)

// ReferenceRecord represents a single row from a declared adapter training corpus.
type ReferenceRecord struct {
	ID     string `json:"id"`
	Corpus string `json:"corpus"`
	Text   string `json:"text"`
}

// OverlapFinding records a verbatim SHA-256 overlap or near-duplicate Jaccard violation.
type OverlapFinding struct {
	EvalSampleID string  `json:"eval_sample_id"`
	RefID        string  `json:"ref_id"`
	RefCorpus    string  `json:"ref_corpus"`
	Jaccard      float64 `json:"jaccard"`
	ExactMatch   bool    `json:"exact_match"`
}

// DecontaminationReport summarizes pre-flight decontamination results deterministically.
type DecontaminationReport struct {
	NGramSize        int              `json:"ngram_size"`
	Threshold        float64          `json:"threshold"`
	TotalEvalSamples int              `json:"total_eval_samples"`
	TotalRefRecords  int              `json:"total_ref_records"`
	VerbatimOverlaps []OverlapFinding `json:"verbatim_overlaps"`
	NearDuplicates   []OverlapFinding `json:"near_duplicates"`
	FlaggedSampleIDs []string         `json:"flagged_sample_ids"`
	Passed           bool             `json:"passed"`
}

// NormalizeText applies Unicode NFKC, lowercasing, and whitespace collapsing.
func NormalizeText(s string) string {
	nfkc := norm.NFKC.String(s)
	return strings.Join(strings.Fields(strings.ToLower(nfkc)), " ")
}

// TextSHA256 hashes a string with SHA-256 and returns lowercase hex.
func TextSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Tokenize extracts normalized lowercase alphanumeric tokens after Unicode NFKC normalization.
func Tokenize(s string) []string {
	nfkc := strings.ToLower(norm.NFKC.String(s))
	var tokens []string
	var cur strings.Builder
	for _, r := range nfkc {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			cur.WriteRune(r)
		} else if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// TokenNGrams builds the deduplicated set of contiguous token n-grams.
// For inputs shorter than n tokens, it emits a single shingle of all available tokens when non-empty.
func TokenNGrams(tokens []string, n int) map[string]struct{} {
	if n <= 0 {
		n = DefaultNGramSize
	}
	grams := make(map[string]struct{})
	if len(tokens) == 0 {
		return grams
	}
	if len(tokens) < n {
		grams[strings.Join(tokens, "\x1f")] = struct{}{}
		return grams
	}
	for i := 0; i <= len(tokens)-n; i++ {
		grams[strings.Join(tokens[i:i+n], "\x1f")] = struct{}{}
	}
	return grams
}

// JaccardSimilarity computes |A ∩ B| / |A ∪ B| for two n-gram sets.
func JaccardSimilarity(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0.0
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	inter := 0
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0.0
	}
	return float64(inter) / float64(union)
}

// SampleText joins all turn texts for decontamination comparison.
func SampleText(s Sample) string {
	if len(s.Turns) == 1 {
		return s.Turns[0].Text
	}
	parts := make([]string, len(s.Turns))
	for i, t := range s.Turns {
		parts[i] = t.Text
	}
	return strings.Join(parts, "\n")
}

// Decontaminate checks evalSamples against reference training records for:
//  1. Verbatim SHA-256 overlap (exact raw or normalized text match)
//  2. Token n-gram Jaccard similarity >= threshold (default n=5, threshold=0.90)
//
// Results are sorted deterministically by (EvalSampleID, RefCorpus, RefID).
func Decontaminate(
	evalSamples []Sample,
	refs []ReferenceRecord,
	ngramSize int,
	threshold float64,
) (DecontaminationReport, []Sample) {
	if ngramSize <= 0 {
		ngramSize = DefaultNGramSize
	}
	if threshold <= 0 {
		threshold = DefaultJaccardThreshold
	}

	type indexedRef struct {
		rec   ReferenceRecord
		grams map[string]struct{}
	}

	exactRawIndex := make(map[string][]int, len(refs))
	exactNormIndex := make(map[string][]int, len(refs))
	gramInverted := make(map[string][]int)
	indexedRefs := make([]indexedRef, len(refs))

	for i, ref := range refs {
		rawHash := TextSHA256(ref.Text)
		exactRawIndex[rawHash] = append(exactRawIndex[rawHash], i)

		normHash := TextSHA256(NormalizeText(ref.Text))
		exactNormIndex[normHash] = append(exactNormIndex[normHash], i)

		grams := TokenNGrams(Tokenize(ref.Text), ngramSize)
		indexedRefs[i] = indexedRef{rec: ref, grams: grams}
		for g := range grams {
			gramInverted[g] = append(gramInverted[g], i)
		}
	}

	var verbatim []OverlapFinding
	var nearDup []OverlapFinding
	flaggedSet := make(map[string]struct{})
	cleanSamples := make([]Sample, 0, len(evalSamples))

	for _, sample := range evalSamples {
		// Compare both full concatenated sample text and each individual turn so
		// contaminated single turns inside multi-turn sessions are also caught.
		candidatesTexts := make([]string, 0, len(sample.Turns)+1)
		fullText := SampleText(sample)
		candidatesTexts = append(candidatesTexts, fullText)
		if len(sample.Turns) > 1 {
			for _, t := range sample.Turns {
				candidatesTexts = append(candidatesTexts, t.Text)
			}
		}

		// Track best match per ref index to avoid emitting duplicate rows per sample/ref pair.
		type bestMatch struct {
			exact   bool
			jaccard float64
		}
		matches := make(map[int]bestMatch)

		for _, txt := range candidatesTexts {
			rawHash := TextSHA256(txt)
			for _, refIdx := range exactRawIndex[rawHash] {
				matches[refIdx] = bestMatch{exact: true, jaccard: 1.0}
			}
			normHash := TextSHA256(NormalizeText(txt))
			for _, refIdx := range exactNormIndex[normHash] {
				matches[refIdx] = bestMatch{exact: true, jaccard: 1.0}
			}

			evalGrams := TokenNGrams(Tokenize(txt), ngramSize)
			// Collect candidate refs sharing at least one n-gram via inverted index.
			refHits := make(map[int]int)
			for g := range evalGrams {
				for _, refIdx := range gramInverted[g] {
					refHits[refIdx]++
				}
			}
			for refIdx, shared := range refHits {
				if prev, ok := matches[refIdx]; ok && prev.exact {
					continue
				}
				union := len(evalGrams) + len(indexedRefs[refIdx].grams) - shared
				if union <= 0 {
					continue
				}
				j := float64(shared) / float64(union)
				if j >= threshold {
					prev := matches[refIdx]
					if j > prev.jaccard {
						matches[refIdx] = bestMatch{exact: false, jaccard: j}
					}
				}
			}
		}

		if len(matches) == 0 {
			cleanSamples = append(cleanSamples, sample)
			continue
		}

		flaggedSet[sample.SampleID] = struct{}{}
		// Sort ref indices for deterministic processing before global sort.
		refIdxs := make([]int, 0, len(matches))
		for idx := range matches {
			refIdxs = append(refIdxs, idx)
		}
		sort.Ints(refIdxs)

		for _, refIdx := range refIdxs {
			m := matches[refIdx]
			finding := OverlapFinding{
				EvalSampleID: sample.SampleID,
				RefID:        indexedRefs[refIdx].rec.ID,
				RefCorpus:    indexedRefs[refIdx].rec.Corpus,
				Jaccard:      m.jaccard,
				ExactMatch:   m.exact,
			}
			if m.exact {
				verbatim = append(verbatim, finding)
			} else {
				nearDup = append(nearDup, finding)
			}
		}
	}

	sortFindings := func(fs []OverlapFinding) {
		sort.Slice(fs, func(i, j int) bool {
			if fs[i].EvalSampleID != fs[j].EvalSampleID {
				return fs[i].EvalSampleID < fs[j].EvalSampleID
			}
			if fs[i].RefCorpus != fs[j].RefCorpus {
				return fs[i].RefCorpus < fs[j].RefCorpus
			}
			return fs[i].RefID < fs[j].RefID
		})
	}
	sortFindings(verbatim)
	sortFindings(nearDup)

	flaggedIDs := make([]string, 0, len(flaggedSet))
	for id := range flaggedSet {
		flaggedIDs = append(flaggedIDs, id)
	}
	sort.Strings(flaggedIDs)

	if verbatim == nil {
		verbatim = []OverlapFinding{}
	}
	if nearDup == nil {
		nearDup = []OverlapFinding{}
	}

	report := DecontaminationReport{
		NGramSize:        ngramSize,
		Threshold:        threshold,
		TotalEvalSamples: len(evalSamples),
		TotalRefRecords:  len(refs),
		VerbatimOverlaps: verbatim,
		NearDuplicates:   nearDup,
		FlaggedSampleIDs: flaggedIDs,
		Passed:           len(verbatim) == 0 && len(nearDup) == 0,
	}
	return report, cleanSamples
}
