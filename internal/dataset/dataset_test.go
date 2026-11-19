package dataset_test

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PromptCultivator/guardrail-bench/internal/dataset"
	benchv1 "github.com/PromptCultivator/guardrail-bench/internal/gen/bench/v1"
)

func TestLoadAndVerifySmoke50Manifest(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join("..", "..")
	manifestPath := filepath.Join(repoRoot, "datasets", "manifests", "smoke_50.manifest.json")

	m, err := dataset.LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	samples, err := dataset.VerifyManifest(m, repoRoot)
	if err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	if len(samples) != 50 {
		t.Fatalf("expected 50 samples, got %d", len(samples))
	}

	// Verify TurnToEvaluateRequest preserves optional pointer presence.
	var checkedSpoof, checkedFetch bool
	for _, s := range samples {
		for _, turn := range s.Turns {
			req, err := dataset.TurnToEvaluateRequest(s.SampleID, "sess-"+s.SampleID, turn)
			if err != nil {
				t.Fatalf("TurnToEvaluateRequest(%s, turn %d): %v", s.SampleID, turn.TurnIndex, err)
			}
			if s.SampleID == "t3-mcp-0001" && turn.TurnIndex == 2 {
				if req.GetMcpTool() == nil || req.GetMcpTool().ReadOnlyHint != nil || req.GetMcpTool().OpenWorldHint != nil {
					t.Fatalf("expected fetch turn to preserve nil unset hints, got %+v", req.GetMcpTool())
				}
				checkedFetch = true
			}
			if s.SampleID == "t3-mcp-0005" && turn.TurnIndex == 2 {
				tool := req.GetMcpTool()
				if tool == nil || tool.TrustedServer || tool.ReadOnlyHint == nil || !tool.GetReadOnlyHint() ||
					tool.OpenWorldHint == nil || tool.GetOpenWorldHint() {
					t.Fatalf("expected spoofed tool hints to be preserved, got %+v", tool)
				}
				checkedSpoof = true
			}
			if req.GetDirection() == benchv1.Direction_DIRECTION_UNSPECIFIED {
				t.Fatalf("sample %s turn %d produced UNSPECIFIED direction", s.SampleID, turn.TurnIndex)
			}
		}
	}
	if !checkedFetch || !checkedSpoof {
		t.Fatalf("expected to verify both fetch (%v) and spoof (%v) samples", checkedFetch, checkedSpoof)
	}
}

func TestVerifyManifestRejectsTamperedFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	sample := dataset.Sample{
		SampleID:         "t1-valid-0001",
		Track:            dataset.TrackPromptInjection,
		AttackFamily:     "benign_general",
		Encoding:         "plain",
		IsMalicious:      false,
		IsHardNegative:   false,
		GroundTruthSpans: []dataset.Span{},
		Turns: []dataset.Turn{
			{
				TurnIndex:           0,
				Direction:           "DIRECTION_INPUT",
				Role:                "user",
				Text:                "Explain Envoy ext_proc.",
				ExpectedBlockAtTurn: false,
			},
		},
	}

	jsonlPath := filepath.Join(tmpDir, "mini.jsonl")
	if err := dataset.WriteJSONL(jsonlPath, []dataset.Sample{sample}); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}
	m, err := dataset.BuildManifest("mini", "1.0.0", "mini.jsonl", jsonlPath, []dataset.Sample{sample}, nil)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if _, err := dataset.VerifyManifest(m, tmpDir); err != nil {
		t.Fatalf("expected valid manifest to pass: %v", err)
	}

	// Tamper with 1 byte.
	raw, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	raw = append(raw, ' ')
	if err := os.WriteFile(jsonlPath, raw, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := dataset.VerifyManifest(m, tmpDir); err == nil {
		t.Fatalf("expected VerifyManifest to fail on tampered file")
	}
}

func TestParseJSONLStrictValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "unknown_field",
			raw:  `{"sample_id":"s1","track":"prompt_injection","attack_family":"a","encoding":"plain","is_malicious":false,"is_hard_negative":false,"ground_truth_spans":[],"extra_bad_field":123,"turns":[{"turn_index":0,"direction":"DIRECTION_INPUT","role":"user","text":"hi","expected_block_at_turn":false}]}` + "\n",
		},
		{
			name: "malicious_and_hard_negative",
			raw:  `{"sample_id":"s1","track":"prompt_injection","attack_family":"a","encoding":"plain","is_malicious":true,"is_hard_negative":true,"ground_truth_spans":[],"turns":[{"turn_index":0,"direction":"DIRECTION_INPUT","role":"user","text":"hi","expected_block_at_turn":true}]}` + "\n",
		},
		{
			name: "out_of_bounds_utf8_rune_span",
			// "José" has 5 UTF-8 bytes but only 4 runes; end_offset=5 must fail rune bounds!
			raw: `{"sample_id":"s1","track":"redaction","attack_family":"pii","encoding":"plain","is_malicious":true,"is_hard_negative":false,"ground_truth_spans":[{"entity_type":"PERSON","begin_offset":0,"end_offset":5}],"turns":[{"turn_index":0,"direction":"DIRECTION_INPUT","role":"user","text":"José","expected_block_at_turn":true}]}` + "\n",
		},
		{
			name: "duplicate_sample_id",
			raw: `{"sample_id":"dup","track":"prompt_injection","attack_family":"a","encoding":"plain","is_malicious":false,"is_hard_negative":false,"ground_truth_spans":[],"turns":[{"turn_index":0,"direction":"DIRECTION_INPUT","role":"user","text":"one","expected_block_at_turn":false}]}` + "\n" +
				`{"sample_id":"dup","track":"prompt_injection","attack_family":"a","encoding":"plain","is_malicious":false,"is_hard_negative":false,"ground_truth_spans":[],"turns":[{"turn_index":0,"direction":"DIRECTION_INPUT","role":"user","text":"two","expected_block_at_turn":false}]}` + "\n",
		},
		{
			name: "unspecified_direction",
			raw:  `{"sample_id":"s1","track":"prompt_injection","attack_family":"a","encoding":"plain","is_malicious":false,"is_hard_negative":false,"ground_truth_spans":[],"turns":[{"turn_index":0,"direction":"DIRECTION_UNSPECIFIED","role":"user","text":"hi","expected_block_at_turn":false}]}` + "\n",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := dataset.ParseJSONL(strings.NewReader(tc.raw)); err == nil {
				t.Fatalf("expected ParseJSONL error for %s, got nil", tc.name)
			}
		})
	}
}

func TestDecontaminateSynthetic92Vs80Jaccard(t *testing.T) {
	t.Parallel()

	// Build a 29-token reference document with 29 unique tokens -> exactly 25 distinct 5-grams.
	refTokens := make([]string, 29)
	for i := range refTokens {
		refTokens[i] = fmt.Sprintf("tok%02d", i)
	}
	refText := strings.Join(refTokens, " ")

	// Prefix of 27 tokens -> 23 distinct 5-grams, all contained in ref (25 5-grams).
	// Exact 5-gram Jaccard = 23 / 25 = 0.9200 (>= 0.90 -> MUST be flagged as near-duplicate).
	nearDup92Text := strings.Join(refTokens[:27], " ")

	// Prefix of 24 tokens -> 20 distinct 5-grams, all contained in ref (25 5-grams).
	// Exact 5-gram Jaccard = 20 / 25 = 0.8000 (< 0.90 -> MUST pass as clean control).
	control80Text := strings.Join(refTokens[:24], " ")

	// Verbatim duplicate (different whitespace/casing -> normalized SHA-256 overlap).
	verbatimText := "  " + strings.ToUpper(refText) + "\n"

	// Verify exact Jaccard values independently first.
	refGrams := dataset.TokenNGrams(dataset.Tokenize(refText), 5)
	j92 := dataset.JaccardSimilarity(refGrams, dataset.TokenNGrams(dataset.Tokenize(nearDup92Text), 5))
	j80 := dataset.JaccardSimilarity(refGrams, dataset.TokenNGrams(dataset.Tokenize(control80Text), 5))
	if math.Abs(j92-0.92) > 1e-9 {
		t.Fatalf("synthetic 92%% fixture Jaccard = %.6f, want 0.92", j92)
	}
	if math.Abs(j80-0.80) > 1e-9 {
		t.Fatalf("synthetic 80%% control Jaccard = %.6f, want 0.80", j80)
	}

	makeSample := func(id, text string) dataset.Sample {
		return dataset.Sample{
			SampleID:         id,
			Track:            dataset.TrackPromptInjection,
			AttackFamily:     "direct_override",
			Encoding:         "plain",
			IsMalicious:      true,
			IsHardNegative:   false,
			GroundTruthSpans: []dataset.Span{},
			Turns: []dataset.Turn{
				{
					TurnIndex:           0,
					Direction:           "DIRECTION_INPUT",
					Role:                "user",
					Text:                text,
					ExpectedBlockAtTurn: true,
				},
			},
		}
	}

	evalSamples := []dataset.Sample{
		makeSample("eval-verbatim", verbatimText),
		makeSample("eval-near-92", nearDup92Text),
		makeSample("eval-ctrl-80", control80Text),
	}
	refs := []dataset.ReferenceRecord{
		{
			ID:     "train-0001",
			Corpus: "adapter_train_v1",
			Text:   refText,
		},
	}

	report, clean := dataset.Decontaminate(
		evalSamples,
		refs,
		dataset.DefaultNGramSize,
		dataset.DefaultJaccardThreshold,
	)

	if report.Passed {
		t.Fatalf("expected decontamination gate to fail when verbatim and 92%% overlaps exist")
	}
	if len(report.VerbatimOverlaps) != 1 || report.VerbatimOverlaps[0].EvalSampleID != "eval-verbatim" {
		t.Fatalf("expected exactly 1 verbatim overlap (eval-verbatim), got %+v", report.VerbatimOverlaps)
	}
	if len(report.NearDuplicates) != 1 || report.NearDuplicates[0].EvalSampleID != "eval-near-92" {
		t.Fatalf("expected exactly 1 near-duplicate (eval-near-92), got %+v", report.NearDuplicates)
	}
	if math.Abs(report.NearDuplicates[0].Jaccard-0.92) > 1e-9 {
		t.Fatalf("near-duplicate Jaccard = %.6f, want 0.92", report.NearDuplicates[0].Jaccard)
	}
	if len(clean) != 1 || clean[0].SampleID != "eval-ctrl-80" {
		t.Fatalf("expected only 80%% control (eval-ctrl-80) to pass cleanly, got %+v", clean)
	}

	// Running decontamination on clean-only corpus must pass.
	cleanReport, cleanAgain := dataset.Decontaminate(
		clean,
		refs,
		dataset.DefaultNGramSize,
		dataset.DefaultJaccardThreshold,
	)
	if !cleanReport.Passed || len(cleanAgain) != 1 {
		t.Fatalf("expected 80%%-Jaccard control alone to pass decontamination, got %+v", cleanReport)
	}
}
