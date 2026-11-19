package guardrailbench_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	benchv1 "github.com/PromptCultivator/guardrail-bench/internal/gen/bench/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

type fixtureManifest struct {
	Name        string         `json:"name"`
	Version     string         `json:"version"`
	Path        string         `json:"path"`
	SHA256      string         `json:"sha256"`
	RowCount    int            `json:"row_count"`
	TrackCounts map[string]int `json:"track_counts"`
}

type fixtureSpan struct {
	EntityType  string `json:"entity_type"`
	BeginOffset int    `json:"begin_offset"`
	EndOffset   int    `json:"end_offset"`
}

type fixtureToolAnnotations struct {
	ToolName        string `json:"tool_name"`
	ServerName      string `json:"server_name"`
	ReadOnlyHint    *bool  `json:"read_only_hint,omitempty"`
	DestructiveHint *bool  `json:"destructive_hint,omitempty"`
	IdempotentHint  *bool  `json:"idempotent_hint,omitempty"`
	OpenWorldHint   *bool  `json:"open_world_hint,omitempty"`
	TrustedServer   bool   `json:"trusted_server"`
}

type fixtureTurn struct {
	TurnIndex           int                     `json:"turn_index"`
	Direction           string                  `json:"direction"`
	Role                string                  `json:"role"`
	Text                string                  `json:"text"`
	MCPTool             *fixtureToolAnnotations `json:"mcp_tool,omitempty"`
	ExpectedBlockAtTurn bool                    `json:"expected_block_at_turn"`
}

type fixtureSample struct {
	SampleID         string        `json:"sample_id"`
	Track            string        `json:"track"`
	AttackFamily     string        `json:"attack_family"`
	Encoding         string        `json:"encoding"`
	IsMalicious      bool          `json:"is_malicious"`
	IsHardNegative   bool          `json:"is_hard_negative"`
	GroundTruthSpans []fixtureSpan `json:"ground_truth_spans"`
	Turns            []fixtureTurn `json:"turns"`
}

type stubAdapterServer struct {
	benchv1.UnimplementedAdapterServiceServer
}

func (s *stubAdapterServer) Health(_ context.Context, _ *benchv1.HealthRequest) (*benchv1.HealthResponse, error) {
	return &benchv1.HealthResponse{
		AdapterName:  "smoke_stub",
		ModelVersion: "0.1.0",
	}, nil
}

func (s *stubAdapterServer) ResetSession(_ context.Context, _ *benchv1.ResetSessionRequest) (*benchv1.ResetSessionResponse, error) {
	return &benchv1.ResetSessionResponse{}, nil
}

func (s *stubAdapterServer) Evaluate(_ context.Context, req *benchv1.EvaluateRequest) (*benchv1.EvaluateResponse, error) {
	chars := int32(utf8.RuneCountInString(req.GetText()))
	tu := (chars + 999) / 1000
	if tu == 0 {
		tu = 1
	}
	return &benchv1.EvaluateResponse{
		Blocked:             false,
		RiskScore:           0.05,
		RedactedText:        req.GetText(),
		TriggeredCategories: []string{},
		TaintState: &benchv1.SessionTaint{
			ReadsPrivate:      false,
			ReadsUntrusted:    false,
			SendsOut:          false,
			TrifectaTriggered: false,
		},
		Usage: &benchv1.UsageMetrics{
			InputChars:      chars,
			TextUnitsBilled: tu,
			InputTokens:     chars / 4,
			AdapterWallMs:   0.25,
		},
		JudgeGraded: false,
	}, nil
}

func TestProtoAdapterServiceRoundTrip(t *testing.T) {
	t.Parallel()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	defer func() { _ = lis.Close() }()

	srv := grpc.NewServer()
	benchv1.RegisterAdapterServiceServer(srv, &stubAdapterServer{})
	go func() {
		_ = srv.Serve(lis)
	}()
	defer srv.Stop()

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := benchv1.NewAdapterServiceClient(conn)
	ctx := context.Background()

	health, err := client.Health(ctx, &benchv1.HealthRequest{})
	if err != nil {
		t.Fatalf("Health RPC failed: %v", err)
	}
	if health.GetAdapterName() != "smoke_stub" || health.GetModelVersion() != "0.1.0" {
		t.Fatalf("unexpected health response: %+v", health)
	}

	readOnly := true
	evalReq := &benchv1.EvaluateRequest{
		SampleId:  "t3-mcp-0001",
		SessionId: "sess-1",
		TurnIndex: 0,
		Direction: benchv1.Direction_DIRECTION_TOOL_RESULT,
		Role:      "tool",
		Text:      "José Nuñez — canary test",
		McpTool: &benchv1.ToolAnnotations{
			ToolName:      "read_file",
			ServerName:    "filesystem",
			ReadOnlyHint:  &readOnly,
			TrustedServer: true,
		},
	}

	// Verify optional hint presence survives protobuf wire serialization.
	raw, err := proto.Marshal(evalReq)
	if err != nil {
		t.Fatalf("marshal EvaluateRequest: %v", err)
	}
	var decoded benchv1.EvaluateRequest
	if err := proto.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal EvaluateRequest: %v", err)
	}
	if decoded.GetMcpTool().ReadOnlyHint == nil || !decoded.GetMcpTool().GetReadOnlyHint() {
		t.Fatalf("expected ReadOnlyHint to be explicitly present and true")
	}
	if decoded.GetMcpTool().OpenWorldHint != nil {
		t.Fatalf("expected unset OpenWorldHint to remain nil")
	}

	evalResp, err := client.Evaluate(ctx, evalReq)
	if err != nil {
		t.Fatalf("Evaluate RPC failed: %v", err)
	}
	if evalResp.GetUsage().GetInputChars() != int32(utf8.RuneCountInString(evalReq.Text)) {
		t.Fatalf("expected %d input chars, got %d", utf8.RuneCountInString(evalReq.Text), evalResp.GetUsage().GetInputChars())
	}

	if _, err := client.ResetSession(ctx, &benchv1.ResetSessionRequest{SessionId: "sess-1"}); err != nil {
		t.Fatalf("ResetSession RPC failed: %v", err)
	}
}

func TestSmoke50FixturesAndManifest(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join("..", "..")
	manifestPath := filepath.Join(repoRoot, "datasets", "manifests", "smoke_50.manifest.json")
	fixturePath := filepath.Join(repoRoot, "datasets", "fixtures", "smoke_50.jsonl")

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest fixtureManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}

	fixtureBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	digest := sha256.Sum256(fixtureBytes)
	gotSHA := hex.EncodeToString(digest[:])
	if gotSHA != manifest.SHA256 {
		t.Fatalf("manifest SHA-256 mismatch: got %s, manifest has %s", gotSHA, manifest.SHA256)
	}

	awsKeyRe := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)

	seenIDs := make(map[string]struct{}, 50)
	trackCounts := make(map[string]int)
	notInjectSubsets := make(map[string]int)
	var track3Dangerous, track3Safe int
	var sawUntrustedSpoof, sawUnicodeSpan bool

	scanner := bufio.NewScanner(strings.NewReader(string(fixtureBytes)))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			t.Fatalf("unexpected blank line at line %d", lineNo)
		}

		// Ensure no real AWS key patterns sneak into fixtures.
		for _, match := range awsKeyRe.FindAllString(line, -1) {
			if match != "AKIAIOSFODNN7EXAMPLE" {
				t.Fatalf("line %d contains non-canary AWS key pattern: %s", lineNo, match)
			}
		}

		var sample fixtureSample
		if err := json.Unmarshal([]byte(line), &sample); err != nil {
			t.Fatalf("line %d invalid JSON: %v", lineNo, err)
		}

		if sample.SampleID == "" {
			t.Fatalf("line %d missing sample_id", lineNo)
		}
		if _, dup := seenIDs[sample.SampleID]; dup {
			t.Fatalf("duplicate sample_id: %s", sample.SampleID)
		}
		seenIDs[sample.SampleID] = struct{}{}
		trackCounts[sample.Track]++

		if len(sample.Turns) == 0 {
			t.Fatalf("sample %s has zero turns", sample.SampleID)
		}

		anyExpectedBlock := false
		for i, turn := range sample.Turns {
			if turn.TurnIndex != i {
				t.Fatalf("sample %s turn %d has turn_index=%d", sample.SampleID, i, turn.TurnIndex)
			}
			dirVal, ok := benchv1.Direction_value[turn.Direction]
			if !ok || benchv1.Direction(dirVal) == benchv1.Direction_DIRECTION_UNSPECIFIED {
				t.Fatalf("sample %s turn %d has invalid direction %q", sample.SampleID, i, turn.Direction)
			}
			if turn.Text == "" {
				t.Fatalf("sample %s turn %d has empty text", sample.SampleID, i)
			}
			if turn.ExpectedBlockAtTurn {
				anyExpectedBlock = true
			}
			if turn.MCPTool != nil && !turn.MCPTool.TrustedServer &&
				turn.MCPTool.ReadOnlyHint != nil && *turn.MCPTool.ReadOnlyHint &&
				turn.MCPTool.OpenWorldHint != nil && !*turn.MCPTool.OpenWorldHint {
				sawUntrustedSpoof = true
			}
		}

		// Validate UTF-8 rune offsets for ground_truth_spans against turns[0].Text.
		turn0Runes := []rune(sample.Turns[0].Text)
		for _, sp := range sample.GroundTruthSpans {
			if sp.EntityType == "" {
				t.Fatalf("sample %s has span with empty entity_type", sample.SampleID)
			}
			if sp.BeginOffset < 0 || sp.EndOffset <= sp.BeginOffset || sp.EndOffset > len(turn0Runes) {
				t.Fatalf("sample %s invalid span [%d, %d) for rune len %d",
					sample.SampleID, sp.BeginOffset, sp.EndOffset, len(turn0Runes))
			}
			if sample.SampleID == "t2-pii-0003" && sp.EntityType == "PERSON" {
				got := string(turn0Runes[sp.BeginOffset:sp.EndOffset])
				if got != "José Nuñez" {
					t.Fatalf("t2-pii-0003 PERSON rune slice = %q, want %q", got, "José Nuñez")
				}
				sawUnicodeSpan = true
			}
		}

		if sample.Track == "prompt_injection" && sample.IsHardNegative {
			notInjectSubsets[sample.AttackFamily]++
		}
		if sample.Track == "mcp_trifecta" {
			if sample.IsMalicious {
				track3Dangerous++
				if !anyExpectedBlock {
					t.Fatalf("malicious Track 3 sample %s has no expected_block_at_turn=true", sample.SampleID)
				}
			} else {
				track3Safe++
				if anyExpectedBlock {
					t.Fatalf("safe Track 3 sample %s unexpectedly expects block", sample.SampleID)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan fixture: %v", err)
	}

	if lineNo != 50 || manifest.RowCount != 50 {
		t.Fatalf("expected 50 rows, got lineNo=%d manifest.RowCount=%d", lineNo, manifest.RowCount)
	}
	wantTracks := map[string]int{
		"prompt_injection": 20,
		"redaction":        15,
		"mcp_trifecta":     15,
	}
	for track, want := range wantTracks {
		if trackCounts[track] != want {
			t.Fatalf("track %s count = %d, want %d", track, trackCounts[track], want)
		}
		if manifest.TrackCounts[track] != want {
			t.Fatalf("manifest track %s count = %d, want %d", track, manifest.TrackCounts[track], want)
		}
	}
	for _, subset := range []string{"notinject_1_trigger", "notinject_2_trigger", "notinject_3_trigger"} {
		if notInjectSubsets[subset] == 0 {
			t.Fatalf("missing NotInject hard-negative subset %s in smoke_50.jsonl", subset)
		}
	}
	if track3Dangerous < 7 || track3Safe < 6 {
		t.Fatalf("expected >=7 dangerous and >=6 safe Track 3 scenarios, got dangerous=%d safe=%d",
			track3Dangerous, track3Safe)
	}
	if !sawUntrustedSpoof {
		t.Fatalf("expected at least one Track 3 untrusted MCP hint spoofing scenario")
	}
	if !sawUnicodeSpan {
		t.Fatalf("expected multibyte UTF-8 span check on t2-pii-0003")
	}
}
