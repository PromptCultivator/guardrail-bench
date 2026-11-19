package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproccfgv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	benchv1 "github.com/PromptCultivator/guardrail-bench/internal/gen/bench/v1"
	"github.com/PromptCultivator/guardrail-bench/pkg/trifecta"
)

const (
	adapterName  = "trifecta_extproc"
	modelVersion = "0.2.0"
)

// Server serves both bench.v1.AdapterService (for direct micro-benchmarking) and
// envoy.service.ext_proc.v3.ExternalProcessor (for full Envoy proxy benchmarking).
type Server struct {
	benchv1.UnimplementedAdapterServiceServer
	extprocv3.UnimplementedExternalProcessorServer

	engine *trifecta.Engine
}

// NewServer constructs a combined AdapterService + Envoy ExternalProcessor gRPC server.
func NewServer(engine *trifecta.Engine) *Server {
	if engine == nil {
		engine = trifecta.NewEngine(trifecta.DefaultEngineConfig())
	}
	return &Server{engine: engine}
}

// Health implements bench.v1.AdapterService.Health.
func (s *Server) Health(_ context.Context, _ *benchv1.HealthRequest) (*benchv1.HealthResponse, error) {
	return &benchv1.HealthResponse{
		AdapterName:  adapterName,
		ModelVersion: modelVersion,
	}, nil
}

// ResetSession implements bench.v1.AdapterService.ResetSession.
func (s *Server) ResetSession(_ context.Context, req *benchv1.ResetSessionRequest) (*benchv1.ResetSessionResponse, error) {
	s.engine.ResetSession(req.GetSessionId())
	return &benchv1.ResetSessionResponse{}, nil
}

// Evaluate implements bench.v1.AdapterService.Evaluate.
func (s *Server) Evaluate(_ context.Context, req *benchv1.EvaluateRequest) (*benchv1.EvaluateResponse, error) {
	in := trifecta.EvalInput{
		SampleID:  req.GetSampleId(),
		SessionID: req.GetSessionId(),
		TurnIndex: int(req.GetTurnIndex()),
		Direction: protoToDirection(req.GetDirection()),
		Role:      req.GetRole(),
		Text:      req.GetText(),
		MCPTool:   protoToToolAnnotations(req.GetMcpTool()),
	}
	res := s.engine.Evaluate(in)
	return resultToProto(res), nil
}

type extProcEnvelope struct {
	SampleID  string             `json:"sample_id"`
	SessionID string             `json:"session_id"`
	TurnIndex int                `json:"turn_index"`
	Direction string             `json:"direction"`
	Role      string             `json:"role"`
	Text      string             `json:"text"`
	MCPTool   *extProcToolJSON   `json:"mcp_tool"`
	Stream    bool               `json:"stream"`
	Messages  []extProcOAIHeader `json:"messages"`
}

type extProcToolJSON struct {
	ToolName        string `json:"tool_name"`
	ServerName      string `json:"server_name"`
	ReadOnlyHint    *bool  `json:"read_only_hint"`
	DestructiveHint *bool  `json:"destructive_hint"`
	IdempotentHint  *bool  `json:"idempotent_hint"`
	OpenWorldHint   *bool  `json:"open_world_hint"`
	TrustedServer   bool   `json:"trusted_server"`
}

type extProcOAIHeader struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type extProcBlockBody struct {
	Error               string   `json:"error"`
	Blocked             bool     `json:"blocked"`
	RiskScore           float64  `json:"risk_score"`
	TriggeredCategories []string `json:"triggered_categories"`
	TrifectaTriggered   bool     `json:"trifecta_triggered"`
	ReadsPrivate        bool     `json:"reads_private"`
	ReadsUntrusted      bool     `json:"reads_untrusted"`
	SendsOut            bool     `json:"sends_out"`
}

// Process implements envoy.service.ext_proc.v3.ExternalProcessor.Process.
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	var (
		reqHeaders map[string]string
		sessionID  string
		sampleID   string
		turnIndex  int
		reqPath    string
		reqBuf     []byte
		respBuf    []byte
	)

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return nil
		}
		if err != nil {
			return err
		}

		switch v := req.GetRequest().(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			reqHeaders = extractHeaderMap(v.RequestHeaders.GetHeaders())
			reqPath = reqHeaders[":path"]
			sessionID = reqHeaders["x-session-id"]
			sampleID = reqHeaders["x-sample-id"]
			if ti, err := strconv.Atoi(reqHeaders["x-turn-index"]); err == nil {
				turnIndex = ti
			}

			if resetID := reqHeaders["x-trifecta-reset-session"]; resetID != "" {
				s.engine.ResetSession(resetID)
			}
			if strings.HasPrefix(reqPath, "/reset-session") {
				if sessionID != "" {
					s.engine.ResetSession(sessionID)
				}
				if err := stream.Send(immediateJSONResponse(typev3.StatusCode_OK, []byte(`{"reset":true}`), nil)); err != nil {
					return err
				}
				return nil
			}

			// For GET / bodyless health checks, skip body buffering via mode override.
			var modeOverride *extproccfgv3.ProcessingMode
			if v.RequestHeaders.GetEndOfStream() {
				modeOverride = &extproccfgv3.ProcessingMode{
					RequestBodyMode:  extproccfgv3.ProcessingMode_NONE,
					ResponseBodyMode: extproccfgv3.ProcessingMode_NONE,
				}
			}

			resp := &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_RequestHeaders{
					RequestHeaders: &extprocv3.HeadersResponse{
						Response: &extprocv3.CommonResponse{
							Status: extprocv3.CommonResponse_CONTINUE,
						},
					},
				},
				ModeOverride: modeOverride,
			}
			if err := stream.Send(resp); err != nil {
				return err
			}

		case *extprocv3.ProcessingRequest_RequestBody:
			reqBuf = append(reqBuf, v.RequestBody.GetBody()...)
			if !v.RequestBody.GetEndOfStream() {
				if err := stream.Send(&extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_RequestBody{
						RequestBody: &extprocv3.BodyResponse{
							Response: &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE},
						},
					},
				}); err != nil {
					return err
				}
				continue
			}

			in := parseExtProcInput(reqHeaders, reqPath, sampleID, sessionID, turnIndex, reqBuf)
			if in.SessionID != "" {
				sessionID = in.SessionID
			}
			res := s.engine.Evaluate(in)

			if res.Blocked {
				if err := stream.Send(immediateBlockResponse(res)); err != nil {
					return err
				}
				return nil
			}

			if err := stream.Send(&extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_RequestBody{
					RequestBody: &extprocv3.BodyResponse{
						Response: &extprocv3.CommonResponse{
							Status: extprocv3.CommonResponse_CONTINUE,
						},
					},
				},
			}); err != nil {
				return err
			}

		case *extprocv3.ProcessingRequest_ResponseHeaders:
			st := s.engine.SessionState(sessionID)

			// Critical for SSE TTFT latency (< 5ms p99): if the session does NOT hold both
			// reads_private and reads_untrusted, bypass response body inspection via ModeOverride
			// so benign SSE streams incur zero buffering and zero per-chunk gRPC round-trips.
			// When doubly-tainted, buffer the assistant response before downstream headers flush
			// so EchoLeak Markdown image exfiltration returns a clean HTTP 403 ImmediateResponse.
			var modeOverride *extproccfgv3.ProcessingMode
			if st.ReadsPrivate && st.ReadsUntrusted {
				modeOverride = &extproccfgv3.ProcessingMode{
					ResponseBodyMode: extproccfgv3.ProcessingMode_BUFFERED,
				}
			} else {
				modeOverride = &extproccfgv3.ProcessingMode{
					ResponseBodyMode: extproccfgv3.ProcessingMode_NONE,
				}
			}

			if err := stream.Send(&extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extprocv3.HeadersResponse{
						Response: &extprocv3.CommonResponse{
							Status: extprocv3.CommonResponse_CONTINUE,
						},
					},
				},
				ModeOverride: modeOverride,
			}); err != nil {
				return err
			}

		case *extprocv3.ProcessingRequest_ResponseBody:
			respBuf = append(respBuf, v.ResponseBody.GetBody()...)
			// Inspect accumulated output when end-of-stream or chunk contains potential exfil image.
			chunkStr := string(respBuf)
			res := s.engine.Evaluate(trifecta.EvalInput{
				SampleID:  sampleID,
				SessionID: sessionID,
				TurnIndex: turnIndex,
				Direction: trifecta.DirectionOutput,
				Role:      "assistant",
				Text:      chunkStr,
			})
			if res.Blocked {
				if err := stream.Send(immediateBlockResponse(res)); err != nil {
					return err
				}
				return nil
			}
			if err := stream.Send(&extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseBody{
					ResponseBody: &extprocv3.BodyResponse{
						Response: &extprocv3.CommonResponse{
							Status: extprocv3.CommonResponse_CONTINUE,
						},
					},
				},
			}); err != nil {
				return err
			}

		case *extprocv3.ProcessingRequest_RequestTrailers:
			if err := stream.Send(&extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_RequestTrailers{
					RequestTrailers: &extprocv3.TrailersResponse{},
				},
			}); err != nil {
				return err
			}

		case *extprocv3.ProcessingRequest_ResponseTrailers:
			if err := stream.Send(&extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseTrailers{
					ResponseTrailers: &extprocv3.TrailersResponse{},
				},
			}); err != nil {
				return err
			}
		}
	}
}

func parseExtProcInput(
	hdrs map[string]string,
	reqPath, sampleID, sessionID string,
	turnIndex int,
	body []byte,
) trifecta.EvalInput {
	in := trifecta.EvalInput{
		SampleID:  sampleID,
		SessionID: sessionID,
		TurnIndex: turnIndex,
		Direction: directionFromString(hdrs["x-direction"]),
		Role:      hdrs["x-role"],
		Text:      string(body),
	}

	var env extProcEnvelope
	if len(body) > 0 && json.Unmarshal(body, &env) == nil {
		if env.SampleID != "" {
			in.SampleID = env.SampleID
		}
		if env.SessionID != "" {
			in.SessionID = env.SessionID
		}
		if env.TurnIndex > 0 {
			in.TurnIndex = env.TurnIndex
		}
		if env.Direction != "" {
			in.Direction = directionFromString(env.Direction)
		}
		if env.Role != "" {
			in.Role = env.Role
		}
		if env.Text != "" {
			in.Text = env.Text
		} else if len(env.Messages) > 0 {
			last := env.Messages[len(env.Messages)-1]
			in.Text = last.Content
			if in.Role == "" {
				in.Role = last.Role
			}
		}
		if env.MCPTool != nil {
			in.MCPTool = &trifecta.ToolAnnotations{
				ToolName:        env.MCPTool.ToolName,
				ServerName:      env.MCPTool.ServerName,
				ReadOnlyHint:    env.MCPTool.ReadOnlyHint,
				DestructiveHint: env.MCPTool.DestructiveHint,
				IdempotentHint:  env.MCPTool.IdempotentHint,
				OpenWorldHint:   env.MCPTool.OpenWorldHint,
				TrustedServer:   env.MCPTool.TrustedServer,
			}
		}
	}

	// Allow HTTP headers to supply MCP annotations if not embedded in JSON body.
	if in.MCPTool == nil && hdrs["x-mcp-tool"] != "" {
		tool := &trifecta.ToolAnnotations{
			ToolName:      hdrs["x-mcp-tool"],
			ServerName:    hdrs["x-mcp-server"],
			TrustedServer: parseBoolDefault(hdrs["x-mcp-trusted"], false),
		}
		tool.ReadOnlyHint = parseOptionalBool(hdrs["x-mcp-read-only"])
		tool.DestructiveHint = parseOptionalBool(hdrs["x-mcp-destructive"])
		tool.IdempotentHint = parseOptionalBool(hdrs["x-mcp-idempotent"])
		tool.OpenWorldHint = parseOptionalBool(hdrs["x-mcp-open-world"])
		in.MCPTool = tool
	}

	if in.Direction == trifecta.DirectionUnspecified {
		switch {
		case strings.Contains(reqPath, "/mcp/tool_result"):
			in.Direction = trifecta.DirectionToolResult
		case strings.Contains(reqPath, "/mcp/call"):
			in.Direction = trifecta.DirectionToolCall
		default:
			in.Direction = trifecta.DirectionInput
		}
	}
	if in.Role == "" {
		switch in.Direction {
		case trifecta.DirectionToolResult:
			in.Role = "tool"
		case trifecta.DirectionToolCall, trifecta.DirectionOutput:
			in.Role = "assistant"
		default:
			in.Role = "user"
		}
	}

	return in
}

func immediateBlockResponse(res trifecta.EvalResult) *extprocv3.ProcessingResponse {
	payload, _ := json.Marshal(extProcBlockBody{
		Error:               "guardrail_blocked",
		Blocked:             true,
		RiskScore:           res.RiskScore,
		TriggeredCategories: res.TriggeredCategories,
		TrifectaTriggered:   res.TaintState.TrifectaTriggered,
		ReadsPrivate:        res.TaintState.ReadsPrivate,
		ReadsUntrusted:      res.TaintState.ReadsUntrusted,
		SendsOut:            res.TaintState.SendsOut,
	})
	extraHeaders := map[string]string{
		"x-guardrail-blocked":  "true",
		"x-trifecta-triggered": strconv.FormatBool(res.TaintState.TrifectaTriggered),
	}
	return immediateJSONResponse(typev3.StatusCode_Forbidden, payload, extraHeaders)
}

func immediateJSONResponse(code typev3.StatusCode, body []byte, extraHeaders map[string]string) *extprocv3.ProcessingResponse {
	setHeaders := []*corev3.HeaderValueOption{
		{
			Header: &corev3.HeaderValue{
				Key:      "content-type",
				RawValue: []byte("application/json"),
			},
		},
	}
	keys := make([]string, 0, len(extraHeaders))
	for k := range extraHeaders {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		setHeaders = append(setHeaders, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:      k,
				RawValue: []byte(extraHeaders[k]),
			},
		})
	}
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status:  &typev3.HttpStatus{Code: code},
				Headers: &extprocv3.HeaderMutation{SetHeaders: setHeaders},
				Body:    body,
				Details: "trifecta_extproc_policy_decision",
			},
		},
	}
}

func extractHeaderMap(hm *corev3.HeaderMap) map[string]string {
	out := make(map[string]string)
	if hm == nil {
		return out
	}
	for _, h := range hm.GetHeaders() {
		key := strings.ToLower(h.GetKey())
		val := h.GetValue()
		if val == "" && len(h.GetRawValue()) > 0 {
			val = string(h.GetRawValue())
		}
		out[key] = val
	}
	return out
}

func parseOptionalBool(v string) *bool {
	s := strings.TrimSpace(strings.ToLower(v))
	if s == "" {
		return nil
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return nil
	}
	return &b
}

func parseBoolDefault(v string, def bool) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(strings.ToLower(v)))
	if err != nil {
		return def
	}
	return b
}

func directionFromString(s string) trifecta.Direction {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DIRECTION_INPUT", "INPUT":
		return trifecta.DirectionInput
	case "DIRECTION_OUTPUT", "OUTPUT":
		return trifecta.DirectionOutput
	case "DIRECTION_TOOL_CALL", "TOOL_CALL":
		return trifecta.DirectionToolCall
	case "DIRECTION_TOOL_RESULT", "TOOL_RESULT":
		return trifecta.DirectionToolResult
	default:
		return trifecta.DirectionUnspecified
	}
}

func protoToDirection(d benchv1.Direction) trifecta.Direction {
	switch d {
	case benchv1.Direction_DIRECTION_INPUT:
		return trifecta.DirectionInput
	case benchv1.Direction_DIRECTION_OUTPUT:
		return trifecta.DirectionOutput
	case benchv1.Direction_DIRECTION_TOOL_CALL:
		return trifecta.DirectionToolCall
	case benchv1.Direction_DIRECTION_TOOL_RESULT:
		return trifecta.DirectionToolResult
	default:
		return trifecta.DirectionUnspecified
	}
}

func protoToToolAnnotations(t *benchv1.ToolAnnotations) *trifecta.ToolAnnotations {
	if t == nil {
		return nil
	}
	out := &trifecta.ToolAnnotations{
		ToolName:      t.GetToolName(),
		ServerName:    t.GetServerName(),
		TrustedServer: t.GetTrustedServer(),
	}
	if t.ReadOnlyHint != nil {
		v := t.GetReadOnlyHint()
		out.ReadOnlyHint = &v
	}
	if t.DestructiveHint != nil {
		v := t.GetDestructiveHint()
		out.DestructiveHint = &v
	}
	if t.IdempotentHint != nil {
		v := t.GetIdempotentHint()
		out.IdempotentHint = &v
	}
	if t.OpenWorldHint != nil {
		v := t.GetOpenWorldHint()
		out.OpenWorldHint = &v
	}
	return out
}

func resultToProto(res trifecta.EvalResult) *benchv1.EvaluateResponse {
	spans := make([]*benchv1.SpanFinding, 0, len(res.Spans))
	for _, sp := range res.Spans {
		spans = append(spans, &benchv1.SpanFinding{
			EntityType:  sp.EntityType,
			BeginOffset: int32(sp.BeginOffset),
			EndOffset:   int32(sp.EndOffset),
			Confidence:  sp.Confidence,
		})
	}
	return &benchv1.EvaluateResponse{
		Blocked:             res.Blocked,
		RiskScore:           res.RiskScore,
		RedactedText:        res.RedactedText,
		Spans:               spans,
		TriggeredCategories: res.TriggeredCategories,
		TaintState: &benchv1.SessionTaint{
			ReadsPrivate:      res.TaintState.ReadsPrivate,
			ReadsUntrusted:    res.TaintState.ReadsUntrusted,
			SendsOut:          res.TaintState.SendsOut,
			TrifectaTriggered: res.TaintState.TrifectaTriggered,
		},
		Usage: &benchv1.UsageMetrics{
			InputChars:      int32(res.Usage.InputChars),
			TextUnitsBilled: int32(res.Usage.TextUnitsBilled),
			InputTokens:     int32(res.Usage.InputTokens),
			AdapterWallMs:   res.Usage.AdapterWallMs,
		},
		JudgeGraded: res.JudgeGraded,
	}
}
