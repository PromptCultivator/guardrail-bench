package client

import (
	"context"
	"fmt"
	"strings"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	benchv1 "github.com/PromptCultivator/guardrail-bench/internal/gen/bench/v1"
	"github.com/PromptCultivator/guardrail-bench/pkg/trifecta"
)

// AdapterClient is the unified interface used by internal/runner to drive both
// out-of-process gRPC adapters (TCP or UDS) and the in-process Go trifecta baseline.
type AdapterClient interface {
	Health(ctx context.Context) (*benchv1.HealthResponse, error)
	Evaluate(ctx context.Context, req *benchv1.EvaluateRequest) (*benchv1.EvaluateResponse, error)
	ResetSession(ctx context.Context, sessionID string) error
	Close() error
}

// GRPCClient connects to any AdapterService over TCP ("host:port") or Unix domain socket ("unix:///path").
type GRPCClient struct {
	conn   *grpc.ClientConn
	client benchv1.AdapterServiceClient
}

// DialGRPC opens a gRPC client connection to target.
func DialGRPC(target string) (*GRPCClient, error) {
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("gRPC target address is required")
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial gRPC adapter %q: %w", target, err)
	}
	return &GRPCClient{
		conn:   conn,
		client: benchv1.NewAdapterServiceClient(conn),
	}, nil
}

func (c *GRPCClient) Health(ctx context.Context) (*benchv1.HealthResponse, error) {
	return c.client.Health(ctx, &benchv1.HealthRequest{})
}

func (c *GRPCClient) Evaluate(ctx context.Context, req *benchv1.EvaluateRequest) (*benchv1.EvaluateResponse, error) {
	return c.client.Evaluate(ctx, req)
}

func (c *GRPCClient) ResetSession(ctx context.Context, sessionID string) error {
	_, err := c.client.ResetSession(ctx, &benchv1.ResetSessionRequest{SessionId: sessionID})
	return err
}

func (c *GRPCClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// EnvoyExtProcClient opens raw envoy.service.ext_proc.v3.ExternalProcessor streams for direct probing.
type EnvoyExtProcClient struct {
	conn   *grpc.ClientConn
	client extprocv3.ExternalProcessorClient
}

// DialEnvoyExtProc opens an ExternalProcessor gRPC connection to target.
func DialEnvoyExtProc(target string) (*EnvoyExtProcClient, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial ext_proc %q: %w", target, err)
	}
	return &EnvoyExtProcClient{
		conn:   conn,
		client: extprocv3.NewExternalProcessorClient(conn),
	}, nil
}

func (c *EnvoyExtProcClient) Process(ctx context.Context) (extprocv3.ExternalProcessor_ProcessClient, error) {
	return c.client.Process(ctx)
}

func (c *EnvoyExtProcClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// InProcessTrifectaClient runs the native Go pkg/trifecta engine directly in-process
// behind the same AdapterClient interface, enabling zero-setup local CLI runs.
type InProcessTrifectaClient struct {
	engine *trifecta.Engine
}

// NewInProcessTrifectaClient creates an in-process trifecta_extproc adapter client.
func NewInProcessTrifectaClient(cfg trifecta.EngineConfig) *InProcessTrifectaClient {
	return &InProcessTrifectaClient{
		engine: trifecta.NewEngine(cfg),
	}
}

func (c *InProcessTrifectaClient) Health(_ context.Context) (*benchv1.HealthResponse, error) {
	return &benchv1.HealthResponse{
		AdapterName:  "trifecta_extproc",
		ModelVersion: "0.2.0",
	}, nil
}

func (c *InProcessTrifectaClient) ResetSession(_ context.Context, sessionID string) error {
	c.engine.ResetSession(sessionID)
	return nil
}

func (c *InProcessTrifectaClient) Evaluate(ctx context.Context, req *benchv1.EvaluateRequest) (*benchv1.EvaluateResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var tool *trifecta.ToolAnnotations
	if mt := req.GetMcpTool(); mt != nil {
		tool = &trifecta.ToolAnnotations{
			ToolName:      mt.GetToolName(),
			ServerName:    mt.GetServerName(),
			TrustedServer: mt.GetTrustedServer(),
		}
		if mt.ReadOnlyHint != nil {
			v := mt.GetReadOnlyHint()
			tool.ReadOnlyHint = &v
		}
		if mt.DestructiveHint != nil {
			v := mt.GetDestructiveHint()
			tool.DestructiveHint = &v
		}
		if mt.IdempotentHint != nil {
			v := mt.GetIdempotentHint()
			tool.IdempotentHint = &v
		}
		if mt.OpenWorldHint != nil {
			v := mt.GetOpenWorldHint()
			tool.OpenWorldHint = &v
		}
	}

	var dir trifecta.Direction
	switch req.GetDirection() {
	case benchv1.Direction_DIRECTION_INPUT:
		dir = trifecta.DirectionInput
	case benchv1.Direction_DIRECTION_OUTPUT:
		dir = trifecta.DirectionOutput
	case benchv1.Direction_DIRECTION_TOOL_CALL:
		dir = trifecta.DirectionToolCall
	case benchv1.Direction_DIRECTION_TOOL_RESULT:
		dir = trifecta.DirectionToolResult
	default:
		dir = trifecta.DirectionUnspecified
	}

	res := c.engine.Evaluate(trifecta.EvalInput{
		SampleID:  req.GetSampleId(),
		SessionID: req.GetSessionId(),
		TurnIndex: int(req.GetTurnIndex()),
		Direction: dir,
		Role:      req.GetRole(),
		Text:      req.GetText(),
		MCPTool:   tool,
	})

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
	}, nil
}

func (c *InProcessTrifectaClient) Close() error { return nil }
