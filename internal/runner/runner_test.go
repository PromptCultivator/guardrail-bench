package runner_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/PromptCultivator/guardrail-bench/internal/client"
	"github.com/PromptCultivator/guardrail-bench/internal/dataset"
	"github.com/PromptCultivator/guardrail-bench/internal/runner"
	"github.com/PromptCultivator/guardrail-bench/pkg/trifecta"
)

func TestOpenLoopConcurrentRunnerDeterminismAndRaceSafety(t *testing.T) {
	t.Parallel()

	fixturePath := filepath.Join("..", "..", "datasets", "fixtures", "smoke_50.jsonl")
	samples, err := dataset.LoadJSONL(fixturePath)
	if err != nil {
		t.Fatalf("LoadJSONL: %v", err)
	}
	// Run a 12-sample slice across all 3 tracks under open-loop Poisson arrivals + 4 workers.
	subset := append([]dataset.Sample{}, samples[:4]...)
	subset = append(subset, samples[20:24]...)
	subset = append(subset, samples[35:39]...)

	opts := runner.Options{
		AdapterName:   "trifecta_extproc",
		DatasetPath:   fixturePath,
		DatasetSHA256: "test-sha",
		Seed:          42,
		Repeats:       3,
		Concurrency:   4,
		TargetRPS:     2000, // Fast open-loop Poisson pacing
		Timeout:       5 * time.Second,
	}

	c1 := client.NewInProcessTrifectaClient(trifecta.DefaultEngineConfig())
	art1, err := runner.Run(context.Background(), c1, subset, opts)
	if err != nil {
		t.Fatalf("Run 1: %v", err)
	}

	c2 := client.NewInProcessTrifectaClient(trifecta.DefaultEngineConfig())
	art2, err := runner.Run(context.Background(), c2, subset, opts)
	if err != nil {
		t.Fatalf("Run 2: %v", err)
	}

	if art1.ErrorCount != 0 || art2.ErrorCount != 0 {
		t.Fatalf("unexpected RPC errors: run1=%d run2=%d", art1.ErrorCount, art2.ErrorCount)
	}
	if art1.Latency == nil || art1.Latency.EndToEnd.Count == 0 {
		t.Fatalf("expected non-empty latency summary before WithoutTimings()")
	}

	b1, err := json.Marshal(art1.WithoutTimings())
	if err != nil {
		t.Fatalf("marshal 1: %v", err)
	}
	b2, err := json.Marshal(art2.WithoutTimings())
	if err != nil {
		t.Fatalf("marshal 2: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("concurrent open-loop runner did not produce byte-identical canonical output")
	}
}

func TestMeasureSSEStreamingTaxProbe(t *testing.T) {
	t.Parallel()

	makeSSEServer := func(delay time.Duration) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if delay > 0 {
				time.Sleep(delay)
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "data: {\"token\":\"hi\"}\n\ndata: [DONE]\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}))
	}

	passSrv := makeSSEServer(0)
	defer passSrv.Close()
	guardSrv := makeSSEServer(3 * time.Millisecond)
	defer guardSrv.Close()

	rep, err := runner.MeasureSSEStreamingTax(context.Background(), guardSrv.URL, passSrv.URL, 10, 2, 2*time.Second)
	if err != nil {
		t.Fatalf("MeasureSSEStreamingTax: %v", err)
	}
	if rep.Requests != 10 || rep.DeltaTTFTP50Ms < 2.0 {
		t.Fatalf("expected ΔTTFT p50 >= 2ms for 3ms artificial guard delay, got %+v", rep)
	}
}
