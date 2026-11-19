package runner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MeasureSSEStreamingTax benchmarks benign SSE Time-to-First-Token (TTFT) across a
// guarded proxy endpoint vs a passthrough proxy endpoint:
//
//	ΔTTFT = TTFT_guarded − TTFT_passthrough
func MeasureSSEStreamingTax(
	ctx context.Context,
	guardedURL string,
	passthroughURL string,
	requests int,
	warmup int,
	timeout time.Duration,
) (*SSEReport, error) {
	if requests <= 0 {
		requests = 50
	}
	if warmup < 0 {
		warmup = 0
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	defer httpClient.CloseIdleConnections()

	payload := []byte(`{"stream":true,"messages":[{"role":"user","content":"Summarize Envoy HTTP/2 connection pooling."}]}`)

	measure := func(endpoint string) ([]float64, error) {
		for w := 0; w < warmup; w++ {
			if _, err := measureSingleTTFT(ctx, httpClient, endpoint, payload); err != nil {
				return nil, fmt.Errorf("warmup SSE %s: %w", endpoint, err)
			}
		}
		vals := make([]float64, 0, requests)
		for i := 0; i < requests; i++ {
			ms, err := measureSingleTTFT(ctx, httpClient, endpoint, payload)
			if err != nil {
				return nil, fmt.Errorf("SSE request %d (%s): %w", i, endpoint, err)
			}
			vals = append(vals, ms)
		}
		return vals, nil
	}

	passVals, err := measure(passthroughURL)
	if err != nil {
		return nil, err
	}
	guardVals, err := measure(guardedURL)
	if err != nil {
		return nil, err
	}

	passStats := ComputeLatencyStats(passVals)
	guardStats := ComputeLatencyStats(guardVals)

	return &SSEReport{
		Requests:        requests,
		PassthroughTTFT: passStats,
		GuardedTTFT:     guardStats,
		DeltaTTFTP50Ms:  guardStats.P50Ms - passStats.P50Ms,
		DeltaTTFTP95Ms:  guardStats.P95Ms - passStats.P95Ms,
		DeltaTTFTP99Ms:  guardStats.P99Ms - passStats.P99Ms,
	}, nil
}

func measureSingleTTFT(ctx context.Context, client *http.Client, endpoint string, payload []byte) (float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		if strings.HasPrefix(line, "data:") {
			return float64(time.Since(start).Nanoseconds()) / 1e6, nil
		}
	}
}
