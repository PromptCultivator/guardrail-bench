package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type mockChatReq struct {
	Stream           bool   `json:"stream"`
	MockResponseText string `json:"mock_response_text"`
}

func main() {
	listenAddr := flag.String("listen", ":8080", "HTTP listen address")
	chunkDelay := flag.Duration("chunk-delay", 0, "Optional delay between SSE chunks after first token")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req mockChatReq
		_ = json.Unmarshal(body, &req)

		wantsStream := req.Stream || strings.Contains(r.Header.Get("Accept"), "text/event-stream")
		if wantsStream {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(http.StatusOK)

			flusher, hasFlusher := w.(http.Flusher)
			chunks := []string{"Hello ", "from ", "mock ", "LLM ", "SSE."}
			if req.MockResponseText != "" {
				chunks = []string{req.MockResponseText}
			}
			for i, tok := range chunks {
				if i > 0 && *chunkDelay > 0 {
					time.Sleep(*chunkDelay)
				}
				payload, _ := json.Marshal(map[string]any{
					"id": "mock-sse-1",
					"choices": []map[string]any{
						{"index": 0, "delta": map[string]string{"content": tok}},
					},
				})
				_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
				if hasFlusher {
					flusher.Flush()
				}
			}
			_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
			if hasFlusher {
				flusher.Flush()
			}
			return
		}

		content := "ok"
		if req.MockResponseText != "" {
			content = req.MockResponseText
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "mock-chat-1",
			"choices": []map[string]any{
				{"index": 0, "message": map[string]string{"role": "assistant", "content": content}},
			},
		})
	})

	handleMCP := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"executed"}`))
	}
	mux.HandleFunc("/mcp/call", handleMCP)
	mux.HandleFunc("/mcp/tool_result", handleMCP)

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("mock-llm-sse listening on %s", *listenAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("mock-llm-sse serve: %v", err)
	}
}
