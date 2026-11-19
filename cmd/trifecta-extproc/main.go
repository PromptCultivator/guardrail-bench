package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	benchv1 "github.com/PromptCultivator/guardrail-bench/internal/gen/bench/v1"
	"github.com/PromptCultivator/guardrail-bench/pkg/trifecta"
)

func main() {
	listenAddr := flag.String("listen", ":9002", "TCP listen address (or unix:/path/to.sock)")
	maxDepth := flag.Int("max-decode-depth", trifecta.DefaultMaxDepth, "Maximum recursive decode depth")
	maxDecodedBytes := flag.Int("max-decoded-bytes", trifecta.DefaultMaxDecodedBytes, "Maximum decoded bytes per request")
	flag.Parse()

	cfg := trifecta.DefaultEngineConfig()
	cfg.Decoder.MaxDepth = *maxDepth
	cfg.Decoder.MaxDecodedBytes = *maxDecodedBytes

	engine := trifecta.NewEngine(cfg)
	srv := NewServer(engine)

	grpcServer := grpc.NewServer()
	benchv1.RegisterAdapterServiceServer(grpcServer, srv)
	extprocv3.RegisterExternalProcessorServer(grpcServer, srv)

	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus("envoy.service.ext_proc.v3.ExternalProcessor", healthpb.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus("bench.v1.AdapterService", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthSrv)

	network := "tcp"
	addr := *listenAddr
	if len(addr) > 5 && addr[:5] == "unix:" {
		network = "unix"
		addr = addr[5:]
		_ = os.Remove(addr)
	}

	lis, err := net.Listen(network, addr)
	if err != nil {
		log.Fatalf("trifecta-extproc listen %s://%s: %v", network, addr, err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("trifecta-extproc shutting down on signal %v", sig)
		healthSrv.Shutdown()
		grpcServer.GracefulStop()
	}()

	log.Printf("trifecta-extproc listening on %s://%s (AdapterService + Envoy ext_proc v3)", network, addr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("trifecta-extproc serve: %v", err)
	}
}
