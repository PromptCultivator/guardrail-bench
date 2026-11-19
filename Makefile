SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

GOPATH_BIN := $(shell go env GOPATH)/bin
PROTO_DIR := proto
PROTO_FILE := $(PROTO_DIR)/bench/v1/adapter.proto
GO_GEN_DIR := internal/gen
PY_GEN_DIR := python/bench_worker/gen

.PHONY: help proto lint test go-test py-test smoke-gate ci-gate build clean envoy-up envoy-test envoy-down

help:
	@echo "Available targets:"
	@echo "  make proto       Generate Go and Python gRPC/Protobuf stubs"
	@echo "  make lint        Run go vet, ruff, and mypy --strict"
	@echo "  make test        Run all offline Go (-race) and Python unit tests"
	@echo "  make smoke-gate  Run full offline verification gate (proto + lint + test)"
	@echo "  make ci-gate     Run full local CI regression gate against pinned smoke baseline"
	@echo "  make envoy-up    Start local Envoy + trifecta-extproc + mock-llm-sse stack"
	@echo "  make envoy-test  Run live Envoy integration & chaos tests"
	@echo "  make envoy-down  Stop and remove local Envoy stack"
	@echo "  make clean       Remove build artifacts"

proto:
	@mkdir -p $(GO_GEN_DIR) $(PY_GEN_DIR)/bench/v1
	@PATH="$(GOPATH_BIN):$$PATH" protoc \
		-I $(PROTO_DIR) \
		--go_out=$(GO_GEN_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(GO_GEN_DIR) --go-grpc_opt=paths=source_relative \
		$(PROTO_FILE)
	@uv run python -m grpc_tools.protoc \
		-I $(PROTO_DIR) \
		--python_out=$(PY_GEN_DIR) \
		--grpc_python_out=$(PY_GEN_DIR) \
		--mypy_out=$(PY_GEN_DIR) \
		--mypy_grpc_out=$(PY_GEN_DIR) \
		$(PROTO_FILE)
	@uv run python -c 'import pathlib; gen_dir = pathlib.Path("$(PY_GEN_DIR)/bench/v1"); [p.write_text(p.read_text(encoding="utf-8").replace("from bench.v1 import adapter_pb2", "from bench_worker.gen.bench.v1 import adapter_pb2"), encoding="utf-8") for p in sorted(gen_dir.glob("adapter_pb2_grpc.py*"))]'
	@printf '"""Generated protobuf and gRPC modules."""\n' > $(PY_GEN_DIR)/__init__.py
	@printf '"""Generated bench protobuf namespace."""\n' > $(PY_GEN_DIR)/bench/__init__.py
	@printf '"""Generated bench.v1 protobuf and gRPC stubs."""\n' > $(PY_GEN_DIR)/bench/v1/__init__.py

lint:
	go vet ./...
	uv run ruff check python/ tests/python/
	uv run mypy --strict python/

go-test:
	go test -race ./...

py-test:
	uv run pytest tests/python/

test: go-test py-test

smoke-gate: proto lint test

ci-gate: smoke-gate build
	./bin/guardrail-bench validate --manifest datasets/manifests/smoke_50.manifest.json
	./bin/guardrail-bench run --adapter trifecta_extproc --dataset datasets/fixtures/smoke_50.jsonl --repeats 5 --seed 42 --out /tmp/gb_ci_r1.json
	./bin/guardrail-bench run --adapter trifecta_extproc --dataset datasets/fixtures/smoke_50.jsonl --repeats 5 --seed 42 --out /tmp/gb_ci_r2.json
	cmp /tmp/gb_ci_r1.json /tmp/gb_ci_r2.json
	./bin/guardrail-bench gate \
		--baseline datasets/baselines/trifecta_extproc_smoke_50.score.json \
		--candidate /tmp/gb_ci_r1.json \
		--max-recall-drop 0.01 \
		--max-notinject-drop 0.01 \
		--max-trifecta-drop 0.01 \
		--max-rslr-increase 0.01 \
		--max-p99-regression 0.15 \
		--require-zero-vfr
	@rm -f /tmp/gb_ci_r1.json /tmp/gb_ci_r2.json

build:
	@mkdir -p bin
	@if [ -f cmd/guardrail-bench/main.go ]; then go build -o bin/guardrail-bench ./cmd/guardrail-bench; fi
	@if [ -f cmd/trifecta-extproc/main.go ]; then go build -o bin/trifecta-extproc ./cmd/trifecta-extproc; fi
	@if [ -f cmd/mock-llm-sse/main.go ]; then go build -o bin/mock-llm-sse ./cmd/mock-llm-sse; fi

envoy-up:
	docker compose -f deployments/envoy/docker-compose.yaml up -d --build

envoy-test:
	ENVOY_INTEGRATION=1 go test -v -count=1 -run TestEnvoyDockerComposeIntegration ./tests/go

envoy-down:
	docker compose -f deployments/envoy/docker-compose.yaml down --remove-orphans

clean:
	rm -rf bin/ dist/ coverage.txt
