# Contributing to guardrail-bench

This guide covers local setup, strict engineering invariants, testing expectations, and standard verification commands for `guardrail-bench`.

For system architecture and data contracts, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## 1. Prerequisites & Local Toolchain

- **Go:** `1.23+` (tested on `go1.27.4`)
- **Python:** `3.11+` managed via [`uv`](https://docs.astral.sh/uv/) (`ruff`, `mypy --strict`, `pytest`)
- **Protobuf compiler & Go plugins:** `protoc`, `protoc-gen-go`, and `protoc-gen-go-grpc` (required when modifying [proto/bench/v1/adapter.proto](proto/bench/v1/adapter.proto))
- **Docker (optional):** Required for the live Envoy `ext_proc` integration and chaos suite (`make envoy-up && make envoy-test`)

Install Python dev dependencies:

```bash
uv sync --frozen --dev
```

Install optional extras for live HuggingFace datasets, local open-source models, or AWS Bedrock:

```bash
uv sync --extra oss --extra aws --extra datasets
```

---

## 2. Engineering Invariants

All changes to Go and Python packages must preserve the following five invariants:

1. **Determinism:** Never use unseeded randomness (`math/rand` or Python `random` without an explicit seed propagated from `--seed`). Any map iteration affecting serialized output order (spans, categories, findings, JSON artifacts) must sort keys first.
2. **Zero Real Secrets:** Committed test fixtures, generators, and unit tests must use clearly marked RFC/AWS documentation canary tokens (e.g., `AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, `900-01-0001`, `@example.com`) so secret scanners never flag the repository.
3. **Untrusted MCP Hints:** In [pkg/trifecta/taint.go](pkg/trifecta/taint.go), never trust `readOnlyHint: true` or `openWorldHint: false` when `trusted_server == false`; always enforce conservative MCP specification defaults (`readOnly=false`, `destructive=true`, `idempotent=false`, `openWorld=true`).
4. **Separation of Concerns (`pkg/trifecta` Isolation):** Keep `pkg/trifecta` free of benchmark-only, `internal/`, gRPC, and Envoy dependencies so it remains importable by any standalone Go `ext_proc` binary (verified by `TestPkgTrifectaImportIsolation`).
5. **Error Handling & Resource Bounds:** Recursive decoding in [pkg/trifecta/decoder.go](pkg/trifecta/decoder.go) must remain bounded (defaults: `MaxDepth = 3`, `MaxDecodedBytes = 1 MiB`, `MaxCandidates = 64`) to prevent base64 zip-bomb and CPU-exhaustion DoS attacks.

---

## 3. Adapter Testing Conventions

- **Offline-first unit tests:** Python ML and cloud adapters (`llamafirewall`, `piguard`, `nemo_presidio`, `granite_guardian`, `bedrock_apply`, `bedrock_checks`) must ship deterministic offline unit tests using mock classifiers or `botocore.stub.Stubber` so `make test` completes without network access or GPUs in under 15 seconds.
- **Live integration gating:** Tests that download HuggingFace weights, query a live vLLM endpoint, or call AWS Bedrock must be decorated with `@pytest.mark.live` and run only when `--live` is passed explicitly.
- **Protobuf parity:** After changing [proto/bench/v1/adapter.proto](proto/bench/v1/adapter.proto), run `make proto` and commit the regenerated Go (`internal/gen/`) and Python (`python/bench_worker/gen/`, including mypy `.pyi` stubs) files. CI checks `git diff --exit-code` after running `make proto`.

---

## 4. Standard Verification Commands

```bash
# Regenerate Go and Python protobuf/gRPC/mypy stubs
make proto

# Go lint and race-enabled unit tests
go vet ./... && go test -race ./...

# Python lint, strict typecheck, and offline unit tests
uv run ruff check python/ tests/python/ datasets/scripts/
uv run mypy --strict python/ tests/python/ datasets/scripts/
uv run pytest tests/python/

# Full offline verification gate (proto + lint + Go/Python tests)
make smoke-gate

# Full local CI regression gate (smoke-gate + build + manifest check + 5-repeat cmp determinism + baseline gate)
make ci-gate

# Live Envoy ext_proc SSE streaming-tax and fail-open/fail-closed chaos suite
make envoy-up && make envoy-test && make envoy-down
```
