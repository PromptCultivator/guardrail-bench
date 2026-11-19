# guardrail-bench — Empirical Benchmark Report

This document records the empirical benchmarks executed against `guardrail-bench` and its native Go Envoy `ext_proc` baseline (`trifecta-extproc`), including exact dataset revisions, SHA-256 digests, pre-flight decontamination findings, live Envoy proxy latency, adversarial DoS micro-benchmarks, cross-plane UDS comparisons, and annualized TCO projections.

All results are separated into **Live Empirical Measurements** (real engines, live HuggingFace datasets, live Docker Envoy `v1.33.0`) and **Offline CI Harness Measurements** (deterministic mocks and `botocore.stub.Stubber` verification). For architectural design and metric derivations, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## 1. Testbed & Provenance

| Parameter | Value |
|---|---|
| **Hardware** | Apple M5 (`arm64`), 10-core |
| **OS / Runtime** | macOS 26.5.1, `go1.27.4`, `Python 3.12.9` (`uv 0.13.9`) |
| **Proxy / Containers** | Docker `29.5.3`, `envoyproxy/envoy:v1.33.0`, `alpine:3.21` |
| **Protobuf / gRPC** | `libprotoc 36.2`, `google.golang.org/grpc v1.85.0`, `grpcio 1.85.3`, `boto3 1.44.6` |
| **PRNG Seed & Bootstrap** | `--seed 42`, B = 1,000 non-parametric bootstrap resamples (95% CIs) |

### Pinned Dataset Revisions & Integrity Digests

| Split / Dataset | Source Repository | Pinned Commit SHA | Rows | Split SHA-256 (`--seed 42`) |
|---|---|---|---|---|
| **Smoke Fixture** (`smoke_50.jsonl`) | Local deterministic synthetic canary corpus | `local-deterministic-v1` | 50 (20 T1 / 15 T2 / 15 T3) | `9bf3426e30e4d7c2490b43d3e15c6452423b43b148fde2c131383d0b91799c5b` |
| **Track 1** (`track1_injection.jsonl`) | `deepset/prompt-injections` (`test`, 116) | `4f61ecb038e9c3fb77e21034b22511b523772cdd` | 2,515 raw (2,353 clean) | `3c14bae0aef3443bf7323967c8324c4b3e0ef67b43271dd6f277013fe9feb47d` |
| ↳ *Track 1 (cont.)* | `xTRam1/safe-guard-prompt-injection` (`test`, 2,060) | `a3a877d608f37b7d20d9945671902df895ecdb46` | — | — |
| ↳ *Track 1 (cont.)* | `leolee99/NotInject` (`NotInject_one`/`two`/`three`, 113 × 3) | `847ae76cf8fea5ed325429e569ae8cfef022d2e0` | — | — |
| **Track 2** (`track2_redaction.jsonl`) | `ai4privacy/pii-masking-300k` (`validation`, 2,000 sampled of 47,728) + 1,000 synthetic secrets/code | `c8c77895a005822682b66ab547fc0422579bc1d3` | 3,000 | `b5bcd022ac50af1ed740de80f89a4937ca024156b10bd9f308c32a5d788662c6` |
| **Track 3** (`track3_mcp_trifecta.jsonl`) | `corteus/trifecta-bench` 9-server expansion (120 dangerous / 80 safe) | `main` (`local-deterministic-v1`) | 200 sessions (550 turns) | `32d8329d2af353489e902e52a534f294316111c18b71131ce0a6ee8b51423a0b` |

---

## 2. Live Pre-Flight Decontamination Findings

Before scoring Track 1, `guardrail-bench decontaminate` evaluated all **2,515** held-out Track 1 test prompts against **8,782** live training rows (`deepset/prompt-injections` `train` = 546 rows + `xTRam1/safe-guard-prompt-injection` `train` = 8,236 rows) using verbatim SHA-256 hashing and inverted-index token 5-gram Jaccard similarity (threshold ≥ 0.90):

| Metric | Live Result | Notable Empirical Finding |
|---|---|---|
| **Eval rows scanned** | 2,515 | `deepset` test + `safe-guard` test + `NotInject` |
| **Reference training rows** | 8,782 | `deepset` train + `safe-guard` train |
| **Verbatim SHA-256 overlaps caught** | **106** | Cross-dataset leakage (e.g., `deepset` test #1 appears verbatim in `safe-guard` train #7071) and intra-dataset test/train duplicates inside `safe-guard` (test #13 repeated 4× in train) |
| **5-gram Jaccard ≥ 0.90 near-duplicates caught** | **56** | Paraphrased / slightly trimmed copies of training prompts |
| **Clean rows retained (`--out-clean`)** | **2,353** | Zero overlap verified before scoring |

### Reproduction

```bash
uv sync --extra datasets
uv run python datasets/scripts/build_splits.py --mode live --seed 42
./bin/guardrail-bench decontaminate \
  --dataset datasets/splits/track1_injection.jsonl \
  --refs /path/to/train_refs.jsonl \
  --out-clean datasets/splits/track1_clean.jsonl
```

---

## 3. Live Full-Corpus Benchmark: `trifecta_extproc` (5,553 Clean Rows, 11,976 Turns)

Executed with `./bin/guardrail-bench run --adapter trifecta_extproc --repeats 2 --concurrency 4 --seed 42 --include-timings` across the decontaminated live HuggingFace splits (Track 1 clean + Track 2 live + Track 3 200-session expansion):

### A. Combined 3-Track Summary

| Adapter | Eval Mode | Evaluated Turns | Track 1 Recall@1%FPR (95% CI) | Real `NotInject` Acc (339 rows, 1/2/3-trig) | Track 2 Char-IoU | Track 2 RSLR | Track 3 Trifecta Block / Safe | VFR | σ̄_s | Wall p50 / p99 | Mean TU |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `trifecta_extproc` (`v0.2.0`) | deterministic (11,976 det / 0 judge) | 11,976 | **8.1%** [6.1%, 10.5%] | **100.0%** (100% / 100% / 100%) | **43.0%** | **85.3%** | **100.0% / 100.0%** | **0.0000** | **0.0000** | **0.08 ms / 0.78 ms** | 1.05 |

### B. Granular Live Sub-Slice Breakdown (`trifecta_extproc`)

Separating Track 2 into its structured secrets/source-code slice vs. multilingual free-text NER slice exposes the exact capability boundary of a deterministic non-ML guardrail:

| Live Sub-Slice | Samples | Turns (2× repeats) | Primary Efficacy Metric | Residual Leak / FP | Wall p50 / p99 (ms) | VFR |
|---|---|---|---|---|---|---|
| **Track 1 — `leolee99/NotInject` (live)** | 339 | 678 | **100.0%** benign allow (113/113 per subset) | **0.0%** false positives | 0.05 / 0.25 | 0.0000 |
| **Track 1 — `deepset` + `safe-guard` (decontaminated)** | 2,014 | 4,028 | **8.1%** Recall@1%FPR [6.1%, 10.5%] | 0.0% FPR @ τ | 0.06 / 0.40 | 0.0000 |
| **Track 2a — Synthetic Secrets & Proprietary Code** (AWS, GitHub, JWT, PEM, base64, Python, SQL) | 1,000 | 2,000 | **100.0%** Char-IoU | **0.0%** RSLR | 0.10 / 0.53 | 0.0000 |
| **Track 2b — Live `ai4privacy/pii-masking-300k`** (multilingual NER: EN/DE/IT/ES) | 2,000 | 4,000 | **11.0%** Char-IoU | **92.5%** RSLR | 0.19 / 0.76 | 0.0000 |
| **Track 3 — 200 MCP Trifecta Sessions** (120 dangerous / 80 safe across 4 failure patterns) | 200 | 1,100 | **100.0%** outbound block (120/120) | **100.0%** safe pass (80/80), 0 premature blocks | 0.04 / 0.22 | 0.0000 |

### Engineering Takeaways

1. **Zero over-defense on real `NotInject` (339/339):** Imperative-structure rules paired with defensive-context gating avoid trigger-word false positives across all three trigger-density tiers.
2. **Deterministic DLP covers structured secrets and source code (100% Char-IoU, 0% RSLR) at sub-millisecond tail latency (0.53 ms p99):** Handles keys, tokens, PEM blocks, base64-encoded secrets, and multi-line code inline at the proxy.
3. **Layered defense is required for semantic and free-text NER coverage:** Pure regex/entropy reaches **8.1% Recall@1%FPR** on unconstrained semantic/multilingual prompt injections (`deepset` + `safe-guard`) and **11.0% Char-IoU** on multilingual free-text NER (`ai4privacy`). Production stacks should combine `trifecta-extproc` inline at the Envoy proxy (for sub-millisecond MCP trifecta, encoding normalization, and secrets/code DLP) with a neural classifier (`PIGuard` or `LlamaFirewall`) and an NER or cloud policy engine (`Presidio` or `AWS Bedrock`).

---

## 4. Live Envoy `ext_proc` Proxy Latency, SSE Streaming Tax & Chaos Gate

Measured against the live 3-container Docker Compose topology ([docker-compose.yaml](deployments/envoy/docker-compose.yaml): `envoyproxy/envoy:v1.33.0` + `trifecta-extproc` on `:9002` + `mock-llm-sse` on `:8080`):

### A. Proxy & SSE Streaming Tax (`ΔTTFT = TTFT_guarded − TTFT_passthrough`)

| Probe / Workload | Measurement | Passthrough (`:10002`) | Guarded `ext_proc` (`:10000`) | Overhead / Delta | Gate Threshold | Status |
|---|---|---|---|---|---|---|
| **`make envoy-test` SSE Suite** (two 60-req trials) | TTFT p50 | `0.315 ms` – `0.348 ms` | `0.459 ms` – `0.594 ms` | `+0.144 ms` – `+0.246 ms` | — | PASS |
| ↳ *Trial A / Trial B* | **TTFT p99** | `0.509 ms` / `0.440 ms` | `0.755 ms` / `1.065 ms` | **`+0.246 ms` / `+0.625 ms`** | `< 5.0 ms` | **PASS** |
| **CLI Probe (`guardrail-bench run --target 127.0.0.1:9002`, 60 SSE reqs)** | **SSE ΔTTFT p99** | — | — | **`+0.31 ms`** | `< 5.0 ms` | **PASS** |
| **Direct gRPC to Containerized `:9002` (380 turns)** | Wall p50 / p99 | — | `0.03 ms / 0.12 ms` | — | — | PASS |
| ↳ *Direct gRPC to Containerized `:9002` (380 turns)* | E2E gRPC p50 / p99 | — | `0.18 ms / 0.52 ms` | — | — | PASS |

### B. Live Envoy Policy Enforcement & Chaos Verification

| Scenario | Envoy Listener | Expected Behavior | Observed Result | Status |
|---|---|---|---|---|
| **8 Dangerous Track 3 MCP Trifecta Scenarios** (`filesystem` + unannotated `fetch`, untrusted hint spoofing, `EchoLeak` `ResponseBody` Markdown image, memory cross-turn, double-base64) | `:10000` (fail-closed) | HTTP `200` on pre-exfil turns; HTTP `403` + `x-guardrail-blocked: true` on exact outbound turn | **8 / 8 blocked on exact outbound turn** | **PASS** |
| **7 Safe Track 3 MCP Scenarios** (≤ 2 trifecta legs) | `:10000` (fail-closed) | HTTP `200` on every turn | **7 / 7 passed every turn** | **PASS** |
| **Chaos: `trifecta-extproc` container stopped** (`docker compose stop`) | `:10001` (`failure_mode_allow: true`) | Fail-open cleanly (HTTP `200`) | **HTTP `200`** | **PASS** |
| **Chaos: `trifecta-extproc` container stopped** (`docker compose stop`) | `:10000` (`failure_mode_allow: false`) | Fail-closed (HTTP `500` or `403`) | **HTTP `500`** | **PASS** |
| **Recovery: `trifecta-extproc` container restarted** | `:10000` | Clean health & enforcement recovery | **HTTP `200` recovered** | **PASS** |

### Reproduction

```bash
make envoy-up
make envoy-test
./bin/guardrail-bench run \
  --adapter trifecta_extproc \
  --target 127.0.0.1:9002 \
  --dataset datasets/fixtures/smoke_50.jsonl \
  --repeats 5 --seed 42 --include-timings \
  --sse-guarded-url http://127.0.0.1:10000/v1/chat/completions \
  --sse-passthrough-url http://127.0.0.1:10002/v1/chat/completions \
  --sse-requests 60 --out /tmp/envoy_run.json
./bin/guardrail-bench report --input /tmp/envoy_run.json --format markdown
make envoy-down
```

---

## 5. `pkg/trifecta` Go Micro-Benchmarks & Adversarial DoS Bounds

Executed via `go test -bench=. -benchmem -benchtime=500ms ./pkg/trifecta` on Apple M5 (`go1.27.4`, `darwin/arm64`):

| Benchmark | Workload Description | Latency (`ns/op`) | Throughput (single core) | Memory (`B/op`) | Allocs (`allocs/op`) |
|---|---|---|---|---|---|
| `BenchmarkEngineBenignPrompt` | Standard benign user prompt (ASCII fast-path NFKC) | **`41,552 ns` (`41.6 µs`)** | ~24,066 req/s | **`2 B`** | **`0`** |
| `BenchmarkEngineMCP3TurnTrifecta` | Complete 3-turn session (`read_file` → `get_issue` → unannotated `fetch` block) | **`58,312 ns` (`58.3 µs`)** | ~17,149 sessions/s | `4,680 B` | `47` |
| `BenchmarkEngineDepth3Base64Secret` | Nested triple-base64 AWS canary key decode + span mapping + redaction | **`73,764 ns` (`73.8 µs`)** | ~13,557 req/s | `2,620 B` | `46` |
| `BenchmarkDecoder1_5MiBBase64Bomb` | Adversarial 1.5 MiB base64 zip-bomb (bounded to 1 MiB, `Truncated=true`) | **`5,080,786 ns` (`5.08 ms`)** | ~197 bombs/s | **`132 B`** | **`2`** |

---

## 6. Cross-Plane Offline Smoke Harness (`smoke_50.jsonl`, 50 Rows)

> **Scope note:** In this offline comparison (`TestCrossPlaneGoOrchestratorToPythonUDSWorkers` + `make ci-gate`), `trifecta_extproc` runs its real Go engine while Plane 2 Python workers (`llamafirewall`, `piguard`, `nemo_presidio`, `granite_guardian`) run over real asyncio gRPC Unix domain sockets using deterministic offline CI mocks, and AWS Bedrock adapters (`bedrock_apply`, `bedrock_checks`) are verified against live `botocore==1.44.6` schemas via `botocore.stub.Stubber`.

| Adapter | Plane / Transport | Mode (`judge_graded`) | Recall@1%FPR (95% CI) | NotInject Acc (1/2/3-trig) | Char-IoU | RSLR | MCP Trifecta Block / Safe | VFR | E2E p50 / p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|
| `trifecta_extproc` | Plane 1 Go (in-proc / gRPC) | deterministic (`false`) | 100.0% [100.0%, 100.0%] | 100.0% (100% / 100% / 100%) | 93.4% | 11.1% | 100.0% / 100.0% | 0.0000 | 0.18 / 0.52 (Docker TCP) |
| `piguard` (`-mock`) | Plane 2 Python `grpc.aio` UDS | deterministic (`false`) | 80.0% [59.8%, 100.0%] | 100.0% (100% / 100% / 100%) | 0.0% | 100.0% | 0.0% / 100.0% | 0.0000 | 0.28 / 0.52 (UDS) |
| `llamafirewall` (`-mock`) | Plane 2 Python `grpc.aio` UDS | deterministic (`false`) | 0.0% [0.0%, 50.2%] | 83.3% (100% / 100% / 50%) | 5.0% | 88.9% | 0.0% / 100.0% | 0.0000 | 0.35 / 2.98 (UDS) |
| `nemo_presidio` (`-mock`) | Plane 2 Python `grpc.aio` UDS | deterministic (`false`) / rails (`true`) | — (PII NER focus) | — | Multibyte `PERSON`+`EMAIL` exact | 0% on PII | — | 0.0000 | Verified via `pytest` |
| `granite_guardian` (`-mock`) | Plane 2 Python `grpc.aio` UDS (vLLM) | **model_judge (`true`)** | Logprob `P(Yes)/(P(Yes)+P(No))` + `<think>` | — | — | — | `function_call` criterion | — | Verified via `pytest` |
| `bedrock_apply` (`Stubber`) | Plane 2 Python `boto3 1.44.6` | deterministic (`false`) | `GUARDRAIL_INTERVENED` + `boto3` #4317 `\n` fix | — | Exact UTF-8 alignment | Paid PII vs. free regex | — | 0.0000 | Verified via `Stubber` |
| `bedrock_checks` (`Stubber`) | Plane 2 Python `boto3 1.44.6` | deterministic (`false`) | Continuous `severityScore` (0.0–1.0) | — | Exact `beginOffset`/`endOffset` | Zero residual leak | — | 0.0000 | Verified via `Stubber` |

---

## 7. Annualized TCO Projections (`internal/scorer/tco.go`)

Computed with `AnnualCost(V) = 12 · ( V · (ū / 1000) · r_unit + C_infra,monthly(V) )`:

### A. At `ū = 1.00` TU/req (`smoke_50.jsonl` / short agentic prompts)

| Adapter | Pricing Model | Annual @ 0.5M/mo | Annual @ 1M/mo | Annual @ 5M/mo | Annual @ 10M/mo |
|---|---|---|---|---|---|
| `trifecta_extproc` | 2× ARM64 Graviton Fargate HA (`$57.67/mo`) | `$692.04` | `$692.04` | `$692.04` | `$692.04` |
| `bedrock_checks` | `$0.18 / 1k TU` (Prompt Attack `$0.08` + PII `$0.10`) | `$1,080.00` | `$2,160.00` | `$10,800.00` | `$21,600.00` |
| `bedrock_apply` | `$0.25 / 1k TU` (Content `$0.15` + PII `$0.10`; regex free) | `$1,500.00` | `$3,000.00` | `$15,000.00` | `$30,000.00` |
| `llamafirewall` | 2× `c7g.xlarge` compute-amortized (`$211.70/mo`) | `$2,540.40` | `$2,540.40` | `$2,540.40` | `$2,540.40` |
| `piguard` | 2× `c7g.xlarge` compute-amortized (`$211.70/mo`) | `$2,540.40` | `$2,540.40` | `$2,540.40` | `$2,540.40` |
| `nemo_presidio` | 2× `m7g.xlarge` compute-amortized (`$262.80/mo`) | `$3,153.60` | `$3,153.60` | `$3,153.60` | `$3,153.60` |
| `granite_guardian` | Self-hosted vLLM `g5.2xlarge` (`$1.212/hr`, `$884.76/mo` base) | `$10,617.12` | `$10,617.12` | `$10,617.12` | `$10,617.12` |

### B. At Empirical Live Corpus `ū = 1.05` TU/req (`deepset` + `safe-guard` + `NotInject` + `ai4privacy`)

| Adapter | Annual @ 0.5M/mo | Annual @ 1M/mo | Annual @ 5M/mo | Annual @ 10M/mo |
|---|---|---|---|---|
| `trifecta_extproc` | `$692.04` | `$692.04` | `$692.04` | `$692.04` |
| `bedrock_checks` | `$1,134.00` | `$2,268.00` | `$11,340.00` | `$22,680.00` |
| `bedrock_apply` | `$1,575.00` | `$3,150.00` | `$15,750.00` | `$31,500.00` |
| `llamafirewall` / `piguard` | `$2,540.40` | `$2,540.40` | `$2,540.40` | `$2,540.40` |
| `nemo_presidio` | `$3,153.60` | `$3,153.60` | `$3,153.60` | `$3,153.60` |
| `granite_guardian` | `$10,617.12` | `$10,617.12` | `$10,617.12` | `$10,617.12` |

---

## 8. Offline CI & Test Suite Runtime Benchmarks

| Command | Scope | Measured Wall Time | Result |
|---|---|---|---|
| `make proto && go test -count=1 ./... && uv run pytest` | Protobuf codegen + all Go & Python unit tests | `~1.6 s` – `~4.8 s` | EXIT 0 |
| `make ci-gate` | Full PR gate: proto + `go vet` + `ruff` + `mypy --strict` (24 files) + `go test -race` + `pytest` (25 passed) + binary build + manifest SHA-256 + 2× 5-repeat `cmp` byte-parity + `guardrail-bench gate` | **`6.65 s`** | EXIT 0 |
| `make envoy-test` | Live Docker Envoy SSE (60 reqs × 2) + 15 Track 3 sessions + container kill/restart chaos | **`1.30 s` – `1.67 s`** | EXIT 0 |
