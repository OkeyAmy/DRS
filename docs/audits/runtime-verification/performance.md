# DRS Performance Assessment

## Method

Benchmarks use real verifier paths in a controlled environment. Raw outputs stay
in `.local/drs-assessment/benchmark-raw/`. Every result must include command,
commit SHA, CPU model, memory, operating system, verifier config, nonce backend,
chain depth, body-binding setting, p50, p95, p99, throughput, and error rate.

## Workloads

| Workload | Chain depth | DID mode | Nonce backend | Body binding | Metrics |
|---|---:|---|---|---|---|
| B-001 | 1 | `did:key` | memory | off | p50/p95/p99, throughput, errors |
| B-002 | 3 | `did:key` | memory | off | p50/p95/p99, throughput, errors |
| B-003 | 10 | `did:key` | memory | off | p50/p95/p99, throughput, errors |
| B-004 | 1 | `did:key` | Redis | off | p50/p95/p99, throughput, errors |
| B-005 | 1 | `did:key` | Redis | on | p50/p95/p99, throughput, errors |
| B-006 | 1 | `did:key` | memory | on | valid versus policy-rejected latency |

## Results

No benchmark runner exists and no benchmark command has been executed. This
workstream is `Not implemented`; do not infer latency, throughput, p50, p95,
p99, or deployment capacity from the persona walkthrough or package tests.

## Reporting Template

No rows are reported because no measurement exists. Add rows only after a real
benchmark run records the command, environment, and raw output under
`.local/drs-assessment/benchmark-raw/`.
