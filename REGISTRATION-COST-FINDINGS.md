# Mazu registration processing cost: 71 ms per peer, and where it actually goes

Microbenchmark of `regstate.ProcessRegistration` — the work every agent does for
every peer registration delivered by the KC stream. Companion to
[`RBE-PERF-FINDINGS.md`](RBE-PERF-FINDINGS.md), which covers the *per-request*
handshake path; this covers a **different axis**: cost that scales with peer
count and replica churn, not with rps.

**Headline:** each streamed registration costs **71 ms of single-core CPU**, and
**59% of it is `xi` decompression** (step 2) — not the pairing-based checks.
Deferring the pairings, the obvious optimization, addresses 40% of the cost.
Restructuring how openings are materialized addresses 59% and is the larger win.

**Status:** microbenchmark only. Nothing here has been observed in a cluster.
See [Open](#open).

---

## Results

`go test ./security/pkg/nodeagent/regstate/ -run XXX -bench . -benchtime 20x -benchmem`

```
BenchmarkProcessRegistration/logs=off     71.1 ms/op   240 KB/op   2449 allocs/op
BenchmarkProcessRegistration/logs=on      73.5 ms/op   243 KB/op   2471 allocs/op
BenchmarkStep2UnmarshalAndDecompress      42.0 ms/op   109 KB/op   1293 allocs/op
BenchmarkStep3ApplyRegistration            0.55 ms/op  117 KB/op   1036 allocs/op
BenchmarkStep4VerifyMembershipOrdered      6.18 ms/op    1.7 KB/op     3 allocs/op
BenchmarkStep5ValidatePodChallenge        22.4 ms/op     9.2 KB/op   106 allocs/op
```

### Breakdown by step

Steps numbered as they appear in `security/pkg/nodeagent/regstate/verify.go`.

| step | what it does | cost | share | deferrable? |
| --- | --- | --- | --- | --- |
| 1. counter attestation | TPM signature verify | **not measured** | — | kept eager by design |
| 2. unmarshal + decompress | 256 proto unmarshals + 256 G1 decompressions (`verify.go:57-73`) | 42.0 ms | **59%** | only by restructuring step 3 |
| 3. `ApplyRegistration` | 256 G1 adds + opening appends (`store.go:147-179`) | 0.55 ms | 0.8% | no — accumulator, order-dependent |
| 3b. `ApplyOrderedCommitment` | 1 G1 add (`store.go:209-231`) | in step 3 noise | ~0% | no |
| 4. `VerifyMembershipOrdered` | 3 pairings (`rbe/verify.go:7-20`) | 6.18 ms | 9% | yes, **with a snapshot** — see trap below |
| 5. `ValidatePodChallenge` | ~7 pairings + encrypt/decrypt (`verify.go:144-184`) | 22.4 ms | 31% | yes, cleanly |
| | **total** | **71.1 ms** | | |

Parts sum to 71.15 ms against a measured total of 71.1 ms, so nothing
significant is unaccounted for.

### Challenge cost does not grow with block depth

`BenchmarkStep5ChallengeByBlockDepth`, all peers forced into one block:

| peers already registered in the block | cost |
| --- | --- |
| 1 | 22.3 ms |
| 8 | 22.8 ms |
| 32 | 22.4 ms |
| 64 | 22.6 ms |

Flat. Total eager cost is therefore **strictly linear in peer count**, with no
compounding term — the per-peer saving from deferral is a constant.

---

## What this costs at scale

Arithmetic from the measured per-op cost, **not an observed cluster number**:

| fleet | peers per agent | eager CPU per agent, per full scale-out |
| --- | --- | --- |
| 10 services x 3 replicas | 30 | 2.1 s |
| 10 services x 15 replicas | 150 | 10.7 s |

On a 1-core proxy budget against a ~15 s HPA metric window, 10.7 s of pinned CPU
is close to a guaranteed scale trigger — and every agent pays it for every peer,
so the work is **O(N²) across the mesh**. A scale-up event therefore feeds
itself: more replicas produce more registrations, which produce more CPU, which
produces more replicas.

For contrast, the steady-state request path after the fixes in
`RBE-PERF-FINDINGS.md` is 4.03 vs 3.80 mcore-s per request — 6% over Istio.
These are unrelated problems and only one of them has been measured in a
cluster.

---

## Implications for the deferral design

### Deferring steps 4+5 saves 40%

28.6 ms of 71.1 ms. Real, but it leaves the largest single item untouched, and
it moves pairing crypto onto the connection path — behind Envoy's 250 ms
validator timeout, which fails closed and does **not** cache the failure
(`rbe_validator.h:96`, `rbe_validator.cc:202-204`). Scale-up is exactly the
worst case for that: N new pods first-contacting M peers at once.

### The trap in deferring step 4

`VerifyMembershipOrdered` checks the proof against `orderedCommitments[k]`, and
`ApplyOrderedCommitment` **mutates that G1 in place** (`store.go:225-227`). A
proof is only valid against the commitment as it stood at its own insertion
point. Deferred to first contact, every later registration in block k has folded
into `com[k]` and the check fails — for a legitimate peer.

Fixable by snapshotting `com[k]` per registration (48 bytes). Missed, it
produces sporadic false denials that look like a crypto bug.

### Step 5 defers cleanly

No ordering dependency: it reads current commitments and current openings.
Combined with the flat-depth result, deferral saves a predictable 22.4 ms per
uncontacted peer.

### The larger win: lazy opening materialization

Step 2's 42 ms exists only to feed step 3's opening loop. But that loop computes

```
opening_j = Σᵢ xiᵢ[jBar]        (store.go:174)
```

— a **group sum, order-independent**. Registrations do not have to be
materialized when they arrive. Storing `xi` as raw bytes and decompressing
`xi[jBar]` only for peers actually contacted reduces eager cost to one
decompression plus one add.

Derived floor, not measured: one G1 decompression is ~164 µs (42.0 ms / 256), so
eager cost would land near **0.2 ms instead of 71 ms — roughly 300×**, with the
lazy remainder paid only on edges of the service graph that actually carry
traffic.

This does not change the security model at all, which the first-contact
deferral does.

### Suggested sequencing

1. Lazy opening materialization — biggest win, no security-model change.
2. Background bounded-rate verifier for steps 4-5 — flattens the burst (which is
   what the HPA reacts to) without putting crypto on the connection path.
3. First-contact deferral — only if something still shows up after 1 and 2.

---

## Secondary findings

- **The opening history is written and never read.** `store.go:176` appends one
  G1 per registration per block member, but `rbe/user.go:66` reads only
  `openings[len(openings)-1]` and `Update` just assigns the slice
  (`rbe/user.go:95-98`). A running sum replaces the slice and drops memory from
  O(BlockSize x registrations) to O(BlockSize).
- **Logging costs 2.4 ms per registration** (3%) — ~6 `Infof` calls at ~400 µs
  each. Visible but not the story here, unlike on the per-request path.
- **`DoVerifyCounter` reads the TPM public key from disk on every call**
  (`security/pkg/trinc/util/util.go:133`). One file read per registration.
- **240 KB and 2449 allocations per registration**, most of it in step 2's
  short-lived G1s — GC pressure on a 1-core sidecar.

---

## Open

- **Step 1 (counter attestation) is unmeasured.** It needs a TPM public key at
  `TPM_PK_PATH` and a real `trinc.CounterAttestation`, so the benchmark passes a
  nil attestation and `ProcessRegistration` skips it (`verify.go:35`). It is the
  one step the deferral proposal keeps eager, so its cost matters. Measure on a
  TPM-equipped node.
- **Nothing here has been observed in a cluster.** The 71 ms is a workstation
  microbenchmark; the 10.7 s figure is arithmetic on top of it. Confirm against
  a real scale-out before building anything.
- **Arrival pacing is unknown.** Whether the KC stream delivers registrations in
  a burst or spread out decides whether 10.7 s of work lands inside one HPA
  window or across several. This is what determines if the background-verifier
  fix alone is sufficient.
- **The ~300× lazy-openings figure is derived, not measured.** It assumes the
  per-point decompression cost divides cleanly out of step 2; the proto
  unmarshal share of that 42 ms was not separated.
- **Workstation CPU, not pod CPU.** Xeon Gold 5512U, single-goroutine. Sidecar
  cores may differ materially.
- **`CONN_REUSE` is irrelevant here** — unlike every number in
  `RBE-PERF-FINDINGS.md`, this cost is per *registration*, not per handshake.

---

## Reproducing

```bash
# full breakdown, production parameters
go test ./security/pkg/nodeagent/regstate/ -run XXX -bench . -benchtime 20x -benchmem

# fixture validity — asserts every step actually runs and passes
go test ./security/pkg/nodeagent/regstate/ -run TestBenchFixtureIsValid -v

# fast iteration at smaller parameters (BlockSize=32)
MAZU_BENCH_MAX_USERS=1024 go test ./security/pkg/nodeagent/regstate/ -run XXX -bench .
```

Four collection traps:

1. **Use `-benchtime 20x`, not the default.** These ops are tens of
   milliseconds; the default 1 s target spends minutes replaying fixtures.
2. **`TestBenchFixtureIsValid` is load-bearing.** It asserts `ProofVerified` and
   `PodValid` on every synthetic registration. Without it a malformed fixture
   makes `ProcessRegistration` bail early and the benchmark silently measures a
   fraction of the work.
3. **Istio's logger writes to stdout**, interleaving with `go test`'s benchmark
   lines. Redirect to a file and grep for `ns/op` rather than `^Benchmark`.
4. **`rbe.KeyCurator` is deliberately not used** to build fixtures — its
   `RegisterUser` calls `CheckXiConsistency`, which costs BlockSize pairings per
   registration (`rbe/publicparams.go:120-136`) and would dominate setup. Proofs
   are accumulated directly instead, mirroring `ApplyRegistration`.

---

## Provenance

| | |
| --- | --- |
| benchmark | `security/pkg/nodeagent/regstate/verify_bench_test.go` |
| commit | `34f00d88a4` (branch `design-v4-no-threads-envoy`) |
| date | 2026-09-15 |
| machine | INTEL(R) XEON(R) GOLD 5512U, 56 cores; single-goroutine measurement |
| toolchain | go1.24.5 linux/amd64 |
| RBE params | MaxUsers 65536 → BlockSize 256, NumBlocks 256 (`rbe/publicparams.go:84-85`), matching the deployed public params |
| peers per fixture | 32 (64 for the block-depth benchmark) |

Fixtures are generated in-process rather than loaded from the deployed PP file,
so the CRS differs per run. Costs do not depend on the values, only on the
parameter sizes.
