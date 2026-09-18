# Mazu RBE handshake performance: what was measured, and what actually fixed it

Investigation log for the Mazu (`st5-AttUpd`) throughput ceiling at 2x Bookinfo
replicas with connection reuse disabled. Companion to the implementation spec in
`envoy/source/extensions/transport_sockets/tls/cert_validator/rbe/README.md`,
which this **revises on several points** — see [What this revises](#what-this-revises).

**Headline:** Mazu went from 232.6 rps to **372.8 rps** at 2x, against an Istio
control of 374.9. The Envoy-side cache (that spec's "Change 1") accounted for
9 points of that. The remaining 47 came from a one-constant change in the
*agent*: `tokenCacheTTL` 2s → 5s. The binding constraint was never Envoy's
threading — it was client-go's default 5 QPS rate limiter throttling the
agent's TokenReview calls.

---

## Results

All at 2x replicas, `CONN_REUSE=0` (`maxRequestsPerConnection=1`), Envoy
`concurrency=1`, 120s per step.

### Achieved throughput (rps)

| target | original | + Envoy cache | + agent TTL | Istio control |
| --- | --- | --- | --- | --- |
| 100 | 95.3 | 95.1 | 95.4 | 95.4 |
| 400 | 232.6 | 253.9 | **372.8** | 374.9 |
| 800 | 230.4 | 249.2 | **373.1** | 376.1 |

### End-to-end latency

| | p50 @100 | p99 @100 | p50 @400 | p99 @400 |
| --- | --- | --- | --- | --- |
| original | 443 ms | 5.95 s | 28.2 s | 55 s |
| + Envoy cache | 451 ms | 6.70 s | 25.3 s | 49.7 s |
| **+ agent TTL** | **49.4 ms** | **95.0 ms** | 4.01 s | 15.1 s |
| Istio control | 48.6 ms | 87.4 ms | 3.17 s | 12.9 s |

At 100 rps Mazu is now within 9% of Istio on p99. At the 400 target both arms
are past capacity, and Mazu's latency there is ~25% worse than Istio's despite
matching throughput.

### Envoy / cgroup diagnostics, productpage sidecar @400

| metric | original | + Envoy cache | + agent TTL | Istio |
| --- | --- | --- | --- | --- |
| peak proxy threads | 98 | 33 | 29 | 10 |
| `upstream_cx_connect_ms` p99 | 1,006 ms | 1,010 ms | **82.4 ms** | 70.1 ms |
| CFS throttled periods | 1,576 | 419 | 727 | 308 |
| TokenReviews / step | 4,098 | 4,002 | **1,203** | 21 |
| handshakes / step | 147,936 | 161,150 | 235,607 | 236,973 |
| CPU per request (mcore-s) | 5.81 | 4.26 | **4.03** | 3.80 |
| `watchdog_miss` | 0 | 0 | 0 | 0 |

Throttled periods rise from 419 to 727 with the TTL fix, but that is a
consequence of doing 47% more work; CPU *per request* falls. Handshake volume
now matches Istio's, i.e. the mesh is no longer losing connections to failed
validations.

### Agent ext_authz Check latency, productpage (the fan-out pod)

| | Check : TokenReview | TokenReviews/s | p50 | p90 | p99 |
| --- | --- | --- | --- | --- | --- |
| `tokenCacheTTL` = 2s | 1.0 | 5.1 | 553 ms | 763 ms | 1,969 ms |
| `tokenCacheTTL` = 5s | 4.6 | 1.7 | **0.10 ms** | 3.08 ms | 8.10 ms |

---

## How it was diagnosed

### 1. Change 1 works, and it is not enough

The thread-local cache + single-flight in `rbe_validator.cc` did exactly what
the spec predicted of it, and none of what the spec predicted it would *buy*:

- peak proxy threads 98–104 → 33–36, i.e. down to the idle floor. Per-handshake
  thread spawning is gone. Envoy→agent RPCs fell ~99% (1,343 handshakes/s →
  12.7 Checks/s).
- CFS throttling 1,576 → 419 periods, comparable to Istio's 330.
- CPU per request −27%, from 1.53x Istio's down to 1.12x.
- **Throughput +9%.**

The tell was that Mazu now burned *less total CPU than Istio* (1.08 vs 1.42
cores) while delivering *less throughput*. It was not CPU-bound. It was blocked.

### 2. The connect-time distribution pointed at the agent

`upstream_cx_connect_ms` on productpage after Change 1: p50 14 ms (cache hit),
but p75 284 ms, p90 513 ms, p99 1,010 ms. A fast median with a plateau near
500 ms–1 s means most handshakes are served from cache and a minority block on
something taking roughly half a second. With single-flight and a 1s validator
TTL, the fraction of slow connections approximates `agentLatency / TTL` — which
put the agent's Check at ~500 ms, not the ~5 ms the spec assumed.

### 3. Measuring the agent directly

The agent already logs `[dev] Check: total duration=` per Check at default info
level in the istio-proxy container. Captured live off four sidecars during a
400 rps step:

| sidecar | Checks/s | p50 | p90 | p99 |
| --- | --- | --- | --- | --- |
| details (×2) | 1.2 | **2.9 ms** | 3.3 ms | 8.5 ms |
| productpage (×2) | 5.1 | **553 ms** | 763 ms | ~1.8 s |

Same binary, 190x apart. `checkWithToken` accounted for essentially all of
`Check` (476.989 vs 476.997 ms), ruling out gRPC transport. The agent then
named the cause itself:

```
Waited for 1.082474186s due to client-side throttling, not priority and
fairness, request: POST:.../apis/authentication.k8s.io/v1/tokenreviews
```

---

## Root cause

`security/pkg/nodeagent/extauthz/server.go:600-612` (`NewExtAuthzServer`) builds
the Kubernetes client without setting QPS/Burst:

```go
config, err := rest.InClusterConfig()
clientset, err := kubernetes.NewForConfig(config)   // QPS/Burst never set
```

`rest.InClusterConfig()` returns `QPS: 0, Burst: 0`, so client-go substitutes
its own defaults — `DefaultQPS = 5.0`, `DefaultBurst = 10`
(`k8s.io/client-go@v0.31.1 rest/config.go:44-45`, applied at 354-359). Every
`TokenReviews().Create()` at `server.go:362` passes through a 5 QPS token
bucket. **This is the absence of configuration, not a limiter anyone added.**

The agent compounded it by issuing **one TokenReview per Check** (exactly 1:1).
`tokenCacheTTL` was 2s while the per-key Check rate was ~0.5/s, so entries
expired before they were ever reused and the cache and singleflight at
`server.go:282-336` never paid off. productpage reached 5.1 TokenReviews/s,
saturated the bucket, and queued. details ran at 1.2/s, stayed under, and was
fast. That threshold is the entire difference.

It was never apiserver-side, which is why earlier work ruled it out: APF
in-queue was 0 and TokenReview p99 was ~5 ms *measured at the apiserver*. The
queue was in the client.

## The fix

`tokenCacheTTL` 2s → 5s (`server.go:44-48`), one constant. Raising the TTL cuts
TokenReviews per Check from 1:1 to 4.6:1, dropping the rate to 1.7/s —
comfortably under the bucket — and the queue disappears. Check latency falls
from 553 ms to 100 µs.

The Envoy binary layer was **byte-identical** between the before and after
images, so this is a clean single-variable result.

### Why not raise QPS/Burst instead

It would also work, and it is the more dangerous lever: it lifts the apiserver
ceiling for *every sidecar simultaneously*. At 2x there is headroom (APF
in-queue 0, TokenReview p99 ~5 ms), but at 16x that is 96 sidecars each
permitted 5x more traffic. The TTL keeps the blast radius inside the agent.

**The cost of the TTL change is revocation freshness: now bounded by 5s rather
than 2s.** That is the one thing to check against the threat model.

---

## What this revises

Corrections to
`envoy/.../cert_validator/rbe/README.md`, all measured:

| that spec says | measurement says |
| --- | --- |
| "the agent's verification work — ruled out" | It was the whole thing. ~550 ms per Check on the fan-out pod. |
| thread-per-handshake is "the measured 1.6x throughput gap" | Removing it entirely bought 9%. Real mechanism, not the binding constraint. |
| the 500–600 ms connect plateau is CFS quota queueing | Throttling fell 3.8x while the plateau did not move. It was the rate-limited Check. |
| the 5s deadline "is why the 2x/100rps p99 was 5.95 s" | Correct that validations were timing out, wrong about why. They timed out *because* Checks took ~550 ms under rate limiting. With the TTL fix the same 5s deadline yields a 95 ms p99. |
| set the deadline "in the tens of milliseconds" | **Do not.** See below. |
| Change 2 (async client) closes the gap | No throughput case at 2x. Correctness only. |

### Traps — do not do these

1. **Do not shorten the 5s validation deadline** on the strength of that spec.
   It was written assuming ~5 ms Checks. A 50 ms timeout while Check p50 was
   553 ms would have failed nearly every handshake. It is now fine as-is.
2. **Do not rename the strategy to benchmark a new build.** `st5-AttUpd` is
   hardcoded in five places and gates the attestation ConfigMap, the TPM
   operator overlay, the TPM device plugin and the TPM manifests. Passing
   `STRATEGIES="my-new-build"` silently yields a mesh with **attestation
   disabled and no TPM** — which looks like a spectacular win. Use `MAZU_TAG`
   (added for this work) to move only the image tag.
3. **Do not raise Envoy's log level to info to capture agent timings.**
   `rbe_validator.cc` has six per-handshake `ENVOY_LOG_MISC(info, ...)` calls
   that would perturb the run. The agent's own lines are already at info in the
   istio-proxy container log; capture those.
4. **A docker tag is not provenance.** Three different builds were pushed to
   `proxyv2:mazu-async` during this work. Record the digest — see below.

---

## Open

- **4x–16x is unverified with this fix.** The rate-limit mechanism predicts that
  collapse too: Envoy's 1s validator TTL makes Check rate scale with the number
  of distinct peers, so a 4x fleet is ~20 TokenReviews/s against a 5 QPS limit,
  waits grow past the 5s validation deadline, handshakes fail, and peers
  reconnect into a storm. That matches the 65 rps observed at 4x. Confirm by
  re-running 4x and counting `client-side throttling` lines.
- **Change 2 (`Grpc::AsyncClient`)** is now purely a correctness item. The one
  worth doing is cancellation on connection teardown — the callback is held in a
  map and may be invoked against a destroyed socket. The `join()` from the
  dispatcher and the recycled-`pthread_t` map key are also real but currently
  benign (`watchdog_miss` was 0 in every run).
- **`CONN_REUSE=1` was never measured** for any of this. Every number here is
  the worst case, where each request pays a fresh handshake.
- **Istio control drift:** the control arm reproduced to 0.6% at 100 rps between
  09-07 and 09-08, but was 4% higher at 400 (359.3 → 374.9). The TTL=5s run had
  no simultaneous control; its Istio comparison is against the run ~2h earlier
  on the same fleet.

---

## Reproducing

```bash
# 2x, both arms, Envoy diagnostics, widened stats
MAZU_TAG=mazu-async ./run-2x-envoy-diag.sh
python3 parse_envoy_diag.py results/envoy-diag-<date>

# agent-side Check latency: capture live during a load step
kubectl logs -f <pod> -n default -c istio-proxy | grep -E \
  "Check: total duration|singleflight executed TokenReview|client-side throttling"
```

`MAZU_TAG` overrides only `docker.io/atosh502/{pilot,proxyv2}:<tag>`, leaving
the strategy gating intact. It is recorded in the run banner and `scales.txt`.

Three collection traps, all still live:

1. `sidecar.istio.io/statsInclusionPrefixes` is an Envoy `stats_matcher`
   **inclusion_list** — excluded stats are never instantiated, so `server.*` and
   `ssl.*` do not exist unless the annotation is widened. `run-2x-envoy-diag.sh`
   does this via `STATS_PREFIXES`.
2. Watchdog counters are per-thread: `server.worker_0.watchdog_miss`, not
   `server.watchdog_miss`. The latter matches nothing, which reads as "zero".
3. `/stats?usedonly` omits never-incremented counters, making "zero" and "does
   not exist" indistinguishable. Use plain `/stats`.

---

## Provenance

Runs, all 2x / `CONN_REUSE=0` / 120s steps:

| directory | arms | image (proxyv2 digest) |
| --- | --- | --- |
| `results/envoy-diag-09-07-26_114514` | mazu + istio | `st5-AttUpd` (pre-Change-1) |
| `results/envoy-diag-mazu-async-09-08-26_134137` | mazu + istio | `mazu-async` @`sha256:479420bc…` (Change 1, TTL=2s) |
| `results/agent-latency-09-08-26_143322` | mazu | same as above |
| `results/agent-ttl5s-09-08-26_152549` | mazu | `mazu-async` @`sha256:df54d6cb…` (Change 1 + TTL=5s) |

`pilot` was byte-identical across all of these — the ext_authz agent ships in
`pilot-agent`, inside **proxyv2**, not in the pilot image.

Manifests were byte-identical between the 09-07 and 09-08 runs apart from `rbe`
being added to `statsInclusionPrefixes`; pod shape, replica counts and CPU
limits unchanged, `concurrency=1` confirmed from `/server_info` in both.
