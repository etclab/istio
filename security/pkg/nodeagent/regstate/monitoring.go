package regstate

import (
	"istio.io/istio/pkg/monitoring"
)

var (
	// LazyPhase labels which part of a deferred validation a sample belongs to:
	// materialize, rbe_proof or challenge_response.
	LazyPhase = monitoring.CreateLabel("lazy_phase")

	// lazyEagerLatency is the per-registration cost on the stream path under
	// the lazy accumulator — attestation, one proto unmarshal, one G1
	// decompression and an append. Compare against the eager path's
	// per-registration cost to see what deferral bought.
	lazyEagerLatency = monitoring.NewDistribution(
		"mazu_lazy_eager_latency_ms",
		"Per-registration cost on the KC stream path under the lazy registration accumulator, in milliseconds.",
		[]float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250},
	)

	// lazyValidateLatency breaks a first-contact validation into its phases.
	lazyValidateLatency = monitoring.NewDistribution(
		"mazu_lazy_validate_latency_ms",
		"Latency of each phase of a deferred first-contact peer validation, in milliseconds.",
		[]float64{0.1, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000},
	)

	// lazyValidateTotalLatency is the whole deferred validation, which is what
	// the first connection to a peer waits on behind Envoy's validator timeout.
	lazyValidateTotalLatency = monitoring.NewDistribution(
		"mazu_lazy_validate_total_latency_ms",
		"Total latency of a deferred first-contact peer validation, in milliseconds.",
		[]float64{0.1, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500},
	)
)
