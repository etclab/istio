package extauthz

import (
	"istio.io/istio/pkg/monitoring"
)

var (
	BenchmarkOp = monitoring.CreateLabel("benchmark_op")

	benchmarkOpLatency = monitoring.NewDistribution(
		"mazu_benchmark_op_latency_ms",
		"Latency of individual benchmark operations in the inline ext_authz check path, in milliseconds.",
		[]float64{0.1, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500},
	)

	benchmarkTotalLatency = monitoring.NewDistribution(
		"mazu_benchmark_total_latency_ms",
		"Total latency of the inline benchmark ext_authz check path, in milliseconds.",
		[]float64{0.1, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500},
	)

	// tokenReviewAPILatency measures the latency of real Kubernetes TokenReview
	// API calls made from doTokenReview (cache misses only). Recorded on every
	// call regardless of inline benchmark mode.
	tokenReviewAPILatency = monitoring.NewDistribution(
		"mazu_token_review_api_latency_ms",
		"Latency of Kubernetes TokenReview API calls (cache misses only), in milliseconds.",
		[]float64{0.1, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
	)

	// verifyTokenLatency measures the effective latency of verifyToken
	// (including cache hits) to reflect what Check() actually waits on.
	verifyTokenLatency = monitoring.NewDistribution(
		"mazu_verify_token_latency_ms",
		"Effective latency of verifyToken including cache hits, in milliseconds.",
		[]float64{0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500},
	)
)
