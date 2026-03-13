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
)
