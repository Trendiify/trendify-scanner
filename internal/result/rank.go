package result

import (
	"sort"

	"trendify-scanner/internal/prober"
)

func Rank(
	results []prober.Result,
	topCount int,
) []prober.Result {

	if topCount <= 0 {
		topCount = 10
	}

	healthy := make(
		[]prober.Result,
		0,
		len(results),
	)

	for _, r := range results {
		if !r.Healthy {
			continue
		}

		healthy = append(
			healthy,
			r,
		)
	}

	sort.Slice(
		healthy,
		func(i, j int) bool {
			return score(healthy[i]) > score(healthy[j])
		},
	)

	if len(healthy) > topCount {
		healthy = healthy[:topCount]
	}

	return healthy
}

func score(r prober.Result) float64 {
	if !r.Healthy {
		return 0
	}

	latency := float64(r.Latency)

	if latency <= 0 {
		latency = 1
	}

	score := 100000.0 / latency

	if r.TCP {
		score += 100
	}

	if r.TLS {
		score += 200
	}

	if r.WebSocket {
		score += 500
	}

	return score
}
