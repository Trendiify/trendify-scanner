package result

import (
	"sort"

	"trendify-scanner/internal/prober"
)

func Healthy(
	input []prober.Result,
) []prober.Result {

	output := make(
		[]prober.Result,
		0,
		len(input),
	)

	for _, item := range input {
		if !item.Healthy {
			continue
		}

		output = append(
			output,
			item,
		)
	}

	return output
}

func Rank(
	input []prober.Result,
) []prober.Result {

	output := Healthy(input)

	sort.Slice(
		output,
		func(i, j int) bool {
			return score(output[i]) >
				score(output[j])
		},
	)

	return output
}

func Top(
	input []prober.Result,
	count int,
) []prober.Result {

	if count <= 0 {
		return []prober.Result{}
	}

	if len(input) <= count {
		return input
	}

	return input[:count]
}

func score(item prober.Result) int64 {
	var score int64

	if item.Healthy {
		score += 100000
	}

	if item.WebSocket {
		score += 50000
	}

	if item.TLS {
		score += 25000
	}

	if item.StatusCode == 101 {
		score += 25000
	}

	latency := item.Latency

	if latency <= 0 {
		latency = 999999
	}

	score -= latency * 10

	return score
}
