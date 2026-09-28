package pool

import (
	"encoding/json"
	"os"
	"time"

	"trendify-scanner/internal/prober"
)

type IPEntry struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Latency   int64  `json:"latency_ms"`
	Healthy   bool   `json:"healthy"`
	WebSocket bool   `json:"websocket"`
	TLS       bool   `json:"tls"`
}

type Pool struct {
	Gateway   string    `json:"gateway"`
	UpdatedAt string    `json:"updated_at"`
	Count     int       `json:"count"`
	IPs       []IPEntry `json:"ips"`
}

func Build(
	gateway string,
	results []prober.Result,
	count int,
	output string,
) error {

	pool := Pool{
		Gateway: gateway,
		UpdatedAt: time.Now().
			UTC().
			Format(time.RFC3339),
	}

	for _, item := range results {

		if !item.Healthy {
			continue
		}

		pool.IPs = append(
			pool.IPs,
			IPEntry{
				IP:        item.IP,
				Port:      item.Port,
				Latency:   item.Latency,
				Healthy:   item.Healthy,
				WebSocket: item.WebSocket,
				TLS:       item.TLS,
			},
		)

		if len(pool.IPs) >= count {
			break
		}
	}

	pool.Count = len(pool.IPs)

	data, err := json.MarshalIndent(
		pool,
		"",
		"  ",
	)

	if err != nil {
		return err
	}

	return os.WriteFile(
		output,
		data,
		0644,
	)
}
