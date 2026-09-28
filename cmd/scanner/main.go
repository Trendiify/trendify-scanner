package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"trendify-scanner/internal/config"
	"trendify-scanner/internal/engine"
	"trendify-scanner/internal/ipsrc"
	"trendify-scanner/internal/parser"
	"trendify-scanner/internal/result"
)

func main() {
	cfg := config.Load()

	if cfg.VLESSURL == "" {
		log.Fatal(
			"TRENDIFY_VLESS_URL is not set",
		)
	}

	fmt.Println("========================================")
	fmt.Println("       Trendify Nexus Scanner")
	fmt.Println("========================================")
	fmt.Println()

	fmt.Println("[1/5] Parsing VLESS configuration...")

	vless, err := parser.Parse(cfg.VLESSURL)
	if err != nil {
		log.Fatalf(
			"VLESS configuration error: %v",
			err,
		)
	}

	fmt.Printf(
		"Server: %s:%d\n",
		vless.Address,
		vless.Port,
	)

	fmt.Printf(
		"SNI: %s\n",
		vless.SNI,
	)

	fmt.Printf(
		"Host: %s\n",
		vless.Host,
	)

	fmt.Printf(
		"Path: %s\n",
		vless.Path,
	)

	fmt.Printf(
		"Network: %s\n",
		vless.Network,
	)

	fmt.Printf(
		"Security: %s\n",
		vless.Security,
	)

	fmt.Println()

	fmt.Println("[2/5] Loading Cloudflare IPv4 ranges...")

	source, err := ipsrc.LoadCloudflareIPv4()
	if err != nil {
		log.Fatalf(
			"Cloudflare IP source error: %v",
			err,
		)
	}

	fmt.Printf(
		"Cloudflare ranges: %d\n",
		len(source.CIDRs),
	)

	fmt.Println()

	fmt.Printf(
		"[3/5] Generating %d candidate IPs...\n",
		cfg.IPCount,
	)

	ips, err := source.Generate(cfg.IPCount)
	if err != nil {
		log.Fatalf(
			"IP generation error: %v",
			err,
		)
	}

	fmt.Printf(
		"Candidate IPs: %d\n",
		len(ips),
	)

	fmt.Println()

	fmt.Printf(
		"[4/5] Scanning with %d workers...\n",
		cfg.Workers,
	)

	start := time.Now()

	scanner := engine.New(
		cfg.Workers,
		cfg.Timeout,
	)

	results := scanner.Scan(
		ips,
		vless,
	)

	elapsed := time.Since(start)

	healthyCount := 0

	for _, r := range results {
		if r.Healthy {
			healthyCount++
		}
	}

	fmt.Printf(
		"Scan completed in %s\n",
		elapsed.Round(time.Millisecond),
	)

	fmt.Printf(
		"Healthy endpoints: %d\n",
		healthyCount,
	)

	fmt.Println()

	fmt.Printf(
		"[5/5] Selecting Top %d endpoints...\n",
		cfg.TopCount,
	)

	top := result.Rank(
		results,
		cfg.TopCount,
	)

	fmt.Printf(
		"Selected endpoints: %d\n",
		len(top),
	)

	fmt.Println()

	for i, r := range top {
		fmt.Printf(
			"#%d  %s:%d  latency=%dms  status=%d\n",
			i+1,
			r.IP,
			r.Port,
			r.Latency,
			r.StatusCode,
		)
	}

	if err := writeResults(
		cfg.OutputFile,
		top,
	); err != nil {
		log.Fatalf(
			"write results: %v",
			err,
		)
	}

	fmt.Println()

	fmt.Printf(
		"Results written to: %s\n",
		cfg.OutputFile,
	)

	fmt.Println("Scanner finished successfully.")
}

func writeResults(
	filename string,
	data interface{},
) error {

	jsonData, err := json.MarshalIndent(
		data,
		"",
		"  ",
	)

	if err != nil {
		return err
	}

	jsonData = append(
		jsonData,
		'\n',
	)

	return os.WriteFile(
		filename,
		jsonData,
		0644,
	)
}
