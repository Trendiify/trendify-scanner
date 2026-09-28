package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"trendify-scanner/internal/config"
	"trendify-scanner/internal/engine"
	"trendify-scanner/internal/ipsrc"
	"trendify-scanner/internal/parser"
	"trendify-scanner/internal/result"
)

type Output struct {
	GeneratedAt string `json:"generated_at"`

	Gateway string `json:"gateway"`

	Source string `json:"source"`

	ConfigName string `json:"config_name"`

	TotalScanned int `json:"total_scanned"`

	HealthyCount int `json:"healthy_count"`

	SelectedCount int `json:"selected_count"`

	Template VLESSTemplate `json:"template"`

	Results interface{} `json:"results"`
}

type VLESSTemplate struct {
	Host     string `json:"host"`
	SNI      string `json:"sni"`
	Port     int    `json:"port"`
	Type     string `json:"type"`
	Security string `json:"security"`
	Path     string `json:"path"`
}

func main() {

	fmt.Println()
	fmt.Println("======================================")
	fmt.Println("       TRENDIFY NEXUS SCANNER")
	fmt.Println("======================================")
	fmt.Println()

	cfg := config.Load()

	if cfg.VLESSURL == "" {
		fmt.Println("ERROR:")
		fmt.Println("TRENDIFY_VLESS_URL is not configured.")
		fmt.Println()
		fmt.Println("Set your VLESS configuration first.")
		os.Exit(1)
	}

	fmt.Println("[1/5] Parsing VLESS configuration...")

	vless, err := parser.Parse(
		cfg.VLESSURL,
	)

	if err != nil {
		fmt.Println("VLESS parse error:", err)
		os.Exit(1)
	}

	fmt.Println("      Address :", vless.Address)
	fmt.Println("      Port    :", vless.Port)
	fmt.Println("      Network :", vless.Network)
	fmt.Println("      Security:", vless.Security)
	fmt.Println("      SNI     :", vless.SNI)
	fmt.Println("      Host    :", vless.Host)
	fmt.Println("      Path    :", vless.Path)
	fmt.Println()

	fmt.Printf(
		"[2/5] Generating %d Cloudflare IPs...\n",
		cfg.IPCount,
	)

	ips, err := ipsrc.Generate(
		cfg.IPCount,
	)

	if err != nil {
		fmt.Println("IP generation error:", err)
		os.Exit(1)
	}

	fmt.Printf(
		"      Generated: %d IPs\n",
		len(ips),
	)

	fmt.Println()
	fmt.Println("[3/5] Starting endpoint validation...")

	scanner := engine.New(
		cfg.Workers,
		cfg.Timeout,
	)

	start := time.Now()

	results := scanner.Scan(
		ips,
		vless,
	)

	fmt.Printf(
		"      Scan finished in %s\n",
		time.Since(start).Round(time.Millisecond),
	)

	fmt.Println()
	fmt.Println("[4/5] Ranking healthy endpoints...")

	ranked := result.Rank(results)

	top := result.Top(
		ranked,
		cfg.TopCount,
	)

	fmt.Printf(
		"      Healthy: %d\n",
		len(ranked),
	)

	fmt.Printf(
		"      Selected: %d\n",
		len(top),
	)

	fmt.Println()

	for i, item := range top {

		fmt.Printf(
			"%02d  %-15s  %4d ms  TLS=%v  WS=%v  HTTP=%d\n",
			i+1,
			item.IP,
			item.Latency,
			item.TLS,
			item.WebSocket,
			item.StatusCode,
		)
	}

output := Output{
	GeneratedAt: time.Now().
		UTC().
		Format(time.RFC3339),

	Gateway: vless.Address,

	Source: "cloudflare",

	ConfigName: vless.Name,

	TotalScanned: len(results),

	HealthyCount: len(ranked),

	SelectedCount: len(top),

Template: VLESSTemplate{
	Host:     vless.Host,
	SNI:      vless.SNI,
	Port:     vless.Port,
	Type:     vless.Network,
	Security: vless.Security,
	Path:     vless.Path,
},

	Results: top,
}

	data, err := json.MarshalIndent(
		output,
		"",
		"  ",
	)

	if err != nil {
		fmt.Println("JSON error:", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("[5/5] Writing results...")

	if err := os.WriteFile(
		cfg.OutputFile,
		data,
		0644,
	); err != nil {

		fmt.Println(
			"Write error:",
			err,
		)

		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("======================================")
	fmt.Println("SCAN COMPLETED")
	fmt.Println("======================================")
	fmt.Println()
	fmt.Println(
		"Output:",
		cfg.OutputFile,
	)
	fmt.Println()
}
