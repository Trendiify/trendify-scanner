package prober

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trendify-scanner/internal/parser"
)

type Result struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Latency    int64  `json:"latency_ms"`
	TCP        bool   `json:"tcp"`
	TLS        bool   `json:"tls"`
	WebSocket  bool   `json:"websocket"`
	Healthy    bool   `json:"healthy"`
	StatusCode int    `json:"status_code"`
	Error      string `json:"error,omitempty"`
}

func Probe(
	ip string,
	cfg *parser.VLESSConfig,
	timeout time.Duration,
) Result {
	result := Result{
		IP:   ip,
		Port: cfg.Port,
	}

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	start := time.Now()

	address := net.JoinHostPort(
		ip,
		fmt.Sprintf("%d", cfg.Port),
	)

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := dialer.Dial(
		"tcp",
		address,
	)

	if err != nil {
		result.Error = "tcp: " + err.Error()
		return result
	}

	result.TCP = true

	serverName := cfg.SNI

	if serverName == "" {
		serverName = cfg.Host
	}

	if serverName == "" {
		serverName = cfg.Address
	}

	tlsConn := tls.Client(
		conn,
		&tls.Config{
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		},
	)

	defer tlsConn.Close()

	if err := tlsConn.SetDeadline(
		time.Now().Add(timeout),
	); err != nil {
		result.Error = "tls deadline: " + err.Error()
		return result
	}

	if err := tlsConn.Handshake(); err != nil {
		result.Error = "tls: " + err.Error()
		return result
	}

	result.TLS = true

	path := cfg.Path

	if path == "" {
		path = "/"
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	host := cfg.Host

	if host == "" {
		host = cfg.SNI
	}

	if host == "" {
		host = cfg.Address
	}

	requestURL := urlForWS(path)

	req := &http.Request{
		Method:     http.MethodGet,
		URL:        &requestURL,
		Host:       host,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}

	req.Header.Set(
		"Host",
		host,
	)

	req.Header.Set(
		"Connection",
		"Upgrade",
	)

	req.Header.Set(
		"Upgrade",
		"websocket",
	)

	req.Header.Set(
		"Sec-WebSocket-Version",
		"13",
	)

	req.Header.Set(
		"Sec-WebSocket-Key",
		"dHJlbmRpZnktc2Nhbm5lcg==",
	)

	req.Header.Set(
		"User-Agent",
		"Trendify-Nexus-Scanner/1.0",
	)

	if err := req.Write(tlsConn); err != nil {
		result.Error = "websocket request: " + err.Error()
		return result
	}

	reader := bufio.NewReader(tlsConn)

	response, err := http.ReadResponse(
		reader,
		req,
	)

	if err != nil {
		result.Error = "websocket response: " + err.Error()
		return result
	}

	defer response.Body.Close()

	result.StatusCode = response.StatusCode
	result.Latency = time.Since(start).Milliseconds()

	if response.StatusCode == http.StatusSwitchingProtocols {
		result.WebSocket = true
		result.Healthy = true
		return result
	}

	result.Error = fmt.Sprintf(
		"websocket returned HTTP %d",
		response.StatusCode,
	)

	return result
}

func urlForWS(path string) url.URL {
	return url.URL{
		Scheme: "https",
		Path:   path,
	}
}
