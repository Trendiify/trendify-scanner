package prober

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"trendify-scanner/internal/parser"
)

type Result struct {
	IP string `json:"ip"`

	Port int `json:"port"`

	Latency int64 `json:"latency_ms"`

	TCP bool `json:"tcp"`

	TLS bool `json:"tls"`

	WebSocket bool `json:"websocket"`

	Healthy bool `json:"healthy"`

	StatusCode int `json:"status_code"`

	Error string `json:"error,omitempty"`
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
		result.Error = fmt.Sprintf(
			"tcp: %v",
			err,
		)

		return result
	}

	result.TCP = true

	if cfg.Security != "tls" &&
		cfg.Security != "reality" {

		result.Error = "unsupported security for TLS probe"

		_ = conn.Close()

		return result
	}

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

	_ = tlsConn.SetDeadline(
		time.Now().Add(timeout),
	)

	if err := tlsConn.Handshake(); err != nil {
		result.Error = fmt.Sprintf(
			"tls: %v",
			err,
		)

		_ = tlsConn.Close()

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

	req := &http.Request{
		Method: http.MethodGet,

		URL: &urlValue{
			path: path,
		},

		Host: host,

		Proto: "HTTP/1.1",

		ProtoMajor: 1,
		ProtoMinor: 1,

		Header: make(http.Header),
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
		result.Error = fmt.Sprintf(
			"websocket request: %v",
			err,
		)

		_ = tlsConn.Close()

		return result
	}

	reader := bufio.NewReader(tlsConn)

	response, err := http.ReadResponse(
		reader,
		req,
	)

	if err != nil {
		result.Error = fmt.Sprintf(
			"websocket response: %v",
			err,
		)

		_ = tlsConn.Close()

		return result
	}

	result.StatusCode = response.StatusCode

	_ = response.Body.Close()
	_ = tlsConn.Close()

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

type urlValue struct {
	path string
}

func (u *urlValue) String() string {
	if u == nil || u.path == "" {
		return "/"
	}

	return u.path
}
