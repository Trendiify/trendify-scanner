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
	IP   string `json:"ip"`
	Port int    `json:"port"`

	TCP       bool `json:"tcp"`
	TLS       bool `json:"tls"`
	WebSocket bool `json:"websocket"`

	TCPTime int64 `json:"tcp_ms"`
	TLSTime int64 `json:"tls_ms"`
	WSTime  int64 `json:"ws_ms"`

	Latency int64 `json:"latency_ms"`

	StatusCode int `json:"status_code"`

	Healthy bool `json:"healthy"`

	Score int64 `json:"score"`

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


	totalStart := time.Now()


	// =====================
	// TCP TEST
	// =====================

	tcpStart := time.Now()

	address := net.JoinHostPort(
		ip,
		fmt.Sprintf("%d", cfg.Port),
	)


	conn, err := net.DialTimeout(
		"tcp",
		address,
		timeout,
	)


	if err != nil {
		result.Error = "tcp: " + err.Error()
		return result
	}


	result.TCP = true
	result.TCPTime = time.Since(tcpStart).Milliseconds()



	// =====================
	// TLS TEST
	// =====================


	serverName := cfg.SNI

	if serverName == "" {
		serverName = cfg.Host
	}

	if serverName == "" {
		serverName = cfg.Address
	}


	tlsStart := time.Now()


	tlsConn := tls.Client(
		conn,
		&tls.Config{
			ServerName: serverName,

			MinVersion: tls.VersionTLS12,

			InsecureSkipVerify: true,
		},
	)


	defer tlsConn.Close()


	err = tlsConn.SetDeadline(
		time.Now().Add(timeout),
	)


	if err != nil {
		result.Error = "deadline: " + err.Error()
		return result
	}


	if err := tlsConn.Handshake(); err != nil {

		result.Error = "tls: " + err.Error()

		return result
	}


	result.TLS = true

	result.TLSTime =
		time.Since(tlsStart).Milliseconds()



	// =====================
	// WEBSOCKET TEST
	// =====================


	wsStart := time.Now()


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



	requestURL := url.URL{
		Scheme: "https",
		Host: host,
		Path: path,
	}



	req := &http.Request{

		Method: http.MethodGet,

		URL: &requestURL,

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
		"dHJlbmRpZnktbmV4dXM=",
	)

	req.Header.Set(
		"User-Agent",
		"Trendify-Nexus-Scanner",
	)



	if err := req.Write(tlsConn); err != nil {

		result.Error =
			"ws write: " + err.Error()

		return result
	}



	reader := bufio.NewReader(
		tlsConn,
	)


	response, err := http.ReadResponse(
		reader,
		req,
	)


	if err != nil {

		result.Error =
			"ws response: " + err.Error()

		return result
	}



	result.StatusCode =
		response.StatusCode



	response.Body.Close()



	result.WSTime =
		time.Since(wsStart).Milliseconds()



if response.StatusCode ==
	http.StatusSwitchingProtocols {


	result.WebSocket = true

	result.Healthy = true

}



result.Latency =
	time.Since(totalStart).Milliseconds()



// =====================
// SCORE
// =====================


result.Score = CalculateScore(result)



if !result.Healthy {

	result.Error =
		fmt.Sprintf(
			"HTTP %d",
			result.StatusCode,
		)

}


return result

}



// Ranking score

func CalculateScore(
	r Result,
) int64 {


	var score int64


	if r.TCP {
		score += 10000
	}


	if r.TLS {
		score += 30000
	}


	if r.WebSocket {
		score += 60000
	}


	if r.StatusCode == 101 {
		score += 30000
	}


	latency := r.Latency


	if latency <= 0 {
		latency = 999999
	}


	score -= latency * 20


	return score

}
