package ipsrc

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const cloudflareIPv4URL = "https://www.cloudflare.com/ips-v4"

type Source struct {
	CIDRs []string
}

func LoadCloudflareIPv4() (*Source, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequest(
		http.MethodGet,
		cloudflareIPv4URL,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("create Cloudflare IP request: %w", err)
	}

	req.Header.Set(
		"User-Agent",
		"Trendify-Nexus-Scanner/1.0",
	)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download Cloudflare IPv4 ranges: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"Cloudflare IPv4 request returned HTTP %d",
			resp.StatusCode,
		)
	}

	var data strings.Builder

	buf := make([]byte, 8192)

	for {
		n, readErr := resp.Body.Read(buf)

		if n > 0 {
			data.Write(buf[:n])
		}

		if readErr != nil {
			if readErr.Error() == "EOF" {
				break
			}

			return nil, fmt.Errorf(
				"read Cloudflare IPv4 ranges: %w",
				readErr,
			)
		}
	}

	lines := strings.Split(data.String(), "\n")

	cidrs := make([]string, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		_, network, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}

		if network.IP.To4() == nil {
			continue
		}

		cidrs = append(cidrs, line)
	}

	if len(cidrs) == 0 {
		return nil, fmt.Errorf(
			"no valid Cloudflare IPv4 ranges found",
		)
	}

	return &Source{
		CIDRs: cidrs,
	}, nil
}

func (s *Source) Generate(limit int) ([]string, error) {
	if s == nil {
		return nil, fmt.Errorf("nil IP source")
	}

	if limit <= 0 {
		return nil, fmt.Errorf("IP limit must be greater than zero")
	}

	result := make([]string, 0, limit)
	seen := make(map[string]struct{}, limit)

	for _, cidr := range s.CIDRs {
		ips, err := hostsFromCIDR(cidr)
		if err != nil {
			continue
		}

		for _, ip := range ips {
			if _, exists := seen[ip]; exists {
				continue
			}

			seen[ip] = struct{}{}
			result = append(result, ip)

			if len(result) >= limit {
				return result, nil
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf(
			"Cloudflare ranges produced no IPv4 addresses",
		)
	}

	return result, nil
}

func hostsFromCIDR(cidr string) ([]string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf(
			"CIDR is not IPv4: %s",
			cidr,
		)
	}

	networkIP := network.IP.To4()
	if networkIP == nil {
		return nil, fmt.Errorf(
			"network is not IPv4: %s",
			cidr,
		)
	}

	mask := binary.BigEndian.Uint32(network.Mask)

	start := binary.BigEndian.Uint32(networkIP)
	end := start | ^mask

	// Skip network and broadcast addresses when the subnet
	// contains enough addresses for them to exist.
	first := start
	last := end

	total := uint64(end) - uint64(start) + 1

	if total > 2 {
		first++
		last--
	}

	count := uint64(last) - uint64(first) + 1

	// Avoid accidentally creating an enormous allocation.
	if count > 1_000_000 {
		count = 1_000_000
	}

	result := make([]string, 0, int(count))

	for value := first; value <= last; value++ {
		buf := make(net.IP, net.IPv4len)

		binary.BigEndian.PutUint32(buf, value)

		result = append(
			result,
			buf.String(),
		)

		if value == ^uint32(0) {
			break
		}
	}

	return result, nil
}
