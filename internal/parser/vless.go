package parser

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type VLESSConfig struct {
	UUID string

	Address string
	Port    int

	SNI  string
	Host string
	Path string

	Network string
	Security string

	Name string
}

func Parse(raw string) (*VLESSConfig, error) {
	raw = strings.TrimSpace(raw)

	if strings.HasPrefix(raw, "vless://") == false {
		return nil, fmt.Errorf("only vless:// is supported")
	}

	u, err := url.Parse(raw)

	if err != nil {
		return nil, fmt.Errorf("parse vless url: %w", err)
	}

	if u.User == nil {
		return nil, fmt.Errorf("missing UUID")
	}

	uuid := u.User.Username()

	if uuid == "" {
		return nil, fmt.Errorf("empty UUID")
	}

	port := 443

	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())

		if err != nil {
			return nil, fmt.Errorf("invalid port")
		}
	}

	query := u.Query()

	network := query.Get("type")

	if network == "" {
		network = query.Get("network")
	}

	security := query.Get("security")

	sni := query.Get("sni")

	host := query.Get("host")

	path := query.Get("path")

	if host == "" {
		host = query.Get("authority")
	}

	name := ""

	if u.Fragment != "" {
		name, _ = url.QueryUnescape(u.Fragment)
	}

	return &VLESSConfig{
		UUID: uuid,

		Address: u.Hostname(),
		Port:    port,

		SNI:  sni,
		Host: host,
		Path: path,

		Network: network,
		Security: security,

		Name: name,
	}, nil
}

func ParseBase64(raw string) (*VLESSConfig, error) {
	raw = strings.TrimSpace(raw)

	data, err := base64.StdEncoding.DecodeString(raw)

	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(raw)

		if err != nil {
			return nil, err
		}
	}

	return Parse(string(data))
}
