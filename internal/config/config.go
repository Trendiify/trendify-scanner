package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	VLESSURL string

	IPCount int
	Workers int

	Timeout time.Duration

	TopCount int

	OutputFile string
}

func Load() Config {
	return Config{
		VLESSURL: os.Getenv("TRENDIFY_VLESS_URL"),

		IPCount: envInt(
			"TRENDIFY_IP_COUNT",
			1000,
		),

		Workers: envInt(
			"TRENDIFY_WORKERS",
			100,
		),

		Timeout: time.Duration(
			envInt(
				"TRENDIFY_TIMEOUT",
				5,
			),
		) * time.Second,

		TopCount: envInt(
			"TRENDIFY_TOP",
			10,
		),

		OutputFile: envString(
			"TRENDIFY_OUTPUT",
			"results.json",
		),
	}
}

func envInt(
	name string,
	fallback int,
) int {

	value := os.Getenv(name)

	if value == "" {
		return fallback
	}

	n, err := strconv.Atoi(value)

	if err != nil || n <= 0 {
		return fallback
	}

	return n
}

func envString(
	name string,
	fallback string,
) string {

	value := os.Getenv(name)

	if value == "" {
		return fallback
	}

	return value
}
