package config

import (
	"os"
	"strings"
)

// Config is guest/host runtime process configuration from the environment.
type Config struct {
	PolicyPath string
	LogLevel   string
	GatewayURL string
}

// Load reads CAUTEUM_* defaults.
func Load() Config {
	return Config{
		PolicyPath: strings.TrimSpace(os.Getenv("CAUTEUM_POLICY")),
		LogLevel:   strings.TrimSpace(os.Getenv("CAUTEUM_LOG_LEVEL")),
		GatewayURL: strings.TrimSpace(os.Getenv("CAUTEUM_GATEWAY_URL")),
	}
}
