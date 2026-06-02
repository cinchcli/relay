package relay

import (
	"os"
	"strings"

	"github.com/cinchcli/relay/internal/media"
)

// Config is the relay server's configuration, parsed once from the environment
// by LoadConfig at startup (cmd/relay) instead of scattering os.Getenv calls
// across the package. It centralizes everything the entrypoint needs to wire a
// Handler, Store, and media backend.
type Config struct {
	Port        string // TCP port; default "8080"
	DatabaseURL string // Postgres DSN (required)
	BaseURL     string // public HTTPS root, e.g. https://api.cinchcli.com
	CORSOrigins []string

	GitHubClientID     string
	GitHubClientSecret string
	GoogleClientID     string
	GoogleClientSecret string

	TelemetryURL          string
	TelemetryAPIKey       string
	InternalServiceSecret string

	// PlanEnforcementDisabled mirrors CINCH_PLAN_ENFORCEMENT_DISABLED: self-host
	// relays skip hosted-plan checks (device limit, retention clamp).
	PlanEnforcementDisabled bool

	BootstrapInviteCode string // RELAY_BOOTSTRAP_INVITE_CODE; empty = none

	Media media.Config
}

// envTruthy reports whether v is a recognized truthy flag ("1" or "true",
// case-insensitive), matching the previous inline checks.
func envTruthy(v string) bool {
	return v == "1" || strings.EqualFold(v, "true")
}

// LoadConfig reads the relay environment once. Defaults and trimming match the
// previous per-call os.Getenv usage so behavior is unchanged.
func LoadConfig() Config {
	cfg := Config{
		Port:                    os.Getenv("PORT"),
		DatabaseURL:             os.Getenv("DATABASE_URL"),
		BaseURL:                 os.Getenv("BASE_URL"),
		GitHubClientID:          os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret:      os.Getenv("GITHUB_CLIENT_SECRET"),
		GoogleClientID:          os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret:      os.Getenv("GOOGLE_CLIENT_SECRET"),
		TelemetryURL:            strings.TrimRight(os.Getenv("TELEMETRY_URL"), "/"),
		TelemetryAPIKey:         os.Getenv("TELEMETRY_API_KEY"),
		InternalServiceSecret:   os.Getenv("INTERNAL_SERVICE_SECRET"),
		PlanEnforcementDisabled: envTruthy(os.Getenv("CINCH_PLAN_ENFORCEMENT_DISABLED")),
		BootstrapInviteCode:     os.Getenv("RELAY_BOOTSTRAP_INVITE_CODE"),
		Media:                   media.LoadConfigFromEnv(),
	}
	if cfg.Port == "" {
		cfg.Port = "8080"
	}
	// CORS_ORIGINS: comma-separated extra allowed origins for self-hosters.
	if corsEnv := os.Getenv("CORS_ORIGINS"); corsEnv != "" {
		for _, o := range strings.Split(corsEnv, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				cfg.CORSOrigins = append(cfg.CORSOrigins, trimmed)
			}
		}
	}
	return cfg
}

// OAuthConfigured reports whether any OAuth provider credentials are present.
func (c Config) OAuthConfigured() bool {
	return c.GitHubClientID != "" || c.GoogleClientID != ""
}
