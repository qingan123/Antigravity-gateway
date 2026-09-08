package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type StaticKeyConfig struct {
	ID            string   `json:"id"`
	Key           string   `json:"key"`
	Name          string   `json:"name"`
	AllowedModels []string `json:"allowed_models,omitempty"`
}

type Config struct {
	upstreamMu    sync.RWMutex
	upstreamStore *RuntimeStore

	UpstreamBaseURL             string
	UpstreamAPIKey              string
	UpstreamAuthMode            string // bearer, none
	UpstreamTimeout             time.Duration
	UpstreamMaxIdleConns        int
	UpstreamMaxIdleConnsPerHost int
	UpstreamMaxConnsPerHost     int

	Host string
	Port int

	APIKey string // Simple downstream key: API_KEY

	AdminAPIKey   string
	KeyHMACSecret string
	KeyDBPath     string

	StaticKeys []StaticKeyConfig

	ControlMessageRole     string // system, developer
	ControlMessagePosition string // tail, head, system_tail
	ControlPromptTemplate  string
	SyntheticToolPrefix    string
	SyntheticToolStrict    bool

	WrapperMode          string // prefer, required, off
	RecoveryPolicy       string // repair, repair_then_retry, fail
	UpstreamEmptyRetries int    // default 3
	TextModelPattern     string // Optional regex override for text models
	NonTextModelPattern  string // Optional regex override for non-text models

	MaxRequestBytes             int64
	MaxResponseBytes            int64
	MaxConcurrentRequests       int
	MaxConcurrentRequestsPerKey int
	RequestQueueTimeout         time.Duration

	StreamSideBufferBytes   int
	StreamRepairBufferBytes int
	StreamFlushInterval     time.Duration

	ShutdownTimeout time.Duration
	ModelsCacheTTL  time.Duration
	LogLevel        string
	TrustProxy      bool
	EnvFileLoaded   string
}

func LoadFromEnv() (*Config, error) {
	loadedFile, _, err := LoadDotEnv()
	if err != nil {
		return nil, fmt.Errorf("error loading .env: %w", err)
	}
	cfg, err := Load(os.Getenv)
	if err != nil {
		return nil, err
	}
	cfg.EnvFileLoaded = loadedFile
	return cfg, nil
}
func Load(getenv func(string) string) (*Config, error) {
	cfg := &Config{}

	// Upstream Base URL (Required)
	rawUpstream := strings.TrimSpace(getenv("UPSTREAM_BASE_URL"))
	if rawUpstream == "" {
		return nil, errors.New("UPSTREAM_BASE_URL is required")
	}
	parsedURL, err := url.Parse(rawUpstream)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid UPSTREAM_BASE_URL: must be a valid http/https URL with host")
	}
	// Normalize root URL (trim trailing slashes and optional /v1)
	cleanUpstream := strings.TrimRight(rawUpstream, "/")
	cleanUpstream = strings.TrimSuffix(cleanUpstream, "/v1")
	cfg.UpstreamBaseURL = strings.TrimRight(cleanUpstream, "/")

	// Upstream Auth Mode
	cfg.UpstreamAuthMode = strings.ToLower(strings.TrimSpace(getenv("UPSTREAM_AUTH_MODE")))
	if cfg.UpstreamAuthMode == "" {
		cfg.UpstreamAuthMode = "bearer"
	}
	if cfg.UpstreamAuthMode != "bearer" && cfg.UpstreamAuthMode != "none" {
		return nil, fmt.Errorf("invalid UPSTREAM_AUTH_MODE: %q (must be 'bearer' or 'none')", cfg.UpstreamAuthMode)
	}

	// Upstream API Key
	cfg.UpstreamAPIKey = strings.TrimSpace(getenv("UPSTREAM_API_KEY"))
	if cfg.UpstreamAuthMode == "bearer" && cfg.UpstreamAPIKey == "" {
		return nil, errors.New("UPSTREAM_API_KEY is required when UPSTREAM_AUTH_MODE is 'bearer'")
	}

	// Upstream Timeout
	cfg.UpstreamTimeout = getDurationMS(getenv("UPSTREAM_TIMEOUT_MS"), 120000, 1000, 600000)

	// Upstream Connection Pool
	cfg.UpstreamMaxIdleConns = getInt(getenv("UPSTREAM_MAX_IDLE_CONNS"), 2048, 1, 100000)
	cfg.UpstreamMaxIdleConnsPerHost = getInt(getenv("UPSTREAM_MAX_IDLE_CONNS_PER_HOST"), 512, 1, 100000)
	cfg.UpstreamMaxConnsPerHost = getInt(getenv("UPSTREAM_MAX_CONNS_PER_HOST"), 512, 1, 100000)

	// Host and Port
	cfg.Host = strings.TrimSpace(getenv("HOST"))
	if cfg.Host == "" {
		cfg.Host = "0.0.0.0"
	}
	cfg.Port = getInt(getenv("PORT"), 8080, 1, 65535)

	// Simple Downstream API Key (Optional, convenient single key)
	cfg.APIKey = strings.TrimSpace(getenv("API_KEY"))
	if cfg.APIKey != "" {
		cfg.StaticKeys = append(cfg.StaticKeys, StaticKeyConfig{
			ID:   "default",
			Key:  cfg.APIKey,
			Name: "Default API Key",
		})
	}

	// Admin API Key (Optional, default to auto/admin-secret-key if not set)
	cfg.AdminAPIKey = strings.TrimSpace(getenv("ADMIN_API_KEY"))
	if cfg.AdminAPIKey == "" {
		cfg.AdminAPIKey = "admin-secret-key-12345"
	} else if len(cfg.AdminAPIKey) < 6 {
		return nil, errors.New("ADMIN_API_KEY must be at least 6 characters")
	}

	// Key HMAC Secret (Optional, fallback to default secret if not set)
	cfg.KeyHMACSecret = strings.TrimSpace(getenv("KEY_HMAC_SECRET"))
	if cfg.KeyHMACSecret == "" {
		cfg.KeyHMACSecret = "antigravity-gateway-default-hmac-secret-2025"
	} else if len(cfg.KeyHMACSecret) < 16 {
		return nil, errors.New("KEY_HMAC_SECRET must be at least 16 characters")
	}

	// Key DB Path
	cfg.KeyDBPath = strings.TrimSpace(getenv("KEY_DB_PATH"))
	if cfg.KeyDBPath == "" {
		cfg.KeyDBPath = "./data/keys.sqlite"
	}

	// Downstream Static Keys
	rawStaticKeys := strings.TrimSpace(getenv("DOWNSTREAM_KEYS_JSON"))
	if rawStaticKeys != "" && rawStaticKeys != "[]" {
		var staticKeys []StaticKeyConfig
		if err := json.Unmarshal([]byte(rawStaticKeys), &staticKeys); err != nil {
			return nil, fmt.Errorf("invalid DOWNSTREAM_KEYS_JSON: %w", err)
		}
		seenIDs := make(map[string]bool)
		for _, k := range staticKeys {
			if strings.TrimSpace(k.ID) == "" {
				return nil, errors.New("static key ID cannot be empty")
			}
			if strings.TrimSpace(k.Key) == "" {
				return nil, fmt.Errorf("static key for ID %q cannot be empty", k.ID)
			}
			if seenIDs[k.ID] {
				return nil, fmt.Errorf("duplicate static key ID: %q", k.ID)
			}
			seenIDs[k.ID] = true
		}
		cfg.StaticKeys = staticKeys
	}
	storePath := strings.TrimSpace(getenv("RUNTIME_CONFIG_PATH"))
	if storePath == "" {
		storePath = filepath.Join(filepath.Dir(cfg.KeyDBPath), "runtime-config.json")
	}
	store, err := NewRuntimeStore(storePath, UpstreamSettings{BaseURL: cfg.UpstreamBaseURL, APIKey: cfg.UpstreamAPIKey, AuthMode: cfg.UpstreamAuthMode})
	if err != nil {
		return nil, fmt.Errorf("failed to load runtime config: %w", err)
	}
	cfg.upstreamStore = store
	if saved := store.Get(); saved.BaseURL != "" {
		cfg.UpstreamBaseURL, cfg.UpstreamAPIKey, cfg.UpstreamAuthMode = saved.BaseURL, saved.APIKey, saved.AuthMode
		if cfg.UpstreamAuthMode == "bearer" && cfg.UpstreamAPIKey == "" {
			return nil, errors.New("UPSTREAM_API_KEY is required when UPSTREAM_AUTH_MODE is 'bearer'")
		}
	}

	// Control Message Role & Position
	cfg.ControlMessageRole = strings.ToLower(strings.TrimSpace(getenv("CONTROL_MESSAGE_ROLE")))
	if cfg.ControlMessageRole == "" {
		cfg.ControlMessageRole = "system"
	}
	if cfg.ControlMessageRole != "system" && cfg.ControlMessageRole != "developer" {
		return nil, fmt.Errorf("invalid CONTROL_MESSAGE_ROLE: %q (must be 'system' or 'developer')", cfg.ControlMessageRole)
	}

	cfg.ControlMessagePosition = strings.ToLower(strings.TrimSpace(getenv("CONTROL_MESSAGE_POSITION")))
	if cfg.ControlMessagePosition == "" {
		cfg.ControlMessagePosition = "tail"
	}
	if cfg.ControlMessagePosition != "tail" && cfg.ControlMessagePosition != "head" && cfg.ControlMessagePosition != "system_tail" {
		return nil, fmt.Errorf("invalid CONTROL_MESSAGE_POSITION: %q (must be 'tail', 'head' or 'system_tail')", cfg.ControlMessagePosition)
	}

	// Synthetic Tool Prefix & Strict
	cfg.SyntheticToolPrefix = strings.TrimSpace(getenv("SYNTHETIC_TOOL_PREFIX"))
	if cfg.SyntheticToolPrefix == "" {
		cfg.SyntheticToolPrefix = "agw_emit_"
	}
	cfg.SyntheticToolStrict = getBool(getenv("SYNTHETIC_TOOL_STRICT"), false)

	// Wrapper Mode
	cfg.WrapperMode = strings.ToLower(strings.TrimSpace(getenv("WRAPPER_MODE")))
	if cfg.WrapperMode == "" {
		cfg.WrapperMode = "prefer"
	}
	if cfg.WrapperMode != "prefer" && cfg.WrapperMode != "required" && cfg.WrapperMode != "off" {
		return nil, fmt.Errorf("invalid WRAPPER_MODE: %q (must be 'prefer', 'required', or 'off')", cfg.WrapperMode)
	}

	// Recovery Policy
	cfg.RecoveryPolicy = strings.ToLower(strings.TrimSpace(getenv("RECOVERY_POLICY")))
	if cfg.RecoveryPolicy == "" {
		cfg.RecoveryPolicy = "repair"
	}
	if cfg.RecoveryPolicy != "repair" && cfg.RecoveryPolicy != "repair_then_retry" && cfg.RecoveryPolicy != "fail" {
		return nil, fmt.Errorf("invalid RECOVERY_POLICY: %q (must be 'repair', 'repair_then_retry', or 'fail')", cfg.RecoveryPolicy)
	}

	// Upstream Empty Response Retries (default 3)
	cfg.UpstreamEmptyRetries = getInt(getenv("UPSTREAM_EMPTY_RETRIES"), 3, 0, 10)

	// Model Filter Patterns (Regex)
	cfg.TextModelPattern = strings.TrimSpace(getenv("TEXT_MODEL_PATTERN"))
	cfg.NonTextModelPattern = strings.TrimSpace(getenv("NON_TEXT_MODEL_PATTERN"))
	// Buffers & Limits
	cfg.MaxRequestBytes = int64(getInt(getenv("MAX_REQUEST_BYTES"), 16777216, 1024, 104857600))   // 1KB - 100MB
	cfg.MaxResponseBytes = int64(getInt(getenv("MAX_RESPONSE_BYTES"), 16777216, 1024, 104857600)) // 1KB - 100MB

	cfg.MaxConcurrentRequests = getInt(getenv("MAX_CONCURRENT_REQUESTS"), 1024, 1, 100000)
	cfg.MaxConcurrentRequestsPerKey = getInt(getenv("MAX_CONCURRENT_REQUESTS_PER_KEY"), 64, 1, 100000)
	cfg.RequestQueueTimeout = getDurationMS(getenv("REQUEST_QUEUE_TIMEOUT_MS"), 50, 0, 10000)

	cfg.StreamSideBufferBytes = getInt(getenv("STREAM_SIDE_BUFFER_BYTES"), 0, 0, 10485760)
	cfg.StreamRepairBufferBytes = getInt(getenv("STREAM_REPAIR_BUFFER_BYTES"), 1048576, 1024, 10485760)
	cfg.StreamFlushInterval = getDurationMS(getenv("STREAM_FLUSH_INTERVAL_MS"), 0, 0, 10)

	cfg.ShutdownTimeout = getDurationMS(getenv("SHUTDOWN_TIMEOUT_MS"), 30000, 1000, 300000)
	cfg.ModelsCacheTTL = getDurationMS(getenv("MODELS_CACHE_TTL_MS"), 30000, 0, 86400000)

	cfg.LogLevel = strings.ToLower(strings.TrimSpace(getenv("LOG_LEVEL")))
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	cfg.TrustProxy = getBool(getenv("TRUST_PROXY"), false)

	return cfg, nil
}

func getInt(val string, defaultVal int, minVal int, maxVal int) int {
	if val == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < minVal || n > maxVal {
		return defaultVal
	}
	return n
}

func getDurationMS(val string, defaultMS int, minMS int, maxMS int) time.Duration {
	ms := getInt(val, defaultMS, minMS, maxMS)
	return time.Duration(ms) * time.Millisecond
}

func getBool(val string, defaultVal bool) bool {
	if val == "" {
		return defaultVal
	}
	val = strings.ToLower(val)
	return val == "true" || val == "1" || val == "yes"
}

func (c *Config) UpstreamChatURL() string {
	base, _, _ := c.UpstreamSettings()
	return base + "/v1/chat/completions"
}

func (c *Config) UpstreamModelsURL() string {
	base, _, _ := c.UpstreamSettings()
	return base + "/v1/models"
}

func (c *Config) UpstreamSettings() (string, string, string) {
	c.upstreamMu.RLock()
	defer c.upstreamMu.RUnlock()
	return c.UpstreamBaseURL, c.UpstreamAPIKey, c.UpstreamAuthMode
}

func (c *Config) UpdateUpstream(settings UpstreamSettings) error {
	if err := c.upstreamStore.Update(settings); err != nil {
		return err
	}
	saved := c.upstreamStore.Get()
	c.upstreamMu.Lock()
	c.UpstreamBaseURL, c.UpstreamAPIKey, c.UpstreamAuthMode = saved.BaseURL, saved.APIKey, saved.AuthMode
	c.upstreamMu.Unlock()
	return nil
}
