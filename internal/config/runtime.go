package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type UpstreamSettings struct {
	BaseURL  string `json:"base_url"`
	APIKey   string `json:"api_key,omitempty"`
	AuthMode string `json:"auth_mode"`
}

type RuntimeStore struct {
	mu       sync.RWMutex
	path     string
	settings UpstreamSettings
}

func NewRuntimeStore(path string, initial UpstreamSettings) (*RuntimeStore, error) {
	s := &RuntimeStore{path: path, settings: initial}
	if data, err := os.ReadFile(path); err == nil {
		var saved UpstreamSettings
		if err := json.Unmarshal(data, &saved); err != nil {
			return nil, fmt.Errorf("invalid runtime config: %w", err)
		}
		if strings.TrimSpace(saved.BaseURL) != "" {
			base, err := NormalizeUpstreamBaseURL(saved.BaseURL)
			if err != nil {
				return nil, err
			}
			saved.BaseURL = base
			if saved.AuthMode == "" {
				saved.AuthMode = "bearer"
			}
			s.settings = saved
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *RuntimeStore) Get() UpstreamSettings { s.mu.RLock(); defer s.mu.RUnlock(); return s.settings }

func (s *RuntimeStore) Update(next UpstreamSettings) error {
	base, err := NormalizeUpstreamBaseURL(next.BaseURL)
	if err != nil {
		return err
	}
	next.BaseURL = base
	next.AuthMode = strings.ToLower(strings.TrimSpace(next.AuthMode))
	if next.AuthMode == "" {
		next.AuthMode = "bearer"
	}
	if next.AuthMode != "bearer" && next.AuthMode != "none" {
		return errors.New("auth_mode must be bearer or none")
	}
	if next.AuthMode == "bearer" && strings.TrimSpace(next.APIKey) == "" {
		return errors.New("api key is required for bearer auth")
	}
	next.APIKey = strings.TrimSpace(next.APIKey)
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(s.path); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.settings = next
	return nil
}

func NormalizeUpstreamBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("upstream URL must be a valid http/https URL with host")
	}
	base := strings.TrimRight(raw, "/")
	base = strings.TrimSuffix(base, "/v1")
	return strings.TrimRight(base, "/"), nil
}
