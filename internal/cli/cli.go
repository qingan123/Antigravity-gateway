package cli

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"antigravity-gateway/internal/config"
	"antigravity-gateway/internal/keymgmt"
)

// Run handles optional administrative CLI commands. It returns handled=false for normal server startup.
func Run(args []string, cfg *config.Config, mgr *keymgmt.Manager) (handled bool, err error) {
	if len(args) == 0 {
		return false, nil
	}
	if err := authenticate(cfg.AdminAPIKey); err != nil {
		return true, err
	}
	switch args[0] {
	case "key":
		return true, runKey(args[1:], mgr)
	case "config":
		return true, runConfig(args[1:], cfg)
	case "help":
		printHelp()
		return true, nil
	default:
		return true, fmt.Errorf("unknown command %q; use help", args[0])
	}
}

func authenticate(expected string) error {
	value := strings.TrimSpace(os.Getenv("ADMIN_PASSWORD"))
	if value == "" {
		fmt.Fprintln(os.Stderr, "管理员密码:")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && len(line) == 0 {
			return errors.New("administrator password is required on stdin or ADMIN_PASSWORD")
		}
		value = strings.TrimSpace(line)
	}
	if subtle.ConstantTimeCompare([]byte(value), []byte(expected)) != 1 {
		return errors.New("invalid administrator password")
	}
	return nil
}

func runKey(args []string, mgr *keymgmt.Manager) error {
	if len(args) == 0 {
		return errors.New("usage: key create [name] | key list | key reveal ID | key delete ID")
	}
	switch args[0] {
	case "create":
		name := ""
		if len(args) > 1 {
			name = strings.Join(args[1:], " ")
		}
		result, err := mgr.CreateKey(name, 0, nil)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "list":
		return printJSON(map[string]any{"object": "list", "data": mgr.ListKeys()})
	case "reveal":
		if len(args) != 2 {
			return errors.New("usage: key reveal ID")
		}
		key, err := mgr.RevealKey(args[1])
		if err != nil {
			return err
		}
		return printJSON(map[string]string{"id": args[1], "key": key})
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: key delete ID")
		}
		if err := mgr.DeleteKey(args[1]); err != nil {
			return err
		}
		return printJSON(map[string]string{"id": args[1], "status": "deleted"})
	default:
		return fmt.Errorf("unknown key command %q", args[0])
	}
}

func runConfig(args []string, cfg *config.Config) error {
	if len(args) == 0 || args[0] == "get" {
		base, _, mode := cfg.UpstreamSettings()
		return printJSON(map[string]string{"base_url": base, "auth_mode": mode, "api_key_configured": fmt.Sprint(mode == "none" || cfgHasUpstreamKey(cfg))})
	}
	if args[0] == "set-upstream" {
		if len(args) < 2 || len(args) > 4 {
			return errors.New("usage: config set-upstream URL [API_KEY] [bearer|none]")
		}
		mode := "bearer"
		if len(args) == 4 {
			mode = args[3]
		}
		key := ""
		if len(args) >= 3 {
			key = args[2]
		}
		if err := cfg.UpdateUpstream(config.UpstreamSettings{BaseURL: args[1], APIKey: key, AuthMode: mode}); err != nil {
			return err
		}
		return printJSON(map[string]string{"status": "updated"})
	}
	return fmt.Errorf("unknown config command %q", args[0])
}

func cfgHasUpstreamKey(cfg *config.Config) bool {
	_, key, _ := cfg.UpstreamSettings()
	return key != ""
}
func printJSON(v any) error { return json.NewEncoder(os.Stdout).Encode(v) }
func printHelp() {
	fmt.Println("Usage: server key create [name] | key list | key reveal ID | key delete ID | config get | config set-upstream URL [API_KEY] [bearer|none]")
}
