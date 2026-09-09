package keymgmt

import (
	"strings"
	"testing"
)

func TestCreateKeyUsesOpenAIStylePrefix(t *testing.T) {
	m, err := NewManager(":memory:", "hmac-secret-at-least-16-bytes", nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Close()

	result, err := m.CreateKey("test", 0, nil)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if !strings.HasPrefix(result.Key, "sk-") {
		t.Fatalf("generated key %q does not start with sk-", result.Key)
	}
	if !strings.HasPrefix(result.KeyPrefix, "sk-") {
		t.Fatalf("key prefix %q does not start with sk-", result.KeyPrefix)
	}
}
