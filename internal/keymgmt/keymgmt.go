package keymgmt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"antigravity-gateway/internal/config"
)

var (
	ErrInvalidKey     = errors.New("invalid downstream api key")
	ErrKeyExpired     = errors.New("downstream api key has expired")
	ErrKeyRevoked     = errors.New("downstream api key has been revoked")
	ErrModelForbidden = errors.New("model not permitted for this api key")
	ErrStaticKey      = errors.New("static key cannot be modified or revoked")
	ErrKeyNotFound    = errors.New("key not found")
)

type KeyInfo struct {
	ID            string   `json:"id"`
	KeyPrefix     string   `json:"key_prefix"`
	HMACHash      string   `json:"-"`
	Name          string   `json:"name"`
	AllowedModels []string `json:"allowed_models,omitempty"`
	CreatedAt     int64    `json:"created_at"`
	ExpiresAt     int64    `json:"expires_at,omitempty"`
	RevokedAt     int64    `json:"revoked_at,omitempty"`
	Status        string   `json:"status"` // active, revoked, expired
	IsStatic      bool     `json:"is_static"`
	CanReveal     bool     `json:"can_reveal"`
	encryptedKey  string
}

type CreateKeyResult struct {
	ID            string   `json:"id"`
	Key           string   `json:"key"` // Returned ONLY once on creation!
	KeyPrefix     string   `json:"key_prefix"`
	Name          string   `json:"name"`
	AllowedModels []string `json:"allowed_models,omitempty"`
	CreatedAt     int64    `json:"created_at"`
	ExpiresAt     int64    `json:"expires_at,omitempty"`
	Status        string   `json:"status"`
}

type KeySnapshot struct {
	byHash map[string]*KeyInfo
	byID   map[string]*KeyInfo
	all    []*KeyInfo
}

type Manager struct {
	db         *sql.DB
	hmacSecret []byte
	staticKeys []config.StaticKeyConfig
	snapshot   atomic.Pointer[KeySnapshot]
	writeMu    sync.Mutex
}

func (m *Manager) cipher() (cipher.AEAD, error) {
	seed := sha256.Sum256(m.hmacSecret)
	block, err := aes.NewCipher(seed[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (m *Manager) encryptKey(raw string) (string, error) {
	aead, err := m.cipher()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(raw), nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (m *Manager) decryptKey(value string) (string, error) {
	aead, err := m.cipher()
	if err != nil {
		return "", err
	}
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(sealed) < aead.NonceSize() {
		return "", errors.New("invalid encrypted key")
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], nil)
	if err != nil {
		return "", errors.New("invalid encrypted key")
	}
	return string(plain), nil
}

func NewManager(dbPath string, hmacSecret string, staticKeys []config.StaticKeyConfig) (*Manager, error) {
	if len(hmacSecret) < 16 {
		return nil, errors.New("key HMAC secret must be at least 16 characters")
	}

	// Ensure parent directory exists
	if dbPath != ":memory:" {
		dir := filepath.Dir(dbPath)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create db directory: %w", err)
			}
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}

	// Enable WAL mode and foreign keys
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to set sqlite pragma: %w", err)
	}

	// Run migration
	schema := `
	CREATE TABLE IF NOT EXISTS downstream_keys (
		id TEXT PRIMARY KEY,
		key_prefix TEXT NOT NULL,
		hmac_hash TEXT NOT NULL UNIQUE,
		encrypted_key TEXT,
		name TEXT NOT NULL,
		allowed_models TEXT,
		created_at INTEGER NOT NULL,
		expires_at INTEGER,
		revoked_at INTEGER,
		status TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_downstream_keys_hmac ON downstream_keys(hmac_hash);
	CREATE TABLE IF NOT EXISTS key_migrations (
		hmac_hash TEXT PRIMARY KEY,
		migrated_at INTEGER NOT NULL
	);
	`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize db schema: %w", err)
	}
	_, _ = db.Exec(`ALTER TABLE downstream_keys ADD COLUMN encrypted_key TEXT`)

	m := &Manager{
		db:         db,
		hmacSecret: []byte(hmacSecret),
		staticKeys: staticKeys,
	}

	// Initial snapshot load
	if err := m.reloadSnapshot(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to load initial key snapshot: %w", err)
	}

	return m, nil
}

func (m *Manager) ImportStaticKeys() error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	for _, sk := range m.staticKeys {
		if strings.TrimSpace(sk.Key) == "" {
			continue
		}
		hash := m.HashKey(sk.Key)
		var migrated int
		if err := m.db.QueryRow(`SELECT COUNT(1) FROM key_migrations WHERE hmac_hash = ?`, hash).Scan(&migrated); err != nil {
			return err
		}
		if migrated > 0 {
			continue
		}
		enc, err := m.encryptKey(sk.Key)
		if err != nil {
			return err
		}
		prefix := sk.Key
		if len(prefix) > 12 {
			prefix = prefix[:12] + "..."
		}
		id := sk.ID
		if id == "" {
			id = "key_" + hex.EncodeToString([]byte(hash[:8]))
		}
		var exists int
		if err := m.db.QueryRow(`SELECT COUNT(1) FROM downstream_keys WHERE hmac_hash = ?`, hash).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			if _, err = m.db.Exec(`INSERT INTO downstream_keys (id,key_prefix,hmac_hash,encrypted_key,name,allowed_models,created_at,status) VALUES (?,?,?,?,?,?,?, 'active')`, id, prefix, hash, enc, sk.Name, nullableStrings(sk.AllowedModels), time.Now().Unix()); err != nil {
				return err
			}
		}
		if _, err = m.db.Exec(`INSERT INTO key_migrations (hmac_hash,migrated_at) VALUES (?,?)`, hash, time.Now().Unix()); err != nil {
			return err
		}
	}
	m.staticKeys = nil
	return m.reloadSnapshot()
}

func nullableStrings(values []string) sql.NullString {
	if len(values) == 0 {
		return sql.NullString{}
	}
	b, _ := json.Marshal(values)
	return sql.NullString{String: string(b), Valid: true}
}

func (m *Manager) RevealKey(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", ErrKeyNotFound
	}
	snap := m.snapshot.Load()
	if snap == nil {
		return "", ErrKeyNotFound
	}
	info, ok := snap.byID[id]
	if !ok || info.Status != "active" {
		return "", ErrKeyNotFound
	}
	if info.encryptedKey == "" {
		return "", errors.New("key cannot be revealed")
	}
	return m.decryptKey(info.encryptedKey)
}

func (m *Manager) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

func (m *Manager) HashKey(rawKey string) string {
	mac := hmac.New(sha256.New, m.hmacSecret)
	mac.Write([]byte(rawKey))
	return hex.EncodeToString(mac.Sum(nil))
}

func (m *Manager) reloadSnapshot() error {
	byHash := make(map[string]*KeyInfo)
	byID := make(map[string]*KeyInfo)
	var all []*KeyInfo

	// 1. Process static keys first
	for _, sk := range m.staticKeys {
		hash := m.HashKey(sk.Key)
		prefix := sk.Key
		if len(prefix) > 12 {
			prefix = prefix[:12] + "..."
		}
		info := &KeyInfo{
			ID:            sk.ID,
			KeyPrefix:     prefix,
			HMACHash:      hash,
			Name:          sk.Name,
			AllowedModels: sk.AllowedModels,
			CreatedAt:     time.Now().Unix(),
			ExpiresAt:     0,
			Status:        "active",
			IsStatic:      true,
			CanReveal:     false,
		}
		if _, exists := byID[info.ID]; exists {
			return fmt.Errorf("duplicate static key ID: %q", info.ID)
		}
		byHash[hash] = info
		byID[info.ID] = info
		all = append(all, info)
	}

	// 2. Read dynamic keys from DB
	rows, err := m.db.Query(`SELECT id, key_prefix, hmac_hash, encrypted_key, name, allowed_models, created_at, expires_at, revoked_at, status FROM downstream_keys`)
	if err != nil {
		return err
	}
	defer rows.Close()

	now := time.Now().Unix()
	for rows.Next() {
		var id, keyPrefix, hmacHash, name, status string
		var encryptedKey, allowedModelsJSON sql.NullString
		var createdAt int64
		var expiresAt, revokedAt sql.NullInt64

		if err := rows.Scan(&id, &keyPrefix, &hmacHash, &encryptedKey, &name, &allowedModelsJSON, &createdAt, &expiresAt, &revokedAt, &status); err != nil {
			return err
		}

		var allowedModels []string
		if allowedModelsJSON.Valid && allowedModelsJSON.String != "" {
			_ = json.Unmarshal([]byte(allowedModelsJSON.String), &allowedModels)
		}

		var exp int64
		if expiresAt.Valid {
			exp = expiresAt.Int64
			if status == "active" && exp > 0 && now > exp {
				status = "expired"
			}
		}

		var rev int64
		if revokedAt.Valid {
			rev = revokedAt.Int64
		}

		// A migrated static key can temporarily coexist with its original
		// static definition during startup. The database copy is authoritative.
		if existing, exists := byID[id]; exists {
			if existing.IsStatic && existing.HMACHash == hmacHash {
				delete(byHash, existing.HMACHash)
				delete(byID, existing.ID)
				for i, item := range all {
					if item == existing {
						all = append(all[:i], all[i+1:]...)
						break
					}
				}
			} else {
				return fmt.Errorf("dynamic key ID %q conflicts with static key", id)
			}
		}

		info := &KeyInfo{
			ID:            id,
			KeyPrefix:     keyPrefix,
			HMACHash:      hmacHash,
			Name:          name,
			AllowedModels: allowedModels,
			CreatedAt:     createdAt,
			ExpiresAt:     exp,
			RevokedAt:     rev,
			Status:        status,
			IsStatic:      false,
			CanReveal:     encryptedKey.Valid && encryptedKey.String != "",
			encryptedKey:  encryptedKey.String,
		}

		byHash[hmacHash] = info
		byID[id] = info
		all = append(all, info)
	}

	if err := rows.Err(); err != nil {
		return err
	}

	snap := &KeySnapshot{
		byHash: byHash,
		byID:   byID,
		all:    all,
	}
	m.snapshot.Store(snap)
	return nil
}

// Authenticate checks a raw Bearer key in O(1) memory lookup without touching SQLite.
func (m *Manager) Authenticate(rawKey string) (*KeyInfo, error) {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return nil, ErrInvalidKey
	}

	hash := m.HashKey(rawKey)
	snap := m.snapshot.Load()
	if snap == nil {
		return nil, ErrInvalidKey
	}

	info, exists := snap.byHash[hash]
	if !exists {
		return nil, ErrInvalidKey
	}

	// Constant-time compare on hash bytes
	if subtle.ConstantTimeCompare([]byte(info.HMACHash), []byte(hash)) != 1 {
		return nil, ErrInvalidKey
	}

	if info.Status == "revoked" || info.RevokedAt > 0 {
		return nil, ErrKeyRevoked
	}

	if info.ExpiresAt > 0 && time.Now().Unix() > info.ExpiresAt {
		return nil, ErrKeyExpired
	}

	return info, nil
}

func (m *Manager) IsModelAllowed(key *KeyInfo, model string) bool {
	if key == nil || len(key.AllowedModels) == 0 {
		return true
	}
	for _, allowed := range key.AllowedModels {
		if allowed == model {
			return true
		}
	}
	return false
}

func (m *Manager) CreateKey(name string, expiresAt int64, allowedModels []string) (*CreateKeyResult, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "default"
	}

	// Generate key ID (12 hex chars) and secret (32 bytes = 256 bits)
	idBytes := make([]byte, 6)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random id: %w", err)
	}
	keyID := hex.EncodeToString(idBytes)

	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)

	fullKey := fmt.Sprintf("sk-%s-%s", keyID, secret)
	keyPrefix := fmt.Sprintf("sk-%s...", keyID)
	hmacHash := m.HashKey(fullKey)
	now := time.Now().Unix()

	var allowedModelsJSON sql.NullString
	if len(allowedModels) > 0 {
		b, _ := json.Marshal(allowedModels)
		allowedModelsJSON = sql.NullString{String: string(b), Valid: true}
	}

	var expSQL sql.NullInt64
	if expiresAt > 0 {
		expSQL = sql.NullInt64{Int64: expiresAt, Valid: true}
	}
	encryptedKey, err := m.encryptKey(fullKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	_, err = m.db.Exec(`
		INSERT INTO downstream_keys (id, key_prefix, hmac_hash, encrypted_key, name, allowed_models, created_at, expires_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')
	`, keyID, keyPrefix, hmacHash, encryptedKey, name, allowedModelsJSON, now, expSQL)
	if err != nil {
		return nil, fmt.Errorf("failed to insert key into db: %w", err)
	}

	if err := m.reloadSnapshot(); err != nil {
		return nil, fmt.Errorf("failed to update key snapshot: %w", err)
	}

	return &CreateKeyResult{
		ID:            keyID,
		Key:           fullKey,
		KeyPrefix:     keyPrefix,
		Name:          name,
		AllowedModels: allowedModels,
		CreatedAt:     now,
		ExpiresAt:     expiresAt,
		Status:        "active",
	}, nil
}

func (m *Manager) ListKeys() []*KeyInfo {
	snap := m.snapshot.Load()
	if snap == nil {
		return []*KeyInfo{}
	}
	result := make([]*KeyInfo, len(snap.all))
	for i, k := range snap.all {
		result[i] = &KeyInfo{
			ID:            k.ID,
			KeyPrefix:     k.KeyPrefix,
			HMACHash:      "", // never expose in public struct
			Name:          k.Name,
			AllowedModels: k.AllowedModels,
			CreatedAt:     k.CreatedAt,
			ExpiresAt:     k.ExpiresAt,
			RevokedAt:     k.RevokedAt,
			Status:        k.Status,
			IsStatic:      k.IsStatic,
			CanReveal:     k.CanReveal,
		}
	}
	return result
}

func (m *Manager) DeleteKey(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrKeyNotFound
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	res, err := m.db.Exec(`DELETE FROM downstream_keys WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return ErrKeyNotFound
	}
	return m.reloadSnapshot()
}

func (m *Manager) RevokeKey(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrKeyNotFound
	}

	snap := m.snapshot.Load()
	if snap != nil {
		if k, exists := snap.byID[id]; exists && k.IsStatic {
			return ErrStaticKey
		}
	}

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	now := time.Now().Unix()
	res, err := m.db.Exec(`
		UPDATE downstream_keys
		SET status = 'revoked', revoked_at = ?
		WHERE id = ?
	`, now, id)
	if err != nil {
		return fmt.Errorf("failed to revoke key in db: %w", err)
	}
	rowsAff, err := res.RowsAffected()
	if err != nil || rowsAff == 0 {
		return ErrKeyNotFound
	}

	return m.reloadSnapshot()
}
