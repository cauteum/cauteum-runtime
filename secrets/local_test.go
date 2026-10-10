package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalEncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.PutProviderCredentials(ctx, "cursor", map[string]string{"CURSOR_API_KEY": "crsr_test"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetProviderCredentials(ctx, "cursor", []string{"CURSOR_API_KEY", "MISSING"})
	if err != nil {
		t.Fatal(err)
	}
	if got["CURSOR_API_KEY"] != "crsr_test" {
		t.Fatalf("got %#v", got)
	}
	if _, ok := got["MISSING"]; ok {
		t.Fatal("missing should be omitted")
	}
	s2, err := OpenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s2.Get(ctx, ProviderKey("cursor", "CURSOR_API_KEY"))
	if err != nil || v != "crsr_test" {
		t.Fatalf("reopen: %q %v", v, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, FileStore))
	if strings.Contains(string(raw), "crsr_test") {
		t.Fatal("plaintext leaked into secrets.enc.json")
	}
}

func TestLegacyStoreMigratesAtomicallyToPasswordKDF(t *testing.T) {
	dir := t.TempDir()
	password := "legacy-short"
	t.Setenv(EnvKEK, password)
	block, err := aes.NewCipher(DeriveKEK([]byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	encoded := base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte("secret"), nil))
	legacy, err := json.Marshal(diskBlob{Version: 1, Entries: map[string]string{"key": encoded}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, FileStore)
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(context.Background(), "key"); err != nil || got != "secret" {
		t.Fatalf("migrated value: %q %v", got, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var blob diskBlob
	if err := json.Unmarshal(raw, &blob); err != nil || blob.Version != 2 || blob.Salt == "" {
		t.Fatalf("expected salted v2 store: %+v, %v", blob, err)
	}
	if _, err := OpenLocal(dir); err != nil {
		t.Fatalf("reopen migrated store: %v", err)
	}
	t.Setenv(EnvKEK, "different-password-material")
	if _, err := OpenLocal(dir); err == nil {
		t.Fatal("wrong password unexpectedly decrypted migrated store")
	}
}

func TestFreshStoreRejectsShortPassword(t *testing.T) {
	t.Setenv(EnvKEK, "short")
	if _, err := OpenLocal(t.TempDir()); err == nil {
		t.Fatal("new store accepted short password")
	}
}
