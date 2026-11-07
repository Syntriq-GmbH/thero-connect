//go:build e2e

package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestE2E(t *testing.T) {
	link := os.Getenv("SMB_E2E_URL")
	if link == "" {
		t.Skip("SMB_E2E_URL is not set")
	}
	token := os.Getenv("SMB_E2E_TOKEN")
	seconds, err := strconv.Atoi(os.Getenv("SMB_E2E_SECONDS"))
	if err != nil {
		seconds = 900
	}
	sum := sha256.Sum256([]byte(link + token))
	dir := filepath.Join(os.TempDir(), "thero-connect-e2e-"+hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("roots:\n  - id: docs\n    path: \\\\fake\\docs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := readIdentity(dir); err != nil {
		machine, err := enroll(t.Context(), dir, cfg, link, os.Getenv("SMB_E2E_CA"), token)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("enrolled as %s", machine)
	}
	alice, bob := "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	src := newFakeSource()
	src.add(`\\fake\docs\alice\plan.txt`, "Alice only: kestrel-7341", readable(alice))
	src.add(`\\fake\docs\shared\handbook.txt`, "Shared handbook: heron-2958", readable(alice, bob))
	src.accountList = []Account{
		{SID: alice, GUID: "6f1c2b3a-4d5e-4f60-8172-93a4b5c6d001", UPN: os.Getenv("SMB_E2E_ALICE"), Mail: os.Getenv("SMB_E2E_ALICE"), Enabled: true},
		{SID: bob, GUID: "6f1c2b3a-4d5e-4f60-8172-93a4b5c6d002", UPN: os.Getenv("SMB_E2E_BOB"), Mail: os.Getenv("SMB_E2E_BOB"), Enabled: true},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	if err := serve(ctx, dir, cfg, src); err != nil {
		t.Fatal(err)
	}
}
