package main

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSharedDBFilenameUsesSHA256(t *testing.T) {
	got := sharedDBFilename("/tmp/share", "demo-psk")
	want := filepath.Join("/tmp/share", fmt.Sprintf("%x.db", sha256.Sum256([]byte("demo-psk"))))
	if got != want {
		t.Fatalf("sharedDBFilename() = %q, want %q", got, want)
	}
}

func TestLegacySharedDBFilenameUsesMD5(t *testing.T) {
	got := legacySharedDBFilename("/tmp/share", "demo-psk")
	want := filepath.Join("/tmp/share", fmt.Sprintf("%x.db", md5.Sum([]byte("demo-psk"))))
	if got != want {
		t.Fatalf("legacySharedDBFilename() = %q, want %q", got, want)
	}
}

func TestLoadResourcesMigratesLegacySharedDBFilename(t *testing.T) {
	dir := t.TempDir()
	psk := "demo-psk"
	legacyPath := legacySharedDBFilename(dir, psk)
	db, err := OpenDatabase(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	cfg := &Config{
		MaxQueue:   1024,
		MaxPacket:  1024 * 1024,
		LogLevel:   "warn",
		UploadDir:  dir,
		Authorized: map[string]bool{psk: true},
	}

	_, shared := cfg.LoadResources()
	sharedDB := shared[psk]
	if sharedDB == nil {
		t.Fatal("expected shared db to be opened")
	}
	t.Cleanup(func() {
		sharedDB.Close()
	})

	currentPath := sharedDBFilename(dir, psk)
	if !exists(currentPath) {
		t.Fatalf("expected migrated db at %q", currentPath)
	}
	if exists(legacyPath) {
		t.Fatalf("expected legacy db %q to be migrated away", legacyPath)
	}
	if _, err := os.Stat(currentPath); err != nil {
		t.Fatalf("expected migrated db to be readable: %v", err)
	}
}
