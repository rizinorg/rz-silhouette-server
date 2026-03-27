package main

import (
	"crypto/sha256"
	"fmt"
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
