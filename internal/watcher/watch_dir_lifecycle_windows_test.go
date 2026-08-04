// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package watcher

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCleanupOwnedWatchDirsPreservesJunctionReplacement(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "plugins")
	created, err := createWatchDir(target)
	if err != nil {
		t.Fatalf("create watch directory: %v", err)
	}

	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", target, outside).CombinedOutput()
	if err != nil {
		t.Skipf("junction creation unavailable: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove junction: %v", err)
		}
	})

	if err := cleanupOwnedWatchDirs(created); err != nil {
		t.Fatalf("clean watch directories: %v", err)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("junction replacement was removed: %v", err)
	}
	if !watchDirIsLinkOrReparse(target, info) {
		t.Fatal("junction replacement was not recognized as a reparse point")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep" {
		t.Fatalf("outside content changed: %q, %v", got, err)
	}
}
