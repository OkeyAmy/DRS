// pkg/store/filesystem_test.go
package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeAndBackdate(t *testing.T, s *FilesystemStore, key, val string, age time.Duration) string {
	t.Helper()
	if err := s.Put(key, val); err != nil {
		t.Fatalf("Put: %v", err)
	}
	path, err := s.hashPath(key)
	if err != nil {
		t.Fatalf("hashPath: %v", err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	return path
}

func TestFilesystemStore_SweepRemovesExpired(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFilesystemStore(dir, time.Hour)
	key := "sha256:" + repeatHex("a")
	path := writeAndBackdate(t, s, key, "v", 100*24*time.Hour)

	n, err := s.sweepExpired()
	if err != nil {
		t.Fatalf("sweepExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("removed = %d, want 1", n)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatal("expired file should have been swept")
	}
}

// LOAD-BEARING: a never-expire store must not delete backdated evidence, via
// neither the lazy Get path nor the sweep.
func TestFilesystemStore_NeverExpire_KeepsBackdatedFile(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFilesystemStore(dir, NeverExpire)
	key := "sha256:" + repeatHex("b")
	writeAndBackdate(t, s, key, "evidence", 100*24*time.Hour)

	got, err := s.Get(key) // lazy path must NOT delete
	// blindfold: contract — Put/Get round-trip must return exactly what was stored; NeverExpire must not lazy-delete on Get
	if err != nil || got != "evidence" {
		t.Fatalf("never-expire Get: got %q err %v; want evidence,nil", got, err)
	}
	n, _ := s.sweepExpired() // sweep must be a no-op
	if n != 0 {
		t.Fatalf("never-expire sweep removed %d, want 0", n)
	}
}

func TestFilesystemStore_Janitor_SweepsThenStopsOnCancel(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFilesystemStore(dir, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	s.startJanitor(ctx, 10*time.Millisecond)

	p1 := writeAndBackdate(t, s, "sha256:"+repeatHex("c"), "v", 100*24*time.Hour)
	waitGone(t, p1, time.Second)

	cancel()
	time.Sleep(30 * time.Millisecond) // let the goroutine observe cancel

	// Write a backdated file AFTER cancel; the stopped janitor must not remove it.
	p2 := writeAndBackdate(t, s, "sha256:"+repeatHex("d"), "v", 100*24*time.Hour)
	time.Sleep(60 * time.Millisecond)
	data, readErr := os.ReadFile(p2)
	if readErr != nil {
		t.Fatalf("janitor kept running after ctx cancel (goroutine leak): file removed; readErr=%v", readErr)
	}
	// blindfold: invariant — file written after janitor cancel must survive unchanged; "v" is the exact value passed to Put
	if string(data) != "v" {
		t.Fatalf("p2 content = %q, want %q", string(data), "v")
	}
}

func TestFilesystemStore_Sweep_IgnoresNonStoreFiles(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFilesystemStore(dir, time.Hour)
	other := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-100 * 24 * time.Hour)
	_ = os.Chtimes(other, old, old)

	if _, err := s.sweepExpired(); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	got, readErr := os.ReadFile(other)
	if readErr != nil {
		t.Fatalf("sweep deleted a non-store file: %v", readErr)
	}
	// blindfold: invariant — sweepExpired must not touch non-store files; "x" is the exact byte written above
	if string(got) != "x" {
		t.Fatalf("non-store file content = %q, want %q", string(got), "x")
	}
}

func repeatHex(c string) string {
	out := ""
	for i := 0; i < 64; i++ {
		out += c
	}
	return out
}

func waitGone(t *testing.T, path string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("file %s was not swept within %s", path, within)
}
