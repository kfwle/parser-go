package app

import (
	"os"
	"testing"

	"github.com/kfwle/parser-go/internal/config"
)

func TestHasWork(t *testing.T) {
	paths := config.NewPaths(t.TempDir())
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	application := New(cfg, paths)
	if application.HasWork() {
		t.Fatal("empty templates must not count as work")
	}
	if err := os.WriteFile(paths.SourcesFile, []byte("# comment only\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if application.HasWork() {
		t.Fatal("comments must not count as work")
	}
	if err := os.WriteFile(paths.SourcesFile, []byte("https://example.com/sub\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !application.HasWork() {
		t.Fatal("a real source must count as work")
	}

	cfg.LoadSources = false
	cfg.ImportWhitelist = false
	cfg.ImportBlacklist = false
	noSources := New(cfg, paths)
	if noSources.HasWork() {
		t.Fatal("sources must be ignored when load_sources is false")
	}
}
