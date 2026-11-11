package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kfwle/parser-go/internal/config"
)

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMigrate(t *testing.T) {
	from := t.TempDir()
	writeTestFile(t, filepath.Join(from, "sources", "sources.txt"), "https://example.com/sub\n")
	writeTestFile(t, filepath.Join(from, "configs", "generic", "whitelist.txt"), "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#a\n")
	writeTestFile(t, filepath.Join(from, "config.json"), `{"verbose":false,"http_threads":7}`)

	to := t.TempDir()
	paths := config.NewPaths(to)
	report, err := Migrate(from, paths, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Copied) != 3 {
		t.Fatalf("copied=%v skipped=%v", report.Copied, report.Skipped)
	}
	data, err := os.ReadFile(paths.SourcesFile)
	if err != nil || string(data) != "https://example.com/sub\n" {
		t.Fatalf("sources content=%q err=%v", data, err)
	}
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil || cfg.HTTPThreads != 7 || cfg.Verbose {
		t.Fatalf("config not migrated: %+v err=%v", cfg, err)
	}

	// A second run must not overwrite real data.
	report, err = Migrate(from, paths, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Copied) != 0 {
		t.Fatalf("second run copied=%v", report.Copied)
	}

	// Force overwrites everything.
	writeTestFile(t, filepath.Join(from, "sources", "sources.txt"), "https://example.com/new\n")
	report, err = Migrate(from, paths, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Copied) == 0 {
		t.Fatal("force migration copied nothing")
	}
	data, _ = os.ReadFile(paths.SourcesFile)
	if !strings.Contains(string(data), "/new") {
		t.Fatalf("force did not overwrite: %q", data)
	}
}

func TestMigrateInvalidSource(t *testing.T) {
	to := config.NewPaths(t.TempDir())
	if _, err := Migrate(t.TempDir(), to, false); err == nil {
		t.Fatal("migration from a non-parser directory must fail")
	}
}
