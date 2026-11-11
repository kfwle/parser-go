package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMergesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"verbose":false,"http_threads":7,"save_clash":false}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Verbose || cfg.HTTPThreads != 7 || cfg.SaveClash {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if !cfg.SaveXray || !cfg.UseDedup || cfg.CheckTimeout != 12 {
		t.Fatalf("defaults lost: %+v", cfg)
	}
}

func TestSaveAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := Default()
	cfg.HTTPThreads = 9
	cfg.UseTelegram = true
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.HTTPThreads != 9 || !loaded.UseTelegram {
		t.Fatalf("roundtrip failed: %+v", loaded)
	}
}

func TestNormalizeClamps(t *testing.T) {
	cfg := Default()
	cfg.HTTPThreads = 10000
	cfg.CheckThreads = 0
	cfg.CheckTimeout = 1
	cfg.TGMessagesLimit = 1
	cfg.Normalize()
	if cfg.HTTPThreads != 200 || cfg.CheckThreads != 1 || cfg.CheckTimeout != 3 || cfg.TGMessagesLimit != 20 {
		t.Fatalf("clamps failed: %+v", cfg)
	}
}

func TestPaths(t *testing.T) {
	p := NewPaths("/tmp/parser-test")
	if p.ConfigFile != "/tmp/parser-test/config.json" {
		t.Fatalf("config path: %s", p.ConfigFile)
	}
	if p.WhitelistFile != "/tmp/parser-test/configs/generic/whitelist.txt" {
		t.Fatalf("whitelist path: %s", p.WhitelistFile)
	}
}
