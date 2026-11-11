package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/dedup"
	"github.com/kfwle/parser-go/internal/logx"
)

func TestRunOnceIntegration(t *testing.T) {
	logx.SetVerbose(false)
	plain := "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&pbk=PBK&sid=abcd&sni=a.example#First\n" +
		"vless://22222222-2222-3333-4444-555555555555@1.2.4.5:443?security=tls&sni=b.example#Second\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(
		"vless://33333333-2222-3333-4444-555555555555@1.2.5.6:443?security=tls&sni=c.example#Third\n"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/b64" {
			_, _ = w.Write([]byte(encoded))
			return
		}
		_, _ = w.Write([]byte(plain))
	}))
	defer server.Close()

	dir := t.TempDir()
	paths := config.NewPaths(dir)
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.SourcesFile, []byte(server.URL+"/plain\n"+server.URL+"/b64\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.IPListFile, []byte("1.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Verbose = false
	cfg.UseTelegram = false
	cfg.ImportWhitelist = false
	cfg.ImportBlacklist = false
	cfg.FixGithubURLs = false
	cfg.SaveFailedSource = false
	cfg.UseDedup = true
	cfg.FilterIP = true
	cfg.FilterSNI = false
	cfg.FilterOthers = true
	cfg.CheckWhitelist = true
	cfg.CheckBlacklist = false
	cfg.CheckViaXray = false
	cfg.TCPCheck = false
	cfg.DetermineCountry = false
	cfg.SaveGarbage = false
	cfg.SaveClash = true
	cfg.SaveXray = true
	cfg.SaveSingbox = true
	cfg.HTTPThreads = 2

	if err := New(cfg, paths).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	configs, err := dedup.ReadLines(paths.ConfigsFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 3 {
		t.Fatalf("configs=%d: %v", len(configs), configs)
	}
	white, err := dedup.ReadLines(paths.WhitelistFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(white) != 3 {
		t.Fatalf("whitelist=%d: %v", len(white), white)
	}
	clean, _ := dedup.ReadLines(paths.CleanFile)
	if len(clean) != 3 {
		t.Fatalf("clean=%d", len(clean))
	}
	wlFiltered, _ := dedup.ReadLines(paths.WLFilteredFile)
	if len(wlFiltered) != 3 {
		t.Fatalf("wl_filtered=%d", len(wlFiltered))
	}

	var clash struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	clashData, err := os.ReadFile(filepath.Join(paths.ClashDir, "whitelist.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(clashData, &clash); err != nil {
		t.Fatal(err)
	}
	if len(clash.Proxies) != 3 {
		t.Fatalf("clash proxies=%d", len(clash.Proxies))
	}

	var xray struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	xrayData, err := os.ReadFile(filepath.Join(paths.XrayDir, "whitelist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(xrayData, &xray); err != nil {
		t.Fatal(err)
	}
	if len(xray.Outbounds) != 3 {
		t.Fatalf("xray outbounds=%d", len(xray.Outbounds))
	}
}
