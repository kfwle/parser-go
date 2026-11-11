package format

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/model"
)

const testUUID = "11111111-2222-3333-4444-555555555555"

func TestGenerateAllFormats(t *testing.T) {
	dir := t.TempDir()
	paths := config.NewPaths(dir)
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	whitelist := filepath.Join(dir, "whitelist.txt")
	content := "vless://" + testUUID + "@1.2.3.4:443?type=ws&security=reality&pbk=PBK&sid=abcd&sni=sni.example&path=%2Fws&host=cdn.example#Node%20A\n" +
		"trojan://secret@5.6.7.8:8443?security=tls&sni=t.example#Node%20B\n" +
		"hy2://auth@9.9.9.9:443?sni=h.example&insecure=1#Node%20C\n"
	if err := os.WriteFile(whitelist, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.SaveClash = true
	cfg.SaveXray = true
	cfg.SaveSingbox = true
	New(paths, cfg).GenerateAll(whitelist, "")

	var clash struct {
		Proxies []map[string]any `yaml:"proxies"`
		Rules   []string         `yaml:"rules"`
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
	names := make(map[string]bool)
	for _, p := range clash.Proxies {
		name, _ := p["name"].(string)
		if names[name] {
			t.Fatalf("duplicate proxy name %q", name)
		}
		names[name] = true
		switch p["type"] {
		case "vless":
			if p["tls"] != true {
				t.Fatalf("vless reality must have tls: true, got %v", p["tls"])
			}
		case "hysteria2":
			if _, exists := p["tls"]; exists {
				t.Fatalf("hysteria2 must not have a tls key: %v", p)
			}
		}
	}
	if len(clash.Rules) != 1 {
		t.Fatalf("clash rules=%v", clash.Rules)
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

	var singbox struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	sbData, err := os.ReadFile(filepath.Join(paths.SingboxDir, "whitelist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(sbData, &singbox); err != nil {
		t.Fatal(err)
	}
	if len(singbox.Outbounds) != 3 {
		t.Fatalf("singbox outbounds=%d", len(singbox.Outbounds))
	}
	if singbox.Outbounds[0]["type"] != "vless" || singbox.Outbounds[1]["type"] != "trojan" || singbox.Outbounds[2]["type"] != "hysteria2" {
		t.Fatalf("unexpected types: %v", singbox.Outbounds)
	}
}

func TestProxyNameUniqueAndCommaFree(t *testing.T) {
	seen := map[string]int{}
	ep := &model.Endpoint{Protocol: model.VLESS, Tag: "a,b", Host: "host"}
	name1 := proxyName(ep, 1, seen)
	name2 := proxyName(ep, 1, seen)
	if name1 == name2 {
		t.Fatalf("names must be unique: %q", name1)
	}
	if strings.Contains(name1, ",") {
		t.Fatalf("comma must be removed: %q", name1)
	}
}
