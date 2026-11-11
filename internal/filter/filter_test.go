package filter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kfwle/parser-go/internal/dedup"
)

func TestApply(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.txt")
	wl := filepath.Join(dir, "wl.txt")
	bl := filepath.Join(dir, "bl.txt")
	ipList := filepath.Join(dir, "ip.txt")
	sniList := filepath.Join(dir, "sni.txt")

	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(clean, "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#a\n"+
		"trojan://p@9.9.9.9:443?sni=ok.example#b\n"+
		"hy2://a@8.8.8.8:443#c\n")
	write(ipList, "1.2\n# comment\n")
	write(sniList, "ok.example\n")

	stats, err := Apply(clean, wl, bl, Options{
		FilterIP: true, FilterSNI: true, FilterOthers: true,
		IPListPath: ipList, SNIListPath: sniList,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.IPMatched != 1 || stats.SNIMatched != 1 || stats.Others != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	white, _ := dedup.ReadLines(wl)
	black, _ := dedup.ReadLines(bl)
	if len(white) != 2 || len(black) != 1 {
		t.Fatalf("white=%d black=%d", len(white), len(black))
	}
}

func TestApplyFiltersDisabled(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.txt")
	wl := filepath.Join(dir, "wl.txt")
	bl := filepath.Join(dir, "bl.txt")
	if err := os.WriteFile(clean, []byte("vless://x@h:1#a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stats, err := Apply(clean, wl, bl, Options{FilterOthers: true})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Others != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	white, _ := dedup.ReadLines(wl)
	black, _ := dedup.ReadLines(bl)
	if len(white) != 0 || len(black) != 1 {
		t.Fatalf("white=%d black=%d", len(white), len(black))
	}
}
