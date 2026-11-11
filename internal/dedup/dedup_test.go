package dedup

import (
	"os"
	"path/filepath"
	"testing"
)

const uuid = "11111111-2222-3333-4444-555555555555"

func TestDeduplicate(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "in.txt")
	output := filepath.Join(dir, "out.txt")
	content := "vless://" + uuid + "@1.2.3.4:443?security=tls#one\n" +
		"vless://" + uuid + "@1.2.3.4:443?security=tls#two\n" +
		"trojan://pass@5.6.7.8:443?sni=a.com#t\n" +
		"garbage line\n" +
		"trojan://pass@5.6.7.8:443?sni=a.com#t2\n"
	if err := os.WriteFile(input, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	unique, err := Deduplicate(input, output, true)
	if err != nil {
		t.Fatal(err)
	}
	if unique != 2 {
		t.Fatalf("unique=%d, want 2", unique)
	}
	lines, err := ReadLines(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0] != "vless://"+uuid+"@1.2.3.4:443?security=tls#one" {
		t.Fatalf("unexpected output: %v", lines)
	}
}
