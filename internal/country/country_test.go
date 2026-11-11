package country

import (
	"strings"
	"testing"
)

func TestUpdateURLTagSanitizesName(t *testing.T) {
	info := &Info{Name: "Evil\nvless://2222@6.6.6.6:443#pwn", Code: "US"}
	out := UpdateURLTag("vless://1111@1.2.3.4:443", info, false)
	if strings.ContainsAny(out, "\r\n") {
		t.Fatalf("newline injected: %q", out)
	}
	if strings.Contains(out, "#pwn") {
		t.Fatalf("fragment injected: %q", out)
	}
}
