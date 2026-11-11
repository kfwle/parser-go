package extract

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/kfwle/parser-go/internal/model"
)

const testUUID = "11111111-2222-3333-4444-555555555555"

func TestParseVLESSRoundTrip(t *testing.T) {
	raw := "vless://" + testUUID + "@1.2.3.4:443?type=xhttp&security=reality&pbk=PUBKEY&sid=abcd&sni=example.com&fp=chrome&alpn=h2%2Chttp%2F1.1&path=%2Ffoo&host=cdn.example.com#Test%20Node"
	ep, ok := ParseVLESS(raw)
	if !ok {
		t.Fatal("parse failed")
	}
	if ep.ID != testUUID || ep.Host != "1.2.3.4" || ep.Port != 443 {
		t.Fatalf("bad endpoint: %+v", ep)
	}
	if ep.Network != "xhttp" || ep.Security != "reality" || ep.PublicKey != "PUBKEY" || ep.ShortID != "abcd" {
		t.Fatalf("bad transport: %+v", ep)
	}
	if ep.SNI != "example.com" || ep.ALPN != "h2,http/1.1" || ep.Path != "/foo" || ep.HostHeader != "cdn.example.com" {
		t.Fatalf("bad params: %+v", ep)
	}
	if ep.Tag != "Test Node" {
		t.Fatalf("bad tag: %q", ep.Tag)
	}
	again, ok := ParseVLESS(EndpointToURL(ep))
	if !ok {
		t.Fatal("roundtrip parse failed")
	}
	if again.Network != ep.Network || again.Security != ep.Security || again.SNI != ep.SNI ||
		again.PublicKey != ep.PublicKey || again.ShortID != ep.ShortID || again.Path != ep.Path {
		t.Fatalf("roundtrip mismatch:\n%+v\n%+v\n%s", ep, again, EndpointToURL(ep))
	}
}

func TestParseTrojan(t *testing.T) {
	raw := "trojan://pass%40word@5.6.7.8:8443?type=ws&security=tls&sni=t.example&path=%2Fws&host=cdn&allowInsecure=0#TJ"
	ep, ok := ParseTrojan(raw)
	if !ok {
		t.Fatal("parse failed")
	}
	if ep.ID != "pass@word" || ep.Host != "5.6.7.8" || ep.Port != 8443 {
		t.Fatalf("bad endpoint: %+v", ep)
	}
	if ep.Network != "ws" || ep.Security != "tls" || ep.SNI != "t.example" || ep.Path != "/ws" || ep.HostHeader != "cdn" {
		t.Fatalf("bad params: %+v", ep)
	}
	if ep.AllowInsecure {
		t.Fatal("allowInsecure should be false")
	}
	if u := EndpointToURL(ep); !strings.Contains(u, "allowInsecure=false") {
		t.Fatalf("lost allowInsecure: %s", u)
	}
}

func TestParseHysteria2(t *testing.T) {
	raw := "hy2://user:pass@9.9.9.9?sni=example.com&insecure=1&alpn=h3&obfs=salamander&obfs-password=pw&upmbps=100&downmbps=200#HY"
	ep, ok := ParseHysteria2(raw)
	if !ok {
		t.Fatal("parse failed")
	}
	if ep.ID != "user:pass" || ep.Port != 443 || ep.SNI != "example.com" || !ep.Insecure {
		t.Fatalf("bad endpoint: %+v", ep)
	}
	if ep.Obfs != "salamander" || ep.ObfsPassword != "pw" || ep.UpMbps != "100" || ep.DownMbps != "200" {
		t.Fatalf("bad params: %+v", ep)
	}
	again, ok := ParseHysteria2(EndpointToURL(ep))
	if !ok || again.Host != ep.Host || again.ID != ep.ID {
		t.Fatalf("roundtrip failed: %+v", again)
	}
}

func TestNormalizeAndValidate(t *testing.T) {
	got := NormalizeConfig("vless://x@h:1?b=2&a=1#tag")
	if got != "vless://x@h:1?a=1&b=2" {
		t.Fatalf("normalize: %s", got)
	}
	if !IsValidConfig("vless://" + testUUID + "@h:443") {
		t.Fatal("valid vless rejected")
	}
	if IsValidConfig("vless://h:443") {
		t.Fatal("vless without @ accepted")
	}
	if !IsValidConfig("trojan://pass@h:443") {
		t.Fatal("valid trojan rejected")
	}
	if !IsSecure("vless://x@h:1?security=reality") {
		t.Fatal("reality must be secure")
	}
	if IsSecure("vless://x@h:1?security=none") {
		t.Fatal("none must be insecure")
	}
}

func TestDedupKey(t *testing.T) {
	a := "vless://" + testUUID + "@h:443?security=tls&sni=a.com#one"
	b := "vless://" + testUUID + "@h:443?security=tls&sni=a.com#two"
	c := "vless://" + testUUID + "@h:443?security=tls&sni=b.com"
	ka, _ := DedupKey(a, true)
	kb, _ := DedupKey(b, true)
	kc, _ := DedupKey(c, true)
	if ka != kb {
		t.Fatal("same key expected")
	}
	if ka == kc {
		t.Fatal("different SNI must give different keys")
	}
	kaNoSNI, _ := DedupKey(a, false)
	kcNoSNI, _ := DedupKey(c, false)
	if kaNoSNI != kcNoSNI {
		t.Fatal("SNI must be ignored")
	}
}

func TestBase64Extraction(t *testing.T) {
	cfg := "vless://" + testUUID + "@1.2.3.4:443?security=tls#x"
	blob := base64.StdEncoding.EncodeToString([]byte(cfg + "\n"))
	decoded, matches := DecodeBase64Content(blob, 0)
	if !strings.Contains(decoded, "vless://") || len(matches) != 1 {
		t.Fatalf("decoded=%q matches=%v", decoded, matches)
	}
}

func TestJSONToURLs(t *testing.T) {
	doc := `{
	  "outbounds": [
	    {"tag":"n1","protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"` + testUUID + `","flow":"xtls-rprx-vision"}]}]},
	     "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"sni.example","alpn":["h2","http/1.1"]},"wsSettings":{"path":"/ws","headers":{"Host":"cdn.example"}}}}
	  ]
	}`
	urls := JSONToURLs(doc)
	if len(urls) != 1 {
		t.Fatalf("urls=%v", urls)
	}
	ep, ok := ParseConfig(urls[0])
	if !ok || ep.ID != testUUID || ep.SNI != "sni.example" || ep.Path != "/ws" || ep.HostHeader != "cdn.example" {
		t.Fatalf("bad converted endpoint: %+v (%s)", ep, urls[0])
	}
}

func TestYAMLToURLs(t *testing.T) {
	doc := `
proxies:
  - name: Node
    type: vless
    server: 1.2.3.4
    port: 443
    uuid: ` + testUUID + `
    network: grpc
    tls: true
    servername: sni.example
    reality-opts:
      public-key: PBK
      short-id: abcd
    grpc-opts:
      grpc-service-name: svc
`
	urls := YAMLToURLs(doc)
	if len(urls) != 1 {
		t.Fatalf("urls=%v", urls)
	}
	ep, ok := ParseConfig(urls[0])
	if !ok || ep.Network != "grpc" || ep.Security != "reality" || ep.PublicKey != "PBK" || ep.ServiceName != "svc" {
		t.Fatalf("bad converted endpoint: %+v (%s)", ep, urls[0])
	}
}

func TestExtractFromText(t *testing.T) {
	text := "hello vless://" + testUUID + "@1.2.3.4:443?security=tls#a and trojan://p@h:443#b and hy2://a@h:8443#c"
	res := ExtractFromText(text, Options{VLESS: true, Trojan: true, Hysteria2: true})
	if len(res.VLESS) != 1 || len(res.Trojan) != 1 || len(res.Hysteria2) != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	disabled := ExtractFromText(text, Options{VLESS: true})
	if len(disabled.Trojan) != 0 || len(disabled.Hysteria2) != 0 {
		t.Fatalf("disabled protocols leaked: %+v", disabled)
	}
}

func TestHostPort(t *testing.T) {
	cases := []struct {
		raw  string
		host string
		port int
	}{
		{"vless://u@1.2.3.4:443?x=1", "1.2.3.4", 443},
		{"trojan://p@[2001:db8::1]:8443#t", "2001:db8::1", 8443},
		{"hy2://a@example.com", "example.com", 443},
	}
	for _, tc := range cases {
		host, port, ok := HostPort(tc.raw)
		if !ok || host != tc.host || port != tc.port {
			t.Fatalf("%s -> %s:%d ok=%v", tc.raw, host, port, ok)
		}
	}
}

func TestAtInsideQueryDoesNotMoveHost(t *testing.T) {
	raw := "vless://" + testUUID + "@good.example:443?type=ws&path=%2Ffoo%40evil.example:8443&sni=x.example"
	ep, ok := ParseVLESS(raw)
	if !ok || ep.Host != "good.example" || ep.Port != 443 {
		t.Fatalf("bad endpoint: %+v", ep)
	}
	if ep.Path != "/foo@evil.example:8443" {
		t.Fatalf("path=%q", ep.Path)
	}
	hy2, ok := ParseHysteria2("hy2://pass@1.2.3.4:443?obfs-password=p@ss")
	if !ok || hy2.Host != "1.2.3.4" || hy2.ObfsPassword != "p@ss" {
		t.Fatalf("hy2=%+v", hy2)
	}
}

func TestCleanURLKeepsEncodedDelimiters(t *testing.T) {
	raw := "vless://" + testUUID + "@h.example:443?path=%2Fa%23b&sni=a.com#tag"
	ep, ok := ParseVLESS(raw)
	if !ok || ep.Path != "/a#b" || ep.SNI != "a.com" || ep.Tag != "tag" {
		t.Fatalf("bad endpoint: %+v", ep)
	}
}

func TestPortRangeRejected(t *testing.T) {
	jsonDocs := []string{
		`{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"h","port":70000,"users":[{"id":"` + testUUID + `"}]}]}}]}`,
		`{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"h","port":-1,"users":[{"id":"` + testUUID + `"}]}]}}]}`,
		`{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"h","port":1e19,"users":[{"id":"` + testUUID + `"}]}]}}]}`,
	}
	for _, doc := range jsonDocs {
		if urls := JSONToURLs(doc); len(urls) != 0 {
			t.Fatalf("invalid port accepted: %v", urls)
		}
	}
	yamlDoc := "proxies:\n  - name: x\n    type: vless\n    server: h\n    port: 70000\n    uuid: " + testUUID + "\n"
	if urls := YAMLToURLs(yamlDoc); len(urls) != 0 {
		t.Fatalf("invalid YAML port accepted: %v", urls)
	}
}

func TestTrojanRealityRoundTrip(t *testing.T) {
	raw := "trojan://pass@h.example:443?security=reality&pbk=PUBKEY&sid=abcd&sni=x.example"
	ep, ok := ParseTrojan(raw)
	if !ok || ep.PublicKey != "PUBKEY" || ep.ShortID != "abcd" {
		t.Fatalf("reality keys lost: %+v", ep)
	}
	out := EndpointToURL(ep)
	if !strings.Contains(out, "pbk=PUBKEY") || !strings.Contains(out, "sid=abcd") {
		t.Fatalf("serialised without reality keys: %s", out)
	}
}

func TestSNIIgnoresFragment(t *testing.T) {
	if got := ExtractSNI("trojan://p@1.2.3.4:443#&sni=allowed.example"); got != "" {
		t.Fatalf("SNI from fragment accepted: %q", got)
	}
}

func TestHostInjectionRejected(t *testing.T) {
	base := model.Endpoint{Protocol: model.VLESS, ID: testUUID, Host: "x@evil.example", Port: 443}
	if got := EndpointToURL(&base); got != "" {
		t.Fatalf("host injection accepted: %s", got)
	}
	base.Host = "x evil.example"
	if got := EndpointToURL(&base); got != "" {
		t.Fatalf("space host accepted: %s", got)
	}
}

func TestNormalizeConfigIdempotent(t *testing.T) {
	inputs := []string{"0 #", "vless://x@h:1?b=2&a=1#tag", "vless://x@h:1?b=2&a=1", "  vless://x@h:1#t  "}
	for _, in := range inputs {
		once := NormalizeConfig(in)
		twice := NormalizeConfig(once)
		if once != twice {
			t.Fatalf("not idempotent: %q -> %q -> %q", in, once, twice)
		}
	}
}
