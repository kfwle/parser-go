package outbound

import (
	"testing"

	"github.com/kfwle/parser-go/internal/model"
)

func TestXrayExcludesHysteria2(t *testing.T) {
	ep := &model.Endpoint{Protocol: model.Hysteria2, Host: "h", Port: 443, ID: "auth"}
	if ob := Xray(ep, "x"); ob != nil {
		t.Fatalf("Xray must not emit hysteria2 outbounds: %v", ob)
	}
}

func TestSingboxTrojanWithoutTLS(t *testing.T) {
	ep := &model.Endpoint{Protocol: model.Trojan, Host: "h", Port: 443, ID: "p", Security: "none"}
	ob := Singbox(ep, "x")
	tls := ob["tls"].(map[string]any)
	if tls["enabled"] != false {
		t.Fatalf("tls enabled for plaintext trojan: %v", tls)
	}
}
