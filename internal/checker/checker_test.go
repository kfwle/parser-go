package checker

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kfwle/parser-go/internal/model"
)

func TestHysteria2ConfigIPv6(t *testing.T) {
	ep := &model.Endpoint{
		Protocol: model.Hysteria2,
		Host:     "2001:db8::1",
		Port:     8443,
		ID:       "auth",
		SNI:      "example.com",
	}
	data, err := hysteria2Config(ep, 1080)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["server"] != "[2001:db8::1]:8443" {
		t.Fatalf("server=%v", cfg["server"])
	}
}
