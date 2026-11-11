// Package format writes Clash, Xray and sing-box files from URL lists.
package format

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/dedup"
	"github.com/kfwle/parser-go/internal/extract"
	"github.com/kfwle/parser-go/internal/logx"
	"github.com/kfwle/parser-go/internal/model"
	"github.com/kfwle/parser-go/internal/outbound"
)

// Generator writes output files into configs/.
type Generator struct {
	Paths *config.Paths
	Cfg   config.Config
}

// New creates a format generator.
func New(paths *config.Paths, cfg config.Config) *Generator {
	return &Generator{Paths: paths, Cfg: cfg}
}

// GenerateAll converts whitelist and blacklist files into all enabled formats.
func (g *Generator) GenerateAll(whitelistPath, blacklistPath string) {
	for _, item := range []struct{ label, src string }{
		{"whitelist", whitelistPath},
		{"blacklist", blacklistPath},
	} {
		if err := g.Generate(item.label, item.src); err != nil {
			logx.Printf("  [%s] %v\n", item.label, err)
		}
	}
}

type namedEndpoint struct {
	ep   *model.Endpoint
	name string
}

// Generate converts one URL list into the enabled formats.
func (g *Generator) Generate(label, src string) error {
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("файл не найден: %s", src)
	}
	lines, err := dedup.ReadLines(src)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return fmt.Errorf("файл пуст, пропускаем")
	}
	logx.Printf("\n  Конвертация %s (%d конфигов)\n", label, len(lines))

	items := make([]namedEndpoint, 0, len(lines))
	seenNames := make(map[string]int)
	failed := 0
	for i, line := range lines {
		ep, ok := extract.ParseConfig(line)
		if !ok {
			failed++
			continue
		}
		items = append(items, namedEndpoint{ep: ep, name: proxyName(ep, i+1, seenNames)})
	}
	if failed > 0 {
		logx.Printf("  [%s] не удалось распарсить: %d\n", label, failed)
	}
	if len(items) == 0 {
		return fmt.Errorf("ни один конфиг не распарсился, пропускаем")
	}

	if g.Cfg.SaveClash {
		proxies := make([]clashProxy, 0, len(items))
		for _, it := range items {
			if p, ok := toClash(it.ep, it.name); ok {
				proxies = append(proxies, p)
			}
		}
		if err := g.writeClash(label, proxies); err != nil {
			return err
		}
	}
	if g.Cfg.SaveXray {
		outbounds := make([]any, 0, len(items))
		for _, it := range items {
			if ob := outbound.Xray(it.ep, it.name); ob != nil {
				outbounds = append(outbounds, ob)
			}
		}
		if err := g.writeXray(label, outbounds); err != nil {
			return err
		}
	}
	if g.Cfg.SaveSingbox {
		outbounds := make([]any, 0, len(items))
		for _, it := range items {
			if ob := outbound.Singbox(it.ep, it.name); ob != nil {
				outbounds = append(outbounds, ob)
			}
		}
		if err := g.writeSingbox(label, outbounds); err != nil {
			return err
		}
	}
	return nil
}

// proxyName builds a readable, unique proxy name. Commas are removed because
// they break Clash MATCH rules.
func proxyName(ep *model.Endpoint, idx int, seen map[string]int) string {
	tag := strings.TrimSpace(ep.Tag)
	base := ""
	switch strings.ToLower(tag) {
	case "", "vless", "trojan", "hy2", "hysteria2":
		base = fmt.Sprintf("%s-%s", ep.Label(), ep.Host)
	default:
		base = tag
	}
	base = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ',' {
			return ' '
		}
		return r
	}, base)
	base = strings.TrimSpace(base)
	if base == "" {
		base = ep.Label()
	}
	name := fmt.Sprintf("%s #%03d", base, idx)
	if seen == nil {
		return name
	}
	if count, exists := seen[name]; exists {
		for {
			count++
			candidate := fmt.Sprintf("%s #%03d-%d", base, idx, count)
			if _, used := seen[candidate]; !used {
				seen[candidate] = 1
				return candidate
			}
		}
	}
	seen[name] = 1
	return name
}

// --- Clash ---

type clashReality struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id,omitempty"`
}

type clashWS struct {
	Path    string            `yaml:"path,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
}

type clashGRPC struct {
	ServiceName string `yaml:"grpc-service-name,omitempty"`
}

type clashProxy struct {
	Name              string        `yaml:"name"`
	Type              string        `yaml:"type"`
	Server            string        `yaml:"server"`
	Port              int           `yaml:"port"`
	UUID              string        `yaml:"uuid,omitempty"`
	Password          string        `yaml:"password,omitempty"`
	UDP               bool          `yaml:"udp"`
	Encryption        string        `yaml:"encryption,omitempty"`
	Network           string        `yaml:"network,omitempty"`
	TLS               *bool         `yaml:"tls,omitempty"`
	Servername        string        `yaml:"servername,omitempty"`
	ClientFingerprint string        `yaml:"client-fingerprint,omitempty"`
	RealityOpts       *clashReality `yaml:"reality-opts,omitempty"`
	Flow              string        `yaml:"flow,omitempty"`
	WSOpts            *clashWS      `yaml:"ws-opts,omitempty"`
	GRPCOpts          *clashGRPC    `yaml:"grpc-opts,omitempty"`
	SNI               string        `yaml:"sni,omitempty"`
	SkipCertVerify    bool          `yaml:"skip-cert-verify,omitempty"`
	Obfs              string        `yaml:"obfs,omitempty"`
	ObfsPassword      string        `yaml:"obfs-password,omitempty"`
	ALPN              []string      `yaml:"alpn,omitempty"`
	Up                string        `yaml:"up,omitempty"`
	Down              string        `yaml:"down,omitempty"`
}

type clashGroup struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
}

type clashConfig struct {
	MixedPort   int          `yaml:"mixed-port"`
	AllowLan    bool         `yaml:"allow-lan"`
	Mode        string       `yaml:"mode"`
	LogLevel    string       `yaml:"log-level"`
	Proxies     []clashProxy `yaml:"proxies"`
	ProxyGroups []clashGroup `yaml:"proxy-groups"`
	Rules       []string     `yaml:"rules"`
}

func toClash(ep *model.Endpoint, name string) (clashProxy, bool) {
	p := clashProxy{Name: name, UDP: true}
	switch ep.Protocol {
	case model.VLESS:
		p.Type = "vless"
		p.Server = ep.Host
		p.Port = ep.Port
		p.UUID = ep.ID
		p.Encryption = firstNonEmpty(ep.Encryption, "none")
		tls := ep.Security == "tls" || ep.Security == "reality"
		p.TLS = &tls
		p.Servername = firstNonEmpty(ep.SNI, ep.Host)
		p.ClientFingerprint = firstNonEmpty(ep.Fingerprint, "chrome")
		if ep.ALPN != "" {
			p.ALPN = outbound.SplitALPN(ep.ALPN)
		}
		p.Flow = ep.Flow
		if ep.Security == "reality" {
			if ep.PublicKey == "" {
				return clashProxy{}, false
			}
			p.RealityOpts = &clashReality{PublicKey: ep.PublicKey, ShortID: ep.ShortID}
		}
		applyClashTransport(&p, ep)
	case model.Trojan:
		p.Type = "trojan"
		p.Server = ep.Host
		p.Port = ep.Port
		p.Password = ep.ID
		tls := ep.Security == "tls"
		p.TLS = &tls
		p.Servername = firstNonEmpty(ep.SNI, ep.Host)
		p.ClientFingerprint = ep.Fingerprint
		if ep.ALPN != "" {
			p.ALPN = outbound.SplitALPN(ep.ALPN)
		}
		applyClashTransport(&p, ep)
	case model.Hysteria2:
		p.Type = "hysteria2"
		p.Server = ep.Host
		p.Port = ep.Port
		p.Password = ep.ID
		p.SNI = ep.SNI
		p.SkipCertVerify = ep.Insecure
		if ep.Obfs == "salamander" && ep.ObfsPassword != "" {
			p.Obfs = "salamander"
			p.ObfsPassword = ep.ObfsPassword
		}
		if ep.ALPN != "" && ep.ALPN != "h3" {
			p.ALPN = outbound.SplitALPN(ep.ALPN)
		}
		p.Up = ep.UpMbps
		p.Down = ep.DownMbps
	default:
		return clashProxy{}, false
	}
	return p, true
}

func applyClashTransport(p *clashProxy, ep *model.Endpoint) {
	switch strings.ToLower(ep.Network) {
	case "ws", "websocket":
		p.Network = "ws"
		if ep.Path != "" || ep.HostHeader != "" {
			ws := &clashWS{Path: ep.Path}
			if ep.HostHeader != "" {
				ws.Headers = map[string]string{"Host": ep.HostHeader}
			}
			p.WSOpts = ws
		}
	case "grpc":
		p.Network = "grpc"
		if ep.ServiceName != "" {
			p.GRPCOpts = &clashGRPC{ServiceName: ep.ServiceName}
		}
	case "tcp", "":
		// no network key
	default:
		p.Network = ep.Network
	}
}

func (g *Generator) writeClash(label string, proxies []clashProxy) error {
	path := filepath.Join(g.Paths.ClashDir, label+".yaml")
	if len(proxies) == 0 {
		_ = os.Remove(path)
		return nil
	}
	names := make([]string, 0, len(proxies))
	for _, p := range proxies {
		names = append(names, p.Name)
	}
	rule := "MATCH,DIRECT"
	if len(names) > 0 {
		rule = "MATCH," + names[0]
	}
	cfg := clashConfig{
		MixedPort: 7890,
		AllowLan:  false,
		Mode:      "rule",
		LogLevel:  "warning",
		Proxies:   proxies,
		ProxyGroups: []clashGroup{{
			Name: "ВЫБОР СЕРВЕРА", Type: "select", Proxies: names,
		}},
		Rules: []string{rule},
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(g.Paths.ClashDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return err
	}
	logx.Printf("    %s -> %s (%d proxies)\n", label, path, len(proxies))
	return nil
}

func (g *Generator) writeXray(label string, outbounds []any) error {
	path := filepath.Join(g.Paths.XrayDir, label+".json")
	if len(outbounds) == 0 {
		_ = os.Remove(path)
		return nil
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"port": 1080, "listen": "127.0.0.1", "protocol": "socks", "tag": "socks-in",
		}},
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "AsIs"},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(g.Paths.XrayDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return err
	}
	logx.Printf("    %s -> %s (%d outbounds)\n", label, path, len(outbounds))
	return nil
}

func (g *Generator) writeSingbox(label string, outbounds []any) error {
	path := filepath.Join(g.Paths.SingboxDir, label+".json")
	if len(outbounds) == 0 {
		_ = os.Remove(path)
		return nil
	}
	data, err := json.MarshalIndent(map[string]any{"outbounds": outbounds}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(g.Paths.SingboxDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return err
	}
	logx.Printf("    %s -> %s (%d outbounds)\n", label, path, len(outbounds))
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
