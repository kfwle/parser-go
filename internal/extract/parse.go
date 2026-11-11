package extract

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/kfwle/parser-go/internal/model"
)

var validNetworks = map[string]bool{
	"tcp": true, "ws": true, "websocket": true, "httpupgrade": true,
	"xhttp": true, "grpc": true, "h2": true, "kcp": true, "quic": true,
}

// ParseVLESS parses a vless:// URL.
func ParseVLESS(raw string) (*model.Endpoint, bool) {
	s := CleanURL(raw)
	if !strings.HasPrefix(strings.ToLower(s), "vless://") {
		return nil, false
	}
	main, tag := splitFragment(s)
	rest := main[len("vless://"):]
	at := strings.LastIndexByte(rest, '@')
	if at < 0 {
		return nil, false
	}
	userinfo := rest[:at]
	hostport, query := splitQuery(rest[at+1:])
	host, port, ok := parseHostPortStrict(hostport)
	if !ok {
		return nil, false
	}
	uuid, err := url.PathUnescape(userinfo)
	if err != nil || uuid == "" {
		return nil, false
	}
	q := parseQueryValues(query)

	network := strings.ToLower(getDefault(q, "type", "tcp"))
	if network == "raw" {
		network = "tcp"
	}
	if !validNetworks[network] {
		network = "tcp"
	}
	security := strings.ToLower(getDefault(q, "security", "none"))
	if security != "tls" && security != "reality" && security != "none" {
		security = "none"
	}
	pbk := getDefault(q, "pbk", "")
	if pbk != "" && security == "tls" {
		security = "reality"
	}
	if tag == "" {
		tag = "vless"
	}
	return &model.Endpoint{
		Protocol:      model.VLESS,
		Tag:           tag,
		ID:            uuid,
		Host:          host,
		Port:          port,
		Network:       network,
		Security:      security,
		Path:          getDefault(q, "path", ""),
		HostHeader:    getDefault(q, "host", ""),
		SNI:           getDefault(q, "sni", ""),
		Fingerprint:   getDefault(q, "fp", "chrome"),
		ALPN:          getDefault(q, "alpn", ""),
		ServiceName:   getDefault(q, "serviceName", ""),
		Flow:          getDefault(q, "flow", ""),
		HeaderType:    getDefault(q, "headerType", ""),
		QUICSecurity:  getDefault(q, "quicSecurity", ""),
		Key:           getDefault(q, "key", ""),
		PublicKey:     pbk,
		ShortID:       getDefault(q, "sid", ""),
		AllowInsecure: parseBool(getDefault(q, "allowInsecure", "true")),
	}, true
}

// ParseTrojan parses a trojan:// URL.
func ParseTrojan(raw string) (*model.Endpoint, bool) {
	s := CleanURL(raw)
	if !strings.HasPrefix(strings.ToLower(s), "trojan://") {
		return nil, false
	}
	main, tag := splitFragment(s)
	rest := main[len("trojan://"):]
	at := strings.LastIndexByte(rest, '@')
	if at < 0 {
		return nil, false
	}
	userinfo := rest[:at]
	hostport, query := splitQuery(rest[at+1:])
	host, port, ok := parseHostPortStrict(hostport)
	if !ok {
		return nil, false
	}
	password, err := url.PathUnescape(userinfo)
	if err != nil || password == "" {
		return nil, false
	}
	q := parseQueryValues(query)

	network := strings.ToLower(getDefault(q, "type", "tcp"))
	if network == "raw" {
		network = "tcp"
	}
	if !validNetworks[network] {
		network = "tcp"
	}
	security := strings.ToLower(getDefault(q, "security", "tls"))
	if security != "tls" && security != "none" && security != "reality" {
		security = "tls"
	}
	if tag == "" {
		tag = "trojan"
	}
	return &model.Endpoint{
		Protocol:      model.Trojan,
		Tag:           tag,
		ID:            password,
		Host:          host,
		Port:          port,
		Network:       network,
		Security:      security,
		Path:          getDefault(q, "path", ""),
		HostHeader:    getDefault(q, "host", ""),
		SNI:           getDefault(q, "sni", ""),
		Fingerprint:   getDefault(q, "fp", "chrome"),
		ALPN:          getDefault(q, "alpn", ""),
		ServiceName:   getDefault(q, "serviceName", ""),
		HeaderType:    getDefault(q, "headerType", ""),
		QUICSecurity:  getDefault(q, "quicSecurity", ""),
		Key:           getDefault(q, "key", ""),
		AllowInsecure: parseBool(getDefault(q, "allowInsecure", "true")),
	}, true
}

// ParseHysteria2 parses a hysteria2:// or hy2:// URL.
func ParseHysteria2(raw string) (*model.Endpoint, bool) {
	s := CleanURL(raw)
	lower := strings.ToLower(s)
	var rest string
	switch {
	case strings.HasPrefix(lower, "hysteria2://"):
		rest = s[len("hysteria2://"):]
	case strings.HasPrefix(lower, "hy2://"):
		rest = s[len("hy2://"):]
	default:
		return nil, false
	}
	main, tag := splitFragment(rest)
	auth := ""
	if at := strings.LastIndexByte(main, '@'); at >= 0 {
		authRaw := main[:at]
		main = main[at+1:]
		if un, err := url.PathUnescape(authRaw); err == nil {
			auth = un
		} else {
			auth = authRaw
		}
	}
	hostport, query := splitQuery(main)
	host, port, err := splitHostPort(hostport)
	if err != nil {
		host = strings.Trim(hostport, "[]")
		port = "443"
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		portNum = 443
	}
	if host == "" {
		return nil, false
	}
	q := parseQueryValues(query)
	if tag == "" {
		tag = "hy2"
	}
	return &model.Endpoint{
		Protocol:      model.Hysteria2,
		Tag:           tag,
		ID:            auth,
		Auth:          auth,
		Host:          host,
		Port:          portNum,
		SNI:           getDefault(q, "sni", host),
		Insecure:      parseBool(getDefault(q, "insecure", "true")),
		ALPN:          getDefault(q, "alpn", "h3"),
		Obfs:          getDefault(q, "obfs", ""),
		ObfsPassword:  getDefault(q, "obfs-password", ""),
		UpMbps:        getDefault(q, "upmbps", ""),
		DownMbps:      getDefault(q, "downmbps", ""),
		AllowInsecure: parseBool(getDefault(q, "insecure", "true")),
	}, true
}

func splitFragment(s string) (string, string) {
	i := strings.IndexByte(s, '#')
	if i < 0 {
		return s, ""
	}
	tag := s[i+1:]
	if un, err := url.PathUnescape(tag); err == nil {
		tag = un
	}
	return s[:i], strings.TrimSpace(tag)
}

func splitQuery(s string) (string, string) {
	i := strings.IndexByte(s, '?')
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

func parseQueryValues(query string) map[string]string {
	out := make(map[string]string)
	if query == "" {
		return out
	}
	values, _ := url.ParseQuery(query)
	for k, v := range values {
		if len(v) > 0 {
			out[k] = strings.TrimSpace(v[0])
		}
	}
	return out
}

func getDefault(m map[string]string, key, def string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return def
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

func parseHostPortStrict(hostport string) (string, int, bool) {
	host, portStr, err := splitHostPort(hostport)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || host == "" {
		return "", 0, false
	}
	return host, port, true
}
