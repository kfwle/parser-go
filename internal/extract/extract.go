// Package extract finds proxy configuration URLs in arbitrary text and
// converts structured payloads (base64, Xray JSON, Clash/sing-box YAML) into
// canonical URL form.
package extract

import (
	"encoding/base64"
	"fmt"
	"html"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kfwle/parser-go/internal/model"
)

var (
	vlessRe  = regexp.MustCompile(`(?i)vless://[^\s#]+`)
	trojanRe = regexp.MustCompile(`(?i)trojan://[^\s#]+`)
	hy2Re    = regexp.MustCompile(`(?i)(?:hysteria2|hy2)://[^\s#]+`)
	urlRe    = regexp.MustCompile("(?i)https?://[^\\s<>\"'(){}|\\\\^`\\[\\]]+")
	happRe   = regexp.MustCompile(`(?i)happ://crypt[0-9]*/[A-Za-z0-9+/=_\-]+`)
	uuidRe   = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	base64Re = regexp.MustCompile(`^[A-Za-z0-9+/_\-]+=*$`)
	sniRe    = regexp.MustCompile(`(?i)[?&](?:sni|host)=([^&#]+)`)
)

// CleanText removes BOM/zero-width characters and decodes HTML entities.
func CleanText(s string) string {
	s = strings.ReplaceAll(s, "\ufeff", "")
	s = strings.ReplaceAll(s, "\u200b", "")
	return html.UnescapeString(s)
}

// CleanURL removes invisible characters and decodes HTML entities. It does NOT
// percent-decode the whole URL: that corrupts encoded delimiters (%23, %26) and
// splits the host/query boundary. Individual components are unescaped by the
// protocol parsers instead.
func CleanURL(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\ufeff", "")
	s = strings.ReplaceAll(s, "\u200b", "")
	s = strings.NewReplacer("\n", "", "\r", "").Replace(s)
	s = html.UnescapeString(s)
	return strings.TrimSpace(s)
}

// IsValidConfig reports whether s looks like a supported proxy URL.
func IsValidConfig(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) > maxConfigLen {
		return false
	}
	switch {
	case strings.HasPrefix(strings.ToLower(s), "vless://"):
		return strings.Contains(s, "@") && uuidRe.MatchString(s)
	case strings.HasPrefix(strings.ToLower(s), "trojan://"):
		return strings.Contains(s, "@")
	case strings.HasPrefix(strings.ToLower(s), "hysteria2://"), strings.HasPrefix(strings.ToLower(s), "hy2://"):
		return strings.Contains(s, "@")
	}
	return false
}

// EnsureHashSuffix appends '#' when missing so tags can be added later.
func EnsureHashSuffix(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, "#") {
		s += "#"
	}
	return s
}

// NormalizeConfig removes the fragment and sorts query parameters. It is used
// for duplicate detection, not for output.
func NormalizeConfig(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	i := strings.IndexByte(s, '?')
	if i < 0 {
		return s
	}
	base, query := strings.TrimSpace(s[:i]), s[i+1:]
	params := make(map[string]string)
	for _, part := range strings.Split(query, "&") {
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if ok {
			params[k] = v
		} else {
			params[k] = ""
		}
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+params[k])
	}
	if len(parts) == 0 {
		return base
	}
	return base + "?" + strings.Join(parts, "&")
}

// NormalizeSource removes the fragment and sorts query parameters of an HTTP
// source URL.
func NormalizeSource(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	u.RawQuery = u.Query().Encode()
	return u.String()
}

// maxConfigLen bounds a single config URL. Hostile subscriptions sometimes
// contain multi-megabyte "configs" that would otherwise poison list files.
const maxConfigLen = 16 * 1024

// FindConfigs returns all vless, trojan and hysteria2 URLs found in text.
func FindConfigs(text string) (vless, trojan, hy2 []string) {
	vless = filterMatches(vlessRe.FindAllString(text, -1))
	trojan = filterMatches(trojanRe.FindAllString(text, -1))
	hy2 = filterMatches(hy2Re.FindAllString(text, -1))
	return
}

func filterMatches(matches []string) []string {
	out := matches[:0]
	for _, m := range matches {
		if len(m) <= maxConfigLen {
			out = append(out, m)
		}
	}
	return out
}

// FindURLs returns every http(s) URL in text.
func FindURLs(text string) []string { return urlRe.FindAllString(text, -1) }

// FindHapp returns happ://cryptN/... links.
func FindHapp(text string) []string { return happRe.FindAllString(text, -1) }

// IsValidHost rejects hosts containing URL delimiters, whitespace or control
// characters. IPv6 literals (colons) are allowed; brackets are not.
func IsValidHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return false
	}
	for _, r := range host {
		if r <= ' ' || r == 0x7f {
			return false
		}
		switch r {
		case '@', '#', '?', '/', '\\', '%', '[', ']', '"', '\'', '<', '>', '&', '=', ';', ',':
			return false
		}
	}
	return true
}

// ExtractSNI reads the sni or host parameter from a config URL. The fragment is
// ignored: SNI must come from the query string, otherwise a tag like
// "#&sni=allowed.example" could bypass the SNI filter.
func ExtractSNI(raw string) string {
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	m := sniRe.FindStringSubmatch(raw)
	if len(m) < 2 {
		return ""
	}
	if un, err := url.PathUnescape(m[1]); err == nil {
		return un
	}
	return m[1]
}

// HostPort extracts host and port from a proxy URL. Hysteria2 defaults to 443.
func HostPort(raw string) (string, int, bool) {
	s := strings.TrimSpace(raw)
	lower := strings.ToLower(s)
	var rest string
	var defaultPort int
	switch {
	case strings.HasPrefix(lower, "vless://"):
		rest = s[len("vless://"):]
	case strings.HasPrefix(lower, "trojan://"):
		rest = s[len("trojan://"):]
	case strings.HasPrefix(lower, "hysteria2://"):
		rest = s[len("hysteria2://"):]
		defaultPort = 443
	case strings.HasPrefix(lower, "hy2://"):
		rest = s[len("hy2://"):]
		defaultPort = 443
	default:
		return "", 0, false
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
	}
	host, portStr, err := splitHostPort(rest)
	if err != nil {
		if defaultPort == 0 {
			return "", 0, false
		}
		host = strings.Trim(rest, "[]")
		if host == "" || !IsValidHost(host) {
			return "", 0, false
		}
		return host, defaultPort, true
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || !IsValidHost(host) {
		return "", 0, false
	}
	return host, port, true
}

// splitHostPort is a bracket-aware wrapper around net.SplitHostPort.
func splitHostPort(s string) (string, string, error) {
	if strings.HasPrefix(s, "[") {
		end := strings.LastIndexByte(s, ']')
		if end < 0 {
			return "", "", fmt.Errorf("bad IPv6 literal")
		}
		host := s[1:end]
		rest := s[end+1:]
		if rest == "" {
			return host, "", fmt.Errorf("missing port")
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("bad port")
		}
		return host, rest[1:], nil
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, "", fmt.Errorf("missing port")
	}
	if strings.Contains(s[:i], ":") {
		// Bare IPv6 without brackets: treat whole string as host.
		return s, "", fmt.Errorf("missing port")
	}
	return s[:i], s[i+1:], nil
}

// Key is a protocol-independent duplicate-detection key.
type Key struct {
	Protocol string
	ID       string
	Host     string
	Port     int
	SNI      string
}

// DedupKey parses raw and returns its duplicate-detection key. bySNI toggles
// inclusion of the SNI/host parameter.
func DedupKey(raw string, bySNI bool) (Key, bool) {
	ep, ok := ParseConfig(raw)
	if !ok {
		return Key{}, false
	}
	sni := ep.SNI
	if sni == "" {
		sni = ep.HostHeader
	}
	if !bySNI {
		sni = ""
	}
	return Key{
		Protocol: ep.Protocol,
		ID:       ep.ID,
		Host:     strings.ToLower(ep.Host),
		Port:     ep.Port,
		SNI:      strings.ToLower(sni),
	}, true
}

// IsBase64Blob reports whether s is a single base64 token (standard or
// URL-safe), ignoring whitespace.
func IsBase64Blob(s string) bool {
	t := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	return t != "" && base64Re.MatchString(t)
}

// DecodeBase64 decodes standard or URL-safe base64 with optional padding.
func DecodeBase64(s string) ([]byte, error) {
	t := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	t = strings.ReplaceAll(t, "-", "+")
	t = strings.ReplaceAll(t, "_", "/")
	t = strings.TrimRight(t, "=")
	if len(t)%4 == 1 {
		return nil, fmt.Errorf("invalid base64 length")
	}
	return base64.RawStdEncoding.DecodeString(t)
}

// DecodeBase64Content decodes base64 text recursively and returns the decoded
// content plus every config URL found inside.
func DecodeBase64Content(content string, depth int) (string, []string) {
	if depth > 3 || !IsBase64Blob(content) {
		return "", nil
	}
	decoded, err := DecodeBase64(content)
	if err != nil {
		return "", nil
	}
	text := string(decoded)
	vless, trojan, hy2 := FindConfigs(text)
	matches := make([]string, 0, len(vless)+len(trojan)+len(hy2))
	matches = append(matches, vless...)
	matches = append(matches, trojan...)
	matches = append(matches, hy2...)
	if len(text) > 100 && IsBase64Blob(text) {
		if _, deeper := DecodeBase64Content(text, depth+1); len(deeper) > 0 {
			matches = append(matches, deeper...)
		}
	}
	return text, matches
}

// Options controls which decoders are enabled for a source.
type Options struct {
	VLESS, Trojan, Hysteria2 bool
	Base64, JSON, YAML       bool
}

// Result is the outcome of ExtractFromText.
type Result struct {
	VLESS, Trojan, Hysteria2 []string
	Base64, JSON, YAML       int
}

// ExtractFromText runs every enabled extractor over text. Counters mirror the
// original per-source statistics (1 means "decoded at least once").
func ExtractFromText(text string, opt Options) Result {
	var res Result
	add := func(cfg string) {
		if len(cfg) > maxConfigLen {
			return
		}
		lower := strings.ToLower(cfg)
		switch {
		case strings.HasPrefix(lower, "vless://"):
			if opt.VLESS {
				res.VLESS = append(res.VLESS, cfg)
			}
		case strings.HasPrefix(lower, "trojan://"):
			if opt.Trojan {
				res.Trojan = append(res.Trojan, cfg)
			}
		case strings.HasPrefix(lower, "hysteria2://"), strings.HasPrefix(lower, "hy2://"):
			if opt.Hysteria2 {
				res.Hysteria2 = append(res.Hysteria2, cfg)
			}
		}
	}

	vless, trojan, hy2 := FindConfigs(text)
	for _, c := range vless {
		add(c)
	}
	for _, c := range trojan {
		add(c)
	}
	for _, c := range hy2 {
		add(c)
	}

	if opt.Base64 {
		if _, matches := DecodeBase64Content(text, 0); len(matches) > 0 {
			res.Base64 = 1
			for _, m := range matches {
				add(m)
			}
		}
	}
	if opt.JSON && (strings.HasPrefix(strings.TrimSpace(text), "{") || strings.HasPrefix(strings.TrimSpace(text), "[")) {
		if urls := JSONToURLs(text); len(urls) > 0 {
			res.JSON = 1
			for _, u := range urls {
				add(u)
			}
		}
	}
	if opt.YAML && (strings.Contains(text, "proxies:") || strings.Contains(strings.ToLower(text), "type: vless")) {
		if urls := YAMLToURLs(text); len(urls) > 0 {
			res.YAML = 1
			for _, u := range urls {
				add(u)
			}
		}
	}
	return res
}

// IsSecure reports whether a config uses TLS/Reality (or verified Hysteria2
// TLS). Used to push unsafe configs to the bottom of output lists.
func IsSecure(raw string) bool {
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "vless://"), strings.HasPrefix(lower, "trojan://"):
		return strings.Contains(lower, "security=tls") || strings.Contains(lower, "security=reality")
	case strings.HasPrefix(lower, "hysteria2://"), strings.HasPrefix(lower, "hy2://"):
		return strings.Contains(lower, "insecure=false") || strings.Contains(lower, "insecure=0")
	}
	return false
}

// ParseConfig dispatches to the protocol parser.
func ParseConfig(raw string) (*model.Endpoint, bool) {
	lower := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.HasPrefix(lower, "vless://"):
		return ParseVLESS(raw)
	case strings.HasPrefix(lower, "trojan://"):
		return ParseTrojan(raw)
	case strings.HasPrefix(lower, "hysteria2://"), strings.HasPrefix(lower, "hy2://"):
		return ParseHysteria2(raw)
	}
	return nil, false
}
