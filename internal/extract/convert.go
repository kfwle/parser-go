package extract

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/kfwle/parser-go/internal/model"
	"gopkg.in/yaml.v3"
)

// JSONToURLs extracts proxy URLs from Xray JSON, sing-box JSON and arrays of
// outbounds. Concatenated JSON documents are supported, like the original.
func JSONToURLs(content string) []string {
	dec := json.NewDecoder(strings.NewReader(content))
	dec.UseNumber()
	var urls []string
	for {
		var obj any
		if err := dec.Decode(&obj); err != nil {
			break
		}
		var outbounds []any
		switch v := obj.(type) {
		case map[string]any:
			outbounds = asList(v["outbounds"])
			if len(outbounds) == 0 {
				if cfg := asMap(v["config"]); cfg != nil {
					outbounds = asList(cfg["outbounds"])
				}
			}
		case []any:
			outbounds = v
		}
		for _, item := range outbounds {
			out := asMap(item)
			if out == nil {
				continue
			}
			var raw string
			var ok bool
			switch asString(out["protocol"]) {
			case "vless":
				raw, ok = outboundToVLESSURL(out)
			case "trojan":
				raw, ok = outboundToTrojanURL(out)
			case "hysteria2", "hy2":
				raw, ok = outboundToHysteria2URL(out)
			default:
				// sing-box style outbounds use "type" instead of "protocol".
				raw, ok = singboxOutboundURL(out)
			}
			if ok && IsValidConfig(raw) {
				urls = append(urls, raw)
			}
		}
	}
	return urls
}

// YAMLToURLs extracts proxy URLs from Clash/mihomo YAML (proxies list).
func YAMLToURLs(content string) []string {
	var data any
	if err := yaml.Unmarshal([]byte(content), &data); err != nil {
		return nil
	}
	root := asMap(data)
	if root == nil {
		return nil
	}
	proxies := asList(root["proxies"])
	var urls []string
	for _, item := range proxies {
		proxy := asMap(item)
		if proxy == nil {
			continue
		}
		var raw string
		var ok bool
		switch strings.ToLower(asString(proxy["type"])) {
		case "vless":
			raw, ok = clashProxyToVLESSURL(proxy)
		case "trojan":
			raw, ok = clashProxyToTrojanURL(proxy)
		case "hysteria2", "hy2":
			raw, ok = clashProxyToHysteria2URL(proxy)
		}
		if ok && IsValidConfig(raw) {
			urls = append(urls, raw)
		}
	}
	return urls
}

func outboundToVLESSURL(out map[string]any) (string, bool) {
	vnext := asList(asMap(out["settings"])["vnext"])
	if len(vnext) == 0 {
		return "", false
	}
	first := asMap(vnext[0])
	if first == nil {
		return "", false
	}
	users := asList(first["users"])
	if len(users) == 0 {
		return "", false
	}
	user := asMap(users[0])
	uuid := asString(user["id"])
	host := asString(first["address"])
	port := asInt(first["port"])
	if uuid == "" || host == "" || port == 0 {
		return "", false
	}
	stream := asMap(out["streamSettings"])
	ep := &model.Endpoint{
		Protocol:      model.VLESS,
		Tag:           asString(out["tag"]),
		ID:            uuid,
		Host:          host,
		Port:          port,
		Network:       strings.ToLower(defString(asString(stream["network"]), "tcp")),
		Security:      strings.ToLower(asString(stream["security"])),
		Flow:          asString(user["flow"]),
		Path:          asString(asMap(stream["wsSettings"])["path"]),
		HostHeader:    headerHost(asMap(asMap(stream["wsSettings"])["headers"])),
		ServiceName:   asString(asMap(stream["grpcSettings"])["serviceName"]),
		Fingerprint:   "",
		ALPN:          "",
		AllowInsecure: false,
	}
	if ep.Network == "raw" {
		ep.Network = "tcp"
	}
	switch ep.Security {
	case "reality":
		reality := asMap(stream["realitySettings"])
		ep.SNI = asString(reality["serverName"])
		ep.PublicKey = asString(reality["publicKey"])
		ep.ShortID = asString(reality["shortId"])
		ep.Fingerprint = asString(reality["fingerprint"])
		ep.ALPN = strings.Join(asStringSlice(reality["alpn"]), ",")
	case "tls":
		tls := asMap(stream["tlsSettings"])
		ep.SNI = asString(tls["serverName"])
		ep.Fingerprint = asString(tls["fingerprint"])
		ep.ALPN = strings.Join(asStringSlice(tls["alpn"]), ",")
		if v, ok := tls["allowInsecure"]; ok {
			ep.AllowInsecure = asBool(v)
		}
	}
	switch ep.Network {
	case "ws", "websocket":
		ws := asMap(stream["wsSettings"])
		ep.Path = asString(ws["path"])
		ep.HostHeader = headerHost(asMap(ws["headers"]))
	case "grpc":
		ep.ServiceName = asString(asMap(stream["grpcSettings"])["serviceName"])
	case "xhttp", "splithttp":
		xhttp := asMap(stream["xhttpSettings"])
		ep.Path = asString(xhttp["path"])
		ep.HostHeader = asString(xhttp["host"])
	case "h2", "http2":
		httpSettings := asMap(stream["httpSettings"])
		ep.Path = asString(httpSettings["path"])
		ep.HostHeader = headerHost(asMap(httpSettings["headers"]))
		if ep.HostHeader == "" {
			ep.HostHeader = strings.Join(asStringSlice(httpSettings["host"]), ",")
		}
	}
	return EndpointToURL(ep), true
}

func outboundToTrojanURL(out map[string]any) (string, bool) {
	servers := asList(asMap(out["settings"])["servers"])
	if len(servers) == 0 {
		return "", false
	}
	s := asMap(servers[0])
	host := asString(s["address"])
	port := asInt(s["port"])
	password := asString(s["password"])
	if host == "" || port == 0 || password == "" {
		return "", false
	}
	stream := asMap(out["streamSettings"])
	ep := &model.Endpoint{
		Protocol:      model.Trojan,
		Tag:           asString(out["tag"]),
		ID:            password,
		Host:          host,
		Port:          port,
		Network:       strings.ToLower(defString(asString(stream["network"]), "tcp")),
		Security:      strings.ToLower(defString(asString(stream["security"]), "tls")),
		Fingerprint:   "",
		AllowInsecure: false,
	}
	if ep.Network == "raw" {
		ep.Network = "tcp"
	}
	if ep.Security == "tls" {
		tls := asMap(stream["tlsSettings"])
		ep.SNI = asString(tls["serverName"])
		ep.Fingerprint = asString(tls["fingerprint"])
		ep.ALPN = strings.Join(asStringSlice(tls["alpn"]), ",")
		if v, ok := tls["allowInsecure"]; ok {
			ep.AllowInsecure = asBool(v)
		}
	}
	switch ep.Network {
	case "ws", "websocket":
		ws := asMap(stream["wsSettings"])
		ep.Path = asString(ws["path"])
		ep.HostHeader = headerHost(asMap(ws["headers"]))
	case "grpc":
		ep.ServiceName = asString(asMap(stream["grpcSettings"])["serviceName"])
	}
	return EndpointToURL(ep), true
}

func outboundToHysteria2URL(out map[string]any) (string, bool) {
	servers := asList(asMap(out["settings"])["servers"])
	if len(servers) == 0 {
		return "", false
	}
	s := asMap(servers[0])
	host := asString(s["address"])
	port := asInt(s["port"])
	if host == "" || port == 0 {
		return "", false
	}
	stream := asMap(out["streamSettings"])
	ep := &model.Endpoint{
		Protocol: model.Hysteria2,
		Tag:      asString(out["tag"]),
		ID:       asString(s["auth"]),
		Auth:     asString(s["auth"]),
		Host:     host,
		Port:     port,
	}
	if strings.EqualFold(asString(stream["security"]), "tls") {
		tls := asMap(stream["tlsSettings"])
		ep.SNI = asString(tls["serverName"])
		ep.ALPN = strings.Join(asStringSlice(tls["alpn"]), ",")
		if v, ok := tls["allowInsecure"]; ok {
			ep.Insecure = asBool(v)
		}
	}
	if hop := asMap(asMap(stream["transport"])["hopConfig"]); hop != nil {
		if asString(hop["obfs"]) == "salamander" && asString(hop["password"]) != "" {
			ep.Obfs = "salamander"
			ep.ObfsPassword = asString(hop["password"])
		}
	}
	return EndpointToURL(ep), true
}

// singboxOutboundURL converts a sing-box "outbounds" entry.
func singboxOutboundURL(out map[string]any) (string, bool) {
	typ := strings.ToLower(asString(out["type"]))
	if typ != "vless" && typ != "trojan" && typ != "hysteria2" && typ != "hy2" {
		return "", false
	}
	host := asString(out["server"])
	port := asInt(out["server_port"])
	if host == "" || port == 0 {
		return "", false
	}
	tls := asMap(out["tls"])
	transport := asMap(out["transport"])
	ep := &model.Endpoint{Protocol: typ, Tag: asString(out["tag"]), Host: host, Port: port}
	if typ == "vless" {
		ep.Protocol = model.VLESS
		ep.ID = asString(out["uuid"])
		ep.Flow = asString(out["flow"])
	} else if typ == "trojan" {
		ep.Protocol = model.Trojan
		ep.ID = asString(out["password"])
	} else {
		ep.Protocol = model.Hysteria2
		ep.ID = asString(out["password"])
		ep.Auth = ep.ID
		ep.Obfs = asString(asMap(out["obfs"])["type"])
		ep.ObfsPassword = asString(asMap(out["obfs"])["password"])
		ep.UpMbps = asString(out["up_mbps"])
		ep.DownMbps = asString(out["down_mbps"])
	}
	if ep.ID == "" && ep.Protocol != model.Hysteria2 {
		return "", false
	}
	if asBool(tls["enabled"]) {
		ep.Security = "tls"
		ep.SNI = asString(tls["server_name"])
		ep.AllowInsecure = asBool(tls["insecure"])
		ep.Insecure = ep.AllowInsecure
		ep.ALPN = strings.Join(asStringSlice(tls["alpn"]), ",")
		ep.Fingerprint = asString(asMap(tls["utls"])["fingerprint"])
		if reality := asMap(tls["reality"]); reality != nil && asBool(reality["enabled"]) {
			ep.Security = "reality"
			ep.PublicKey = asString(reality["public_key"])
			ep.ShortID = asString(reality["short_id"])
		}
	}
	if transport != nil {
		switch strings.ToLower(asString(transport["type"])) {
		case "ws", "websocket":
			ep.Network = "ws"
			ep.Path = asString(transport["path"])
			ep.HostHeader = headerHost(asMap(transport["headers"]))
		case "grpc":
			ep.Network = "grpc"
			ep.ServiceName = asString(transport["service_name"])
		case "http", "h2":
			ep.Network = "h2"
			ep.Path = asString(transport["path"])
			ep.HostHeader = strings.Join(asStringSlice(transport["host"]), ",")
		case "httpupgrade":
			ep.Network = "httpupgrade"
			ep.Path = asString(transport["path"])
			ep.HostHeader = asString(transport["host"])
		}
	}
	return EndpointToURL(ep), true
}

func clashProxyToVLESSURL(proxy map[string]any) (string, bool) {
	server := asString(proxy["server"])
	port := asInt(proxy["port"])
	uuid := asString(proxy["uuid"])
	if server == "" || port == 0 || uuid == "" {
		return "", false
	}
	ep := &model.Endpoint{
		Protocol:    model.VLESS,
		Tag:         asString(proxy["name"]),
		ID:          uuid,
		Host:        server,
		Port:        port,
		Network:     strings.ToLower(defString(asString(proxy["network"]), "tcp")),
		Security:    "none",
		Path:        asString(asMap(proxy["ws-opts"])["path"]),
		HostHeader:  headerHost(asMap(asMap(proxy["ws-opts"])["headers"])),
		ServiceName: asString(asMap(proxy["grpc-opts"])["grpc-service-name"]),
		SNI:         defString(asString(proxy["servername"]), asString(proxy["sni"])),
		Fingerprint: asString(proxy["client-fingerprint"]),
		Flow:        asString(proxy["flow"]),
		ALPN:        strings.Join(asStringSlice(proxy["alpn"]), ","),
	}
	if reality := asMap(proxy["reality-opts"]); reality != nil {
		ep.Security = "reality"
		ep.PublicKey = asString(reality["public-key"])
		ep.ShortID = asString(reality["short-id"])
	} else if asBool(proxy["tls"]) {
		ep.Security = "tls"
	}
	if ep.Network == "websocket" {
		ep.Network = "ws"
	}
	return EndpointToURL(ep), true
}

func clashProxyToTrojanURL(proxy map[string]any) (string, bool) {
	server := asString(proxy["server"])
	port := asInt(proxy["port"])
	password := asString(proxy["password"])
	if server == "" || port == 0 || password == "" {
		return "", false
	}
	ep := &model.Endpoint{
		Protocol:    model.Trojan,
		Tag:         asString(proxy["name"]),
		ID:          password,
		Host:        server,
		Port:        port,
		Network:     strings.ToLower(defString(asString(proxy["network"]), "tcp")),
		Security:    "tls",
		Path:        asString(asMap(proxy["ws-opts"])["path"]),
		HostHeader:  headerHost(asMap(asMap(proxy["ws-opts"])["headers"])),
		ServiceName: asString(asMap(proxy["grpc-opts"])["grpc-service-name"]),
		SNI:         defString(asString(proxy["servername"]), asString(proxy["sni"])),
		Fingerprint: asString(proxy["client-fingerprint"]),
		ALPN:        strings.Join(asStringSlice(proxy["alpn"]), ","),
	}
	if tls, ok := proxy["tls"]; ok && !asBool(tls) {
		ep.Security = "none"
	}
	if ep.Network == "websocket" {
		ep.Network = "ws"
	}
	return EndpointToURL(ep), true
}

func clashProxyToHysteria2URL(proxy map[string]any) (string, bool) {
	server := asString(proxy["server"])
	port := asInt(proxy["port"])
	if server == "" || port == 0 {
		return "", false
	}
	ep := &model.Endpoint{
		Protocol:     model.Hysteria2,
		Tag:          asString(proxy["name"]),
		ID:           asString(proxy["password"]),
		Auth:         asString(proxy["password"]),
		Host:         server,
		Port:         port,
		SNI:          defString(asString(proxy["servername"]), asString(proxy["sni"])),
		ALPN:         strings.Join(asStringSlice(proxy["alpn"]), ","),
		Insecure:     asBool(proxy["skip-cert-verify"]),
		Obfs:         asString(proxy["obfs"]),
		ObfsPassword: asString(proxy["obfs-password"]),
		UpMbps:       asString(proxy["up"]),
		DownMbps:     asString(proxy["down"]),
	}
	return EndpointToURL(ep), true
}

// EndpointToURL serialises an Endpoint back into a proxy URL.
func EndpointToURL(ep *model.Endpoint) string {
	if ep == nil || ep.Host == "" || ep.Port == 0 {
		return ""
	}
	host := ep.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	params := map[string]string{}
	switch ep.Protocol {
	case model.VLESS:
		params["encryption"] = "none"
		params["type"] = defString(ep.Network, "tcp")
		if ep.Flow != "" {
			params["flow"] = ep.Flow
		}
		if ep.Security == "reality" {
			params["security"] = "reality"
			params["sni"] = ep.SNI
			params["pbk"] = ep.PublicKey
			params["sid"] = ep.ShortID
			params["fp"] = ep.Fingerprint
			if ep.ALPN == "" {
				ep.ALPN = "http/1.1"
			}
			params["alpn"] = ep.ALPN
		} else if ep.Security == "tls" {
			params["security"] = "tls"
			params["sni"] = ep.SNI
			params["fp"] = ep.Fingerprint
			params["alpn"] = ep.ALPN
			params["allowInsecure"] = boolParam(ep.AllowInsecure)
		}
		switch ep.Network {
		case "ws", "websocket":
			params["path"] = ep.Path
			params["host"] = ep.HostHeader
		case "grpc":
			params["serviceName"] = ep.ServiceName
		case "xhttp", "splithttp":
			params["path"] = ep.Path
			params["host"] = ep.HostHeader
		case "h2", "http2":
			params["path"] = ep.Path
			params["host"] = ep.HostHeader
		case "httpupgrade":
			params["path"] = ep.Path
			params["host"] = ep.HostHeader
		}
		query := buildQuery(params)
		if query != "" {
			query = "?" + query
		}
		return "vless://" + percentEncode(ep.ID) + "@" + host + ":" + strconv.Itoa(ep.Port) + query + tagSuffix(ep.Tag)
	case model.Trojan:
		if ep.Security != "tls" {
			params["security"] = ep.Security
		}
		params["sni"] = ep.SNI
		params["fp"] = ep.Fingerprint
		params["alpn"] = ep.ALPN
		params["allowInsecure"] = boolParam(ep.AllowInsecure)
		if ep.Network != "" && ep.Network != "tcp" {
			params["type"] = ep.Network
			switch ep.Network {
			case "ws", "websocket":
				params["path"] = ep.Path
				params["host"] = ep.HostHeader
			case "grpc":
				params["serviceName"] = ep.ServiceName
			}
		}
		query := buildQuery(params)
		if query != "" {
			query = "?" + query
		}
		return "trojan://" + percentEncode(ep.ID) + "@" + host + ":" + strconv.Itoa(ep.Port) + query + tagSuffix(ep.Tag)
	case model.Hysteria2:
		params["sni"] = ep.SNI
		params["insecure"] = boolParam(ep.Insecure)
		if ep.ALPN != "" && ep.ALPN != "h3" {
			params["alpn"] = ep.ALPN
		}
		params["obfs"] = ep.Obfs
		params["obfs-password"] = ep.ObfsPassword
		params["upmbps"] = ep.UpMbps
		params["downmbps"] = ep.DownMbps
		query := buildQuery(params)
		if query != "" {
			query = "?" + query
		}
		auth := ""
		if ep.ID != "" {
			auth = percentEncode(ep.ID) + "@"
		}
		return "hy2://" + auth + host + ":" + strconv.Itoa(ep.Port) + query + tagSuffix(ep.Tag)
	}
	return ""
}

func tagSuffix(tag string) string {
	if tag == "" {
		return ""
	}
	return "#" + percentEncode(tag)
}

func boolParam(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// buildQuery percent-encodes values and returns a sorted query string.
func buildQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, percentEncode(k)+"="+percentEncode(params[k]))
	}
	return strings.Join(parts, "&")
}

// percentEncode implements Python's urllib.parse.quote(s, safe=”).
func percentEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

// --- generic map helpers for JSON/YAML documents ---

func asMap(v any) map[string]any {
	switch m := v.(type) {
	case map[string]any:
		return m
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprint(k)] = val
		}
		return out
	}
	return nil
}

func asList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case json.Number:
		return x.String()
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	return ""
}

func asInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	}
	return 0
}

func asBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return parseBool(x)
	case int:
		return x != 0
	case float64:
		return x != 0
	}
	return false
}

func asStringSlice(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s := asString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	case string:
		if x == "" {
			return nil
		}
		parts := strings.Split(x, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return parts
	}
	return nil
}

func headerHost(headers map[string]any) string {
	if headers == nil {
		return ""
	}
	for k, v := range headers {
		if strings.EqualFold(k, "host") {
			return asString(v)
		}
	}
	return ""
}

func defString(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

// SourceKey normalises a source URL so duplicates can be detected.
func SourceKey(raw string) string { return NormalizeSource(raw) }

// PercentEncode exposes Python-style quote(s, safe=”).
func PercentEncode(s string) string { return percentEncode(s) }
