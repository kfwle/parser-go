// Package outbound builds Xray streamSettings/outbounds and sing-box outbounds
// from a parsed Endpoint. It is shared by the checker and the format writers.
package outbound

import (
	"strconv"
	"strings"

	"github.com/kfwle/parser-go/internal/model"
)

// StreamSettings builds Xray streamSettings for an endpoint. nil means the
// configuration is incomplete (for example Reality without a public key).
func StreamSettings(ep *model.Endpoint) map[string]any {
	network := strings.ToLower(ep.Network)
	if network == "raw" || network == "" {
		network = "tcp"
	}
	security := strings.ToLower(ep.Security)
	if security == "" {
		security = "none"
	}
	stream := map[string]any{"network": network, "security": security}
	alpn := SplitALPN(ep.ALPN)
	switch security {
	case "tls":
		serverName := ep.SNI
		if serverName == "" {
			serverName = ep.HostHeader
		}
		tls := map[string]any{
			"serverName":    serverName,
			"allowInsecure": ep.AllowInsecure,
			"fingerprint":   DefString(ep.Fingerprint, "chrome"),
		}
		if len(alpn) > 0 {
			tls["alpn"] = alpn
		}
		stream["tlsSettings"] = tls
	case "reality":
		if ep.PublicKey == "" {
			return nil
		}
		serverName := ep.SNI
		if serverName == "" {
			serverName = ep.HostHeader
		}
		reality := map[string]any{
			"show":        false,
			"publicKey":   ep.PublicKey,
			"shortId":     ep.ShortID,
			"serverName":  serverName,
			"fingerprint": DefString(ep.Fingerprint, "chrome"),
			"spiderX":     "/",
		}
		if len(alpn) > 0 {
			reality["alpn"] = alpn
		}
		stream["realitySettings"] = reality
	}
	switch network {
	case "ws", "websocket":
		stream["wsSettings"] = map[string]any{
			"path": DefString(ep.Path, "/"), "headers": map[string]any{"Host": ep.HostHeader},
		}
	case "httpupgrade":
		stream["httpupgradeSettings"] = map[string]any{
			"path": DefString(ep.Path, "/"), "host": ep.HostHeader,
		}
	case "xhttp", "splithttp":
		stream["xhttpSettings"] = map[string]any{
			"path": DefString(ep.Path, "/"), "host": ep.HostHeader,
		}
	case "h2", "http2":
		stream["h2Settings"] = map[string]any{
			"path": DefString(ep.Path, "/"), "host": []string{ep.HostHeader},
		}
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": ep.ServiceName}
	case "kcp":
		stream["kcpSettings"] = map[string]any{"header": map[string]any{"type": DefString(ep.HeaderType, "none")}}
	case "quic":
		stream["quicSettings"] = map[string]any{
			"security": DefString(ep.QUICSecurity, "none"),
			"key":      ep.Key,
			"header":   map[string]any{"type": DefString(ep.HeaderType, "none")},
		}
	}
	return stream
}

// Xray builds an Xray outbound object for vless, trojan or hysteria2.
func Xray(ep *model.Endpoint, tag string) map[string]any {
	if ep == nil {
		return nil
	}
	switch ep.Protocol {
	case model.VLESS:
		stream := StreamSettings(ep)
		if stream == nil {
			return nil
		}
		user := map[string]any{"id": ep.ID, "encryption": "none"}
		if ep.Flow != "" {
			user["flow"] = ep.Flow
		}
		return map[string]any{
			"tag": tag, "protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": ep.Host, "port": ep.Port, "users": []any{user},
			}}},
			"streamSettings": stream,
		}
	case model.Trojan:
		stream := StreamSettings(ep)
		if stream == nil {
			return nil
		}
		return map[string]any{
			"tag": tag, "protocol": "trojan",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": ep.Host, "port": ep.Port, "password": ep.ID,
			}}},
			"streamSettings": stream,
		}
	case model.Hysteria2:
		sni := ep.SNI
		if sni == "" {
			sni = ep.Host
		}
		tls := map[string]any{"sni": sni, "insecure": ep.Insecure}
		if alpn := SplitALPN(ep.ALPN); len(alpn) > 0 && ep.ALPN != "h3" {
			tls["alpn"] = alpn
		}
		settings := map[string]any{
			"server": ep.Host + ":" + strconv.Itoa(ep.Port),
			"auth":   ep.ID,
			"tls":    tls,
			"socks5": map[string]any{"listen": "127.0.0.1:1080"},
		}
		if ep.ObfsPassword != "" {
			settings["transport"] = map[string]any{"udp": map[string]any{"obfs": map[string]any{
				"type": "salamander", "password": ep.ObfsPassword,
			}}}
		}
		if ep.UpMbps != "" || ep.DownMbps != "" {
			bandwidth := map[string]any{}
			if ep.UpMbps != "" {
				bandwidth["up"] = ep.UpMbps + " mbps"
			}
			if ep.DownMbps != "" {
				bandwidth["down"] = ep.DownMbps + " mbps"
			}
			settings["bandwidth"] = bandwidth
		}
		return map[string]any{"tag": tag, "protocol": "hysteria2", "settings": settings, "type": "hysteria2"}
	}
	return nil
}

// Singbox builds a sing-box outbound object.
func Singbox(ep *model.Endpoint, tag string) map[string]any {
	if ep == nil {
		return nil
	}
	base := map[string]any{
		"tag":         tag,
		"server":      ep.Host,
		"server_port": ep.Port,
	}
	switch ep.Protocol {
	case model.VLESS:
		base["type"] = "vless"
		base["uuid"] = ep.ID
		base["tls"] = map[string]any{"enabled": false}
		if ep.Flow != "" {
			base["flow"] = ep.Flow
		}
	case model.Trojan:
		base["type"] = "trojan"
		base["password"] = ep.ID
		base["tls"] = map[string]any{"enabled": true}
	case model.Hysteria2:
		base["type"] = "hysteria2"
		base["password"] = ep.ID
		insecure := ep.Insecure
		base["tls"] = map[string]any{"enabled": true, "insecure": insecure}
	default:
		return nil
	}
	tls := base["tls"].(map[string]any)
	if ep.Security == "tls" || ep.Security == "reality" || ep.Protocol != model.VLESS {
		tls["enabled"] = true
	}
	if ep.SNI != "" {
		tls["server_name"] = ep.SNI
	}
	if ep.Fingerprint != "" && ep.Protocol != model.Hysteria2 {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": ep.Fingerprint}
	}
	if ep.ALPN != "" {
		if ep.Protocol != model.Hysteria2 || ep.ALPN != "h3" {
			tls["alpn"] = SplitALPN(ep.ALPN)
		}
	}
	if ep.Protocol == model.Hysteria2 {
		tls["insecure"] = ep.Insecure
	} else {
		tls["insecure"] = ep.AllowInsecure
	}
	if ep.Security == "reality" {
		tls["enabled"] = true
		reality := map[string]any{"enabled": true}
		if ep.PublicKey != "" {
			reality["public_key"] = ep.PublicKey
		}
		if ep.ShortID != "" {
			reality["short_id"] = ep.ShortID
		}
		tls["reality"] = reality
	}
	switch strings.ToLower(ep.Network) {
	case "ws", "websocket":
		transport := map[string]any{"type": "ws"}
		if ep.Path != "" {
			transport["path"] = ep.Path
		}
		if ep.HostHeader != "" {
			transport["headers"] = map[string]any{"Host": ep.HostHeader}
		}
		base["transport"] = transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if ep.ServiceName != "" {
			transport["service_name"] = ep.ServiceName
		}
		base["transport"] = transport
	case "httpupgrade":
		transport := map[string]any{"type": "httpupgrade", "host": ep.HostHeader, "path": ep.Path}
		base["transport"] = transport
	}
	if ep.Protocol == model.Hysteria2 {
		if ep.Obfs == "salamander" && ep.ObfsPassword != "" {
			base["obfs"] = map[string]any{"type": "salamander", "password": ep.ObfsPassword}
		}
		if n, err := strconv.Atoi(ep.UpMbps); err == nil && n > 0 {
			base["up_mbps"] = n
		}
		if n, err := strconv.Atoi(ep.DownMbps); err == nil && n > 0 {
			base["down_mbps"] = n
		}
	}
	return base
}

// SplitALPN splits a comma-separated ALPN list.
func SplitALPN(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// DefString returns def when v is empty.
func DefString(v, def string) string {
	if v != "" {
		return v
	}
	return def
}
