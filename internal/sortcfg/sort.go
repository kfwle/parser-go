// Package sortcfg orders final config files by transport priority and security.
package sortcfg

import (
	"strings"

	"github.com/kfwle/parser-go/internal/dedup"
	"github.com/kfwle/parser-go/internal/logx"
)

// ByProtocol rewrites path with vless configs first, then trojan, then others.
func ByProtocol(path string) error {
	lines, err := dedup.ReadLines(path)
	if err != nil {
		return err
	}
	var vless, trojan, other []string
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "vless://"):
			vless = append(vless, line)
		case strings.HasPrefix(line, "trojan://"):
			trojan = append(trojan, line)
		default:
			other = append(other, line)
		}
	}
	merged := make([]string, 0, len(lines))
	merged = append(merged, vless...)
	merged = append(merged, trojan...)
	merged = append(merged, other...)
	if err := dedup.WriteLines(path, merged); err != nil {
		return err
	}
	logx.Printf("configs.txt отсортирован: VLESS=%d, Trojan=%d, Остальные=%d\n",
		len(vless), len(trojan), len(other))
	return nil
}

// SortFile applies the configured ordering to whitelist/blacklist files.
func SortFile(path string, priorityTop, unsafeBottom bool) error {
	lines, err := dedup.ReadLines(path)
	if err != nil {
		return err
	}
	var sorted []string
	switch {
	case priorityTop && unsafeBottom:
		secure, insecure := splitSecure(lines)
		sorted = append(sortPriority(secure), sortPriority(insecure)...)
	case priorityTop:
		sorted = sortPriority(lines)
	case unsafeBottom:
		secure, insecure := splitSecure(lines)
		sorted = append(secure, insecure...)
	default:
		return nil
	}
	if err := dedup.WriteLines(path, sorted); err != nil {
		return err
	}
	logx.Printf("  Отсортирован %s (%d конфигов)\n", path, len(sorted))
	return nil
}

func sortPriority(configs []string) []string {
	var xhttp, grpc, tcp, other []string
	for _, c := range configs {
		lower := strings.ToLower(c)
		switch {
		case strings.Contains(lower, "type=xhttp"), strings.Contains(lower, "type=splithttp"):
			xhttp = append(xhttp, c)
		case strings.Contains(lower, "type=grpc"), strings.Contains(lower, "servicename="):
			grpc = append(grpc, c)
		case strings.HasPrefix(lower, "vless://"), strings.HasPrefix(lower, "trojan://"),
			strings.HasPrefix(lower, "hysteria2://"), strings.HasPrefix(lower, "hy2://"):
			tcp = append(tcp, c)
		default:
			other = append(other, c)
		}
	}
	out := make([]string, 0, len(configs))
	out = append(out, xhttp...)
	out = append(out, grpc...)
	out = append(out, tcp...)
	out = append(out, other...)
	return out
}

func splitSecure(configs []string) (secure, insecure []string) {
	for _, c := range configs {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "security=tls") || strings.Contains(lower, "security=reality") ||
			strings.Contains(lower, "insecure=0") || strings.Contains(lower, "insecure=false") {
			secure = append(secure, c)
		} else {
			insecure = append(insecure, c)
		}
	}
	return secure, insecure
}
