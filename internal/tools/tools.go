// Package tools implements the maintenance helpers from the original menu.
package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kfwle/parser-go/internal/checker"
	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/dedup"
	"github.com/kfwle/parser-go/internal/extract"
	"github.com/kfwle/parser-go/internal/fetch"
	"github.com/kfwle/parser-go/internal/logx"
)

// Whitelist sources used by menu items 5 and 6.
const (
	IPWhitelistURL     = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/ipwhitelist.txt"
	DomainWhitelistURL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"
)

// FilterSources keeps only sources that currently contain configs.
func FilterSources(ctx context.Context, paths *config.Paths) error {
	lines, err := dedup.ReadLines(paths.SourcesFile)
	if err != nil {
		return err
	}
	urls := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	if len(urls) == 0 {
		logx.Println("Нет источников для фильтрации.")
		return nil
	}
	workers := 50
	if len(urls) < workers {
		workers = len(urls)
	}
	logx.Printf("Источников: %d, потоков: %d\n", len(urls), workers)

	working := make([]bool, len(urls))
	indices := make([]int, len(urls))
	for i := range indices {
		indices[i] = i
	}
	logx.RunPool(ctx, indices, workers, "Фильтрация источников", func(ctx context.Context, idx int) {
		content, _, err := fetch.FetchSource(ctx, urls[idx], false, 8*time.Second)
		if err != nil || len(strings.TrimSpace(content)) < 10 {
			return
		}
		if hasConfigs(content) {
			working[idx] = true
		}
	})

	if ctx.Err() != nil {
		logx.Println("Фильтрация источников прервана, sources.txt не изменён.")
		return nil
	}

	backup := filepath.Join(paths.BackupsDir, "sources_backup_"+time.Now().Format("20060102_1504")+".txt")
	if err := os.MkdirAll(paths.BackupsDir, 0o755); err != nil {
		return err
	}
	if err := copyFile(paths.SourcesFile, backup); err != nil {
		return err
	}
	logx.Printf("Бэкап оригинала: %s\n", backup)

	kept := make([]string, 0, len(urls))
	for i, ok := range working {
		if ok {
			kept = append(kept, urls[i])
		}
	}
	if len(kept) == 0 {
		logx.Println("[!] Ни один источник не ответил — sources.txt не изменён (возможно, сеть недоступна).")
		return nil
	}
	if err := dedup.WriteLines(paths.SourcesFile, kept); err != nil {
		return err
	}
	logx.Printf("Сохранено %d/%d рабочих источников в %s\n", len(kept), len(urls), paths.SourcesFile)
	return nil
}

func hasConfigs(text string) bool {
	vless, trojan, hy2 := extract.FindConfigs(text)
	if len(vless)+len(trojan)+len(hy2) > 0 {
		return true
	}
	if extract.IsBase64Blob(text) {
		if decoded, err := extract.DecodeBase64(text); err == nil {
			v, t, h := extract.FindConfigs(string(decoded))
			return len(v)+len(t)+len(h) > 0
		}
	}
	return false
}

// ClearTemp removes temporary files, keeping the garbage pool, downloaded ids
// and the MaxMind database.
func ClearTemp(paths *config.Paths) error {
	keep := map[string]bool{
		"garbage_conf.txt":      true,
		"downloaded_ids.txt":    true,
		"GeoLite2-Country.mmdb": true,
	}
	removed, err := clearDir(paths.TempDir, keep)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(paths.TelegramFilesDir, 0o755); err != nil {
		return err
	}
	logx.Printf("Очищено temp файлов/папок: %d (сохранены: garbage_conf.txt, downloaded_ids.txt)\n", removed)
	return nil
}

// ClearExceptGarbage removes generated configs and temp files but keeps the
// garbage pool.
func ClearExceptGarbage(paths *config.Paths) error {
	files := []string{
		paths.WhitelistFile,
		paths.BlacklistFile,
		filepath.Join(paths.ClashDir, "whitelist.yaml"),
		filepath.Join(paths.ClashDir, "blacklist.yaml"),
		filepath.Join(paths.XrayDir, "whitelist.json"),
		filepath.Join(paths.XrayDir, "blacklist.json"),
		filepath.Join(paths.SingboxDir, "whitelist.json"),
		filepath.Join(paths.SingboxDir, "blacklist.json"),
		paths.ConfigsFile,
		paths.CleanFile,
		paths.WLFilteredFile,
		paths.BLFilteredFile,
		paths.BlacklistSources,
	}
	removed := 0
	for _, file := range files {
		if err := os.Remove(file); err == nil {
			removed++
			logx.Printf("  Удалён: %s\n", file)
		}
	}
	keep := map[string]bool{
		"garbage_conf.txt":      true,
		"downloaded_ids.txt":    true,
		"GeoLite2-Country.mmdb": true,
	}
	if _, err := clearDir(paths.TempDir, keep); err != nil {
		return err
	}
	if err := os.MkdirAll(paths.TelegramFilesDir, 0o755); err != nil {
		return err
	}
	logx.Printf("Очищено конфигов и файлов: %d. Сохранён garbage pool.\n", removed)
	return nil
}

func clearDir(dir string, keep map[string]bool) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, os.MkdirAll(dir, 0o755)
		}
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		if keep[entry.Name()] {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			if err := os.RemoveAll(path); err == nil {
				removed++
			}
			continue
		}
		if err := os.Remove(path); err == nil {
			removed++
		}
	}
	return removed, nil
}

// UpdateCores re-downloads Xray and Hysteria2.
func UpdateCores(ctx context.Context, paths *config.Paths) error {
	logx.Println("Принудительное обновление ядер...")
	return checker.UpdateCores(ctx, paths)
}

// DownloadWhitelist fetches an IP or domain whitelist into dest.
func DownloadWhitelist(ctx context.Context, rawURL, dest, label string) error {
	logx.Printf("Скачивание %s whitelist...\n", label)
	content, err := fetch.GetSecure(ctx, rawURL, 60*time.Second, nil)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
		return err
	}
	count := len(strings.Split(strings.TrimSpace(content), "\n"))
	logx.Printf("%s whitelist сохранён: %s (%d строк)\n", label, dest, count)
	return nil
}

// DownloadIPWhitelist downloads the IP prefix list.
func DownloadIPWhitelist(ctx context.Context, paths *config.Paths) error {
	return DownloadWhitelist(ctx, IPWhitelistURL, paths.IPListFile, "IP")
}

// DownloadDomainWhitelist downloads the SNI domain list.
func DownloadDomainWhitelist(ctx context.Context, paths *config.Paths) error {
	return DownloadWhitelist(ctx, DomainWhitelistURL, paths.SNIListFile, "Domain")
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}
