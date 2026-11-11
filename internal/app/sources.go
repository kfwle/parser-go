package app

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/kfwle/parser-go/internal/dedup"
	"github.com/kfwle/parser-go/internal/extract"
	"github.com/kfwle/parser-go/internal/fetch"
	"github.com/kfwle/parser-go/internal/logx"
	"github.com/kfwle/parser-go/internal/telegram"
)

type sourceStats struct {
	mu          sync.Mutex
	failed      []string
	processed   int
	vless       int
	trojan      int
	hy2         int
	base64      int
	json        int
	yaml        int
	total       int
	newCount    int
	happSuccess int
	newConfigs  []string
}

func (a *App) loadHTTPSources(ctx context.Context) {
	logx.Println("\n" + strings.Repeat("=", 60))
	logx.Println("Загрузка HTTP-источников (multithread)")
	logx.Println(strings.Repeat("=", 60))

	blacklist := make(map[string]struct{})
	if a.Cfg.SaveFailedSource && fileExists(a.Paths.BlacklistSources) {
		lines, err := dedup.ReadLines(a.Paths.BlacklistSources)
		if err == nil {
			for _, line := range lines {
				if !strings.HasPrefix(line, "#") {
					blacklist[line] = struct{}{}
				}
			}
		}
	}
	logx.Printf("  Загружено %d источников в чёрном списке (будут пропущены)\n", len(blacklist))

	allSources, err := dedup.ReadLines(a.Paths.SourcesFile)
	if err != nil {
		logx.Printf("  Файл %s не найден или недоступен: %v\n", a.Paths.SourcesFile, err)
		return
	}
	sources := make([]string, 0, len(allSources))
	for _, line := range allSources {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if _, bad := blacklist[line]; bad {
			continue
		}
		sources = append(sources, line)
	}
	if len(sources) == 0 {
		logx.Println("  Нет источников для обработки.")
		return
	}
	logx.Verbosef("  После чёрного списка: %d\n", len(sources))

	if a.Cfg.FixGithubURLs {
		logx.Verbosef("  Исправление GitHub ссылок...\n")
		fixed := make([]string, len(sources))
		copy(fixed, sources)
		indices := make([]int, len(sources))
		for i := range indices {
			indices[i] = i
		}
		var mu sync.Mutex
		count := 0
		logx.RunPool(ctx, indices, 50, "GitHub", func(ctx context.Context, idx int) {
			newURL := fetch.FixGitHubURL(ctx, sources[idx])
			if newURL != sources[idx] {
				mu.Lock()
				count++
				mu.Unlock()
			}
			fixed[idx] = newURL
		})
		sources = fixed
		if count > 0 {
			logx.Printf("  Исправлено GitHub ссылок: %d\n", count)
		}
	}

	existing := make(map[string]struct{})
	if lines, err := dedup.ReadLines(a.Paths.ConfigsFile); err == nil {
		for _, line := range lines {
			existing[extract.NormalizeConfig(line)] = struct{}{}
		}
	}
	logx.Verbosef("  Уже есть конфигов: %d\n", len(existing))

	// my_configs.txt has priority: add it before sources so sources cannot
	// shadow entries with the same key.
	var myNew []string
	if fileExists(a.Paths.MyConfigsFile) {
		lines, err := dedup.ReadLines(a.Paths.MyConfigsFile)
		if err == nil {
			for _, cfg := range lines {
				if !extract.IsValidConfig(cfg) {
					continue
				}
				cfg = extract.EnsureHashSuffix(cfg)
				norm := extract.NormalizeConfig(cfg)
				if _, dup := existing[norm]; dup {
					continue
				}
				existing[norm] = struct{}{}
				myNew = append(myNew, cfg)
			}
			logx.Printf("  Мои конфиги: %d (новых: %d)\n", len(lines), len(myNew))
		}
	}

	stats := &sourceStats{}
	options := extract.Options{
		VLESS:     a.Cfg.SaveVlessHTTP,
		Trojan:    a.Cfg.SaveTrojanHTTP,
		Hysteria2: a.Cfg.SaveHy2HTTP,
		Base64:    a.Cfg.DecodeBase64HTTP,
		JSON:      a.Cfg.DecodeJSONHTTP,
		YAML:      a.Cfg.DecodeYAMLHTTP,
	}

	logx.Printf("  Загрузка и обработка (%d источников)...\n", len(sources))
	logx.RunPool(ctx, sources, a.Cfg.HTTPThreads, "Разбор", func(ctx context.Context, src string) {
		content, usedHapp, err := fetch.FetchSource(ctx, src, a.Cfg.DecryptHappHTTP, 8*time.Second)
		if err != nil || len(strings.TrimSpace(content)) < 10 {
			stats.mu.Lock()
			stats.failed = append(stats.failed, src)
			stats.processed++
			stats.mu.Unlock()
			return
		}
		res := extract.ExtractFromText(content, options)
		found := len(res.VLESS) + len(res.Trojan) + len(res.Hysteria2)
		if found == 0 {
			stats.mu.Lock()
			stats.failed = append(stats.failed, src)
			stats.processed++
			stats.mu.Unlock()
			return
		}
		stats.mu.Lock()
		defer stats.mu.Unlock()
		stats.processed++
		stats.vless += len(res.VLESS)
		stats.trojan += len(res.Trojan)
		stats.hy2 += len(res.Hysteria2)
		stats.base64 += res.Base64
		stats.json += res.JSON
		stats.yaml += res.YAML
		stats.total += found
		if usedHapp {
			stats.happSuccess++
		}
		for _, cfg := range append(append(res.VLESS, res.Trojan...), res.Hysteria2...) {
			norm := extract.NormalizeConfig(cfg)
			if _, dup := existing[norm]; dup {
				continue
			}
			existing[norm] = struct{}{}
			stats.newConfigs = append(stats.newConfigs, extract.EnsureHashSuffix(cfg))
		}
		stats.newCount = len(stats.newConfigs)
	})
	logx.Println("Загрузка HTTP-источников завершена.")

	if len(stats.failed) > 0 && a.Cfg.SaveFailedSource {
		added, err := appendUnique(a.Paths.BlacklistSources, stats.failed, false)
		if err != nil {
			logx.Printf("  Не удалось записать чёрный список источников: %v\n", err)
		} else {
			logx.Printf("  Добавлено в чёрный список: %d\n", added)
		}
	}

	if len(stats.newConfigs) > 0 {
		added, err := appendUnique(a.Paths.ConfigsFile, stats.newConfigs, true)
		if err != nil {
			logx.Printf("  Не удалось записать новые конфиги: %v\n", err)
		} else {
			logx.Printf("  Добавлено новых конфигов: %d\n", added)
		}
	}
	if len(myNew) > 0 {
		added, err := appendUnique(a.Paths.ConfigsFile, myNew, true)
		if err != nil {
			logx.Printf("  Не удалось записать свои конфиги: %v\n", err)
		} else {
			logx.Printf("  Добавлено своих конфигов: %d\n", added)
		}
	}

	logx.Printf("\n  Обработано: %d/%d\n", stats.processed, len(sources))
	logx.Printf("  Конфигов всего: %d (VLESS: %d, Trojan: %d, HY2: %d)\n",
		stats.total, stats.vless, stats.trojan, stats.hy2)
	logx.Printf("  Декодировано: %d | Happ: %d\n", stats.base64+stats.json+stats.yaml, stats.happSuccess)
	logx.Printf("  Новых добавлено: %d\n", stats.newCount)
}

func (a *App) telegramWork(ctx context.Context) {
	logx.Println("\n" + strings.Repeat("=", 60))
	logx.Println("Запуск Telegram-парсера (web preview)")
	logx.Println(strings.Repeat("=", 60))

	if !fileExists(a.Paths.TGFile) {
		logx.Printf("Файл %s не найден. Telegram-парсинг пропущен.\n", a.Paths.TGFile)
		return
	}
	links, err := dedup.ReadLines(a.Paths.TGFile)
	if err != nil {
		logx.Printf("Ошибка чтения %s: %v\n", a.Paths.TGFile, err)
		return
	}
	if len(links) == 0 {
		logx.Println("Нет ссылок в tg.txt")
		return
	}
	logx.Printf("Источников для обработки: %d\n", len(links))
	logx.Printf("Чтение последних %d сообщений\n", a.Cfg.TGMessagesLimit)

	parser := telegram.New(a.Cfg)
	result := parser.ParseChannels(ctx, links)

	configs := make([]string, 0, len(result.VLESS)+len(result.Trojan)+len(result.Hy2))
	if a.Cfg.SaveVlessTG {
		for cfg := range result.VLESS {
			configs = append(configs, cfg)
		}
	}
	if a.Cfg.SaveTrojanTG {
		for cfg := range result.Trojan {
			configs = append(configs, cfg)
		}
	}
	if a.Cfg.SaveHy2TG {
		for cfg := range result.Hy2 {
			configs = append(configs, cfg)
		}
	}
	added, err := appendUnique(a.Paths.ConfigsFile, configs, true)
	if err != nil {
		logx.Printf("Ошибка записи конфигов: %v\n", err)
	} else {
		logx.Printf("  Добавлено конфигов в configs.txt: %d\n", added)
	}
	if a.Cfg.SaveSourcesTG && len(result.Sources) > 0 {
		sources := make([]string, 0, len(result.Sources))
		for src := range result.Sources {
			sources = append(sources, src)
		}
		added, err := appendUnique(a.Paths.SourcesFile, sources, false)
		if err != nil {
			logx.Printf("Ошибка записи источников: %v\n", err)
		} else {
			logx.Printf("  Добавлено источников в sources.txt: %d\n", added)
		}
	}

	logx.Println("\nTelegram парсинг завершён.")
	logx.Printf("Обработано каналов: %d\n", result.Stats.Channels)
	logx.Printf("Прочитано сообщений: %d\n", result.Stats.Messages)
	logx.Printf("VLESS: %d | Trojan: %d | HY2: %d\n", len(result.VLESS), len(result.Trojan), len(result.Hy2))
	logx.Printf("Найдено источников: %d | Happ расшифровано: %d\n", len(result.Sources), result.Stats.Happ)
}
