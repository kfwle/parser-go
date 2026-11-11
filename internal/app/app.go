// Package app orchestrates the full parsing pipeline: import, sources,
// Telegram, dedup, filtering, checking, country detection, sorting and format
// conversion.
package app

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kfwle/parser-go/internal/checker"
	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/dedup"
	"github.com/kfwle/parser-go/internal/extract"
	"github.com/kfwle/parser-go/internal/filter"
	"github.com/kfwle/parser-go/internal/format"
	"github.com/kfwle/parser-go/internal/logx"
	"github.com/kfwle/parser-go/internal/sortcfg"
)

// App is a configured parser instance.
type App struct {
	Cfg   config.Config
	Paths *config.Paths
}

// New creates an App.
func New(cfg config.Config, paths *config.Paths) *App {
	return &App{Cfg: cfg, Paths: paths}
}

// RunOnce executes one complete parser cycle without sleeping.
func (a *App) RunOnce(ctx context.Context) error {
	if err := a.Paths.EnsureDirs(); err != nil {
		return err
	}
	if !a.HasWork() {
		PrintNoWorkHelp(a.Paths)
		return ErrNoWork
	}
	logx.Println("\n" + strings.Repeat("=", 60))
	logx.Println(" ЗАПУСК ПАРСЕРА")
	logx.Println(strings.Repeat("=", 60))

	if a.Cfg.ImportWhitelist || a.Cfg.ImportBlacklist {
		a.prependWhitelistBlacklist()
	} else {
		logx.Println("Импорт whitelist/blacklist отключён настройками.")
	}
	if ctx.Err() != nil {
		return nil
	}

	if a.Cfg.UseTelegram {
		a.telegramWork(ctx)
	} else {
		logx.Println("Telegram-парсинг отключён настройками.")
	}
	if ctx.Err() != nil {
		return nil
	}

	a.importMyConfigs()
	if ctx.Err() != nil {
		return nil
	}

	if a.Cfg.LoadSources {
		a.loadHTTPSources(ctx)
	} else {
		logx.Println("Загрузка HTTP-источников отключена настройками.")
	}
	if ctx.Err() != nil {
		return nil
	}

	// A brand-new working directory has no configs.txt yet. Create an empty
	// file so the dedup/filter stages below finish cleanly instead of logging
	// filesystem errors on the first run.
	if !fileExists(a.Paths.ConfigsFile) {
		if err := dedup.WriteLines(a.Paths.ConfigsFile, nil); err != nil {
			logx.Printf("Не удалось создать %s: %v\n", a.Paths.ConfigsFile, err)
		}
	}

	if a.Cfg.UseDedup {
		logx.Println("\n" + strings.Repeat("=", 60))
		logx.Println("Дедупликация конфигов")
		logx.Println(strings.Repeat("=", 60))
		if _, err := dedup.Deduplicate(a.Paths.ConfigsFile, a.Paths.CleanFile, a.Cfg.DedupBySNI); err != nil {
			logx.Printf("Дедупликация не удалась: %v\n", err)
		}
	} else {
		logx.Println("Дедупликация отключена настройками. Используем configs.txt как есть.")
		if err := copyFile(a.Paths.ConfigsFile, a.Paths.CleanFile); err != nil {
			logx.Printf("configs.txt недоступен: %v\n", err)
			return nil
		}
	}

	if a.Cfg.FilterIP || a.Cfg.FilterSNI || a.Cfg.FilterOthers {
		logx.Println("\n" + strings.Repeat("=", 60))
		logx.Println("Фильтрация конфигов по IP/SNI")
		logx.Println(strings.Repeat("=", 60))
		stats, err := filter.Apply(a.Paths.CleanFile, a.Paths.WLFilteredFile, a.Paths.BLFilteredFile, filter.Options{
			FilterIP:     a.Cfg.FilterIP,
			FilterSNI:    a.Cfg.FilterSNI,
			FilterOthers: a.Cfg.FilterOthers,
			IPListPath:   a.Paths.IPListFile,
			SNIListPath:  a.Paths.SNIListFile,
		})
		if err != nil {
			logx.Printf("Фильтрация не удалась: %v\n", err)
		} else {
			filter.PrintStats(stats)
		}
	} else {
		logx.Println("Фильтрация отключена настройками. Все конфиги идут в чёрный список.")
		if err := copyFile(a.Paths.CleanFile, a.Paths.BLFilteredFile); err != nil {
			logx.Printf("clean.txt недоступен: %v\n", err)
			return nil
		}
		_ = dedup.WriteLines(a.Paths.WLFilteredFile, nil)
	}

	if ctx.Err() != nil {
		return nil
	}

	if a.Cfg.CheckWhitelist && fileExists(a.Paths.WLFilteredFile) {
		a.checkAndRename(ctx, a.Paths.WLFilteredFile, a.Paths.WhitelistFile)
	} else {
		logx.Println("Проверка белого списка отключена или файл wl_filtered.txt отсутствует.")
		if fileExists(a.Paths.WhitelistFile) {
			_ = os.Remove(a.Paths.WhitelistFile)
		}
	}
	if ctx.Err() != nil {
		return nil
	}

	if a.Cfg.CheckBlacklist && fileExists(a.Paths.BLFilteredFile) {
		a.checkAndRename(ctx, a.Paths.BLFilteredFile, a.Paths.BlacklistFile)
	} else {
		logx.Println("Проверка чёрного списка отключена или файл bl_filtered.txt отсутствует.")
		if fileExists(a.Paths.BlacklistFile) {
			_ = os.Remove(a.Paths.BlacklistFile)
		}
	}
	if ctx.Err() != nil {
		return nil
	}

	if fileExists(a.Paths.WhitelistFile) {
		if err := sortcfg.SortFile(a.Paths.WhitelistFile, a.Cfg.SortGRPCXHTTPTop, a.Cfg.SortUnsafeBottom); err != nil {
			logx.Printf("Сортировка whitelist: %v\n", err)
		}
	}
	if fileExists(a.Paths.BlacklistFile) {
		if err := sortcfg.SortFile(a.Paths.BlacklistFile, a.Cfg.SortGRPCXHTTPTop, a.Cfg.SortUnsafeBottom); err != nil {
			logx.Printf("Сортировка blacklist: %v\n", err)
		}
	}
	if fileExists(a.Paths.ConfigsFile) {
		if err := sortcfg.ByProtocol(a.Paths.ConfigsFile); err != nil {
			logx.Printf("Сортировка configs.txt: %v\n", err)
		}
	}

	if a.Cfg.SaveClash || a.Cfg.SaveXray || a.Cfg.SaveSingbox {
		if fileExists(a.Paths.WhitelistFile) {
			logx.Println("\n" + strings.Repeat("=", 60))
			logx.Println("Конвертация конфигов в форматы Clash / Xray / Sing-box")
			logx.Println(strings.Repeat("=", 60))
			format.New(a.Paths, a.Cfg).GenerateAll(a.Paths.WhitelistFile, a.Paths.BlacklistFile)
		} else {
			logx.Printf("\n[!] whitelist не найден (%s) — конвертация пропущена\n", a.Paths.WhitelistFile)
		}
	}
	return nil
}

// RunLoop repeats RunOnce until the context is cancelled.
func (a *App) RunLoop(ctx context.Context) error {
	for {
		err := a.RunOnce(ctx)
		if err != nil {
			if errors.Is(err, ErrNoWork) {
				return ErrNoWork
			}
			logx.Printf("Ошибка цикла: %v\n", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		rest := a.Cfg.RestTime
		if rest <= 0 {
			logx.Println("Продолжаем без отдыха.")
			continue
		}
		logx.Printf("\nЦикл завершён. Ожидание %d минут...\n", rest)
		select {
		case <-time.After(time.Duration(rest) * time.Minute):
		case <-ctx.Done():
			return nil
		}
	}
}

// prependWhitelistBlacklist copies existing whitelist/blacklist entries to the
// top of configs.txt, removing their duplicates from the rest of the list.
func (a *App) prependWhitelistBlacklist() {
	logx.Println("\n" + strings.Repeat("=", 60))
	logx.Println("Импорт whitelist/blacklist в configs.txt")
	logx.Println(strings.Repeat("=", 60))

	var files []string
	if a.Cfg.ImportWhitelist && fileExists(a.Paths.WhitelistFile) {
		files = append(files, a.Paths.WhitelistFile)
	}
	if a.Cfg.ImportBlacklist && fileExists(a.Paths.BlacklistFile) {
		files = append(files, a.Paths.BlacklistFile)
	}
	if len(files) == 0 {
		logx.Println("Нет файлов для импорта (отключено или файлы отсутствуют).")
		return
	}
	priority := make([]string, 0, 256)
	priorityNorm := make(map[string]struct{})
	for _, file := range files {
		lines, err := dedup.ReadLines(file)
		if err != nil {
			logx.Printf("Ошибка чтения %s: %v\n", file, err)
			continue
		}
		for _, cfg := range lines {
			if !extract.IsValidConfig(cfg) {
				continue
			}
			cfg = extract.EnsureHashSuffix(cfg)
			norm := extract.NormalizeConfig(cfg)
			if _, dup := priorityNorm[norm]; dup {
				continue
			}
			priorityNorm[norm] = struct{}{}
			priority = append(priority, cfg)
		}
	}
	if len(priority) == 0 {
		logx.Println("Нет конфигов в whitelist/blacklist для импорта.")
		return
	}
	old, err := dedup.ReadLines(a.Paths.ConfigsFile)
	if err != nil && !os.IsNotExist(err) {
		logx.Printf("Ошибка чтения %s: %v\n", a.Paths.ConfigsFile, err)
	}
	merged := make([]string, 0, len(priority)+len(old))
	merged = append(merged, priority...)
	for _, line := range old {
		if _, dup := priorityNorm[extract.NormalizeConfig(line)]; dup {
			continue
		}
		merged = append(merged, line)
	}
	if err := dedup.WriteLines(a.Paths.ConfigsFile, merged); err != nil {
		logx.Printf("Ошибка записи в %s: %v\n", a.Paths.ConfigsFile, err)
		return
	}
	logx.Printf("Импортировано %d конфигов в начало %s.\n", len(priority), a.Paths.ConfigsFile)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// appendUnique appends URLs that are not present in path yet. isConfig selects
// config vs source normalisation. Returns the number added.
func appendUnique(path string, urls []string, isConfig bool) (int, error) {
	existing := make(map[string]struct{})
	if fileExists(path) {
		lines, err := dedup.ReadLines(path)
		if err != nil {
			return 0, err
		}
		for _, line := range lines {
			if isConfig {
				existing[extract.NormalizeConfig(line)] = struct{}{}
			} else {
				existing[extract.NormalizeSource(line)] = struct{}{}
			}
		}
	}
	toAdd := make([]string, 0, len(urls))
	for _, raw := range urls {
		if isConfig {
			raw = extract.EnsureHashSuffix(raw)
		}
		var norm string
		if isConfig {
			norm = extract.NormalizeConfig(raw)
		} else {
			norm = extract.NormalizeSource(raw)
		}
		if _, dup := existing[norm]; dup {
			continue
		}
		existing[norm] = struct{}{}
		toAdd = append(toAdd, raw)
	}
	if len(toAdd) == 0 {
		return 0, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, url := range toAdd {
		if _, err := w.WriteString(url + "\n"); err != nil {
			return 0, err
		}
	}
	if err := w.Flush(); err != nil {
		return 0, err
	}
	return len(toAdd), nil
}

// coresWarning prints the same warnings as the original checker.
func (a *App) coresWarning() {
	if a.Cfg.CheckViaXray && !fileExists(a.Paths.XrayPath) {
		logx.Printf("Предупреждение: Xray не найден (%s)\n", a.Paths.XrayPath)
	}
	if !a.Cfg.CheckViaXray {
		logx.Println("Xray проверка отключена — только TCP + Hysteria2")
	}
	if !fileExists(checker.FindHysteria2(a.Paths)) {
		logx.Printf("Предупреждение: Hysteria2 не найден (%s)\n", a.Paths.Hysteria2Path)
	}
}
