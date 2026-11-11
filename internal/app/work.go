package app

import (
	"errors"
	"os"
	"strings"

	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/dedup"
	"github.com/kfwle/parser-go/internal/logx"
)

// ErrNoWork means there is nothing to parse: no sources, no Telegram channels
// and no existing configs to re-check.
var ErrNoWork = errors.New("нет источников для парсинга")

// HasWork reports whether at least one input contains real data.
func (a *App) HasWork() bool {
	if a.Cfg.LoadSources && countMeaningful(a.Paths.SourcesFile) > 0 {
		return true
	}
	if countMeaningful(a.Paths.MyConfigsFile) > 0 {
		return true
	}
	if a.Cfg.UseTelegram && countMeaningful(a.Paths.TGFile) > 0 {
		return true
	}
	if countMeaningful(a.Paths.ConfigsFile) > 0 {
		return true
	}
	if a.Cfg.ImportWhitelist && countMeaningful(a.Paths.WhitelistFile) > 0 {
		return true
	}
	if a.Cfg.ImportBlacklist && countMeaningful(a.Paths.BlacklistFile) > 0 {
		return true
	}
	return false
}

// countMeaningful counts lines that are not empty and not comments.
func countMeaningful(path string) int {
	lines, err := dedup.ReadLines(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range lines {
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count
}

// PrintNoWorkHelp explains why the parser has nothing to do and how to import
// data from the original Python version.
func PrintNoWorkHelp(paths *config.Paths) {
	logx.Println("[!] Нет данных для парсинга: источники и готовые конфиги пусты.")
	logx.Printf("    sources: %s (%d ссылок)\n", paths.SourcesFile, countMeaningful(paths.SourcesFile))
	logx.Printf("    configs: %s (%d конфигов)\n", paths.ConfigsFile, countMeaningful(paths.ConfigsFile))
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "parser-go"
	}
	logx.Println("    Импорт данных из Python-версии:")
	logx.Printf("      %s -dir %s migrate <папка RKP_Parser5.0.1>\n", exe, paths.Base)
	logx.Println("    Или добавьте ссылки в sources/sources.txt вручную.")
	logx.Println("    В интерактивном меню это пункт 5.")
}
