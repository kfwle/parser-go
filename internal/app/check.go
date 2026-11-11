package app

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/kfwle/parser-go/internal/checker"
	"github.com/kfwle/parser-go/internal/country"
	"github.com/kfwle/parser-go/internal/dedup"
	"github.com/kfwle/parser-go/internal/extract"
	"github.com/kfwle/parser-go/internal/logx"
)

type aliveConfig struct {
	url  string
	ping int
}

// checkAndRename performs the full validation stage for one list.
func (a *App) checkAndRename(ctx context.Context, input, output string) {
	logx.Println("\n" + strings.Repeat("=", 60))
	logx.Printf("Проверка конфигов: %s -> %s\n", input, output)
	logx.Println(strings.Repeat("=", 60))

	if !fileExists(input) {
		logx.Printf("Файл %s не найден. Пропускаем.\n", input)
		return
	}

	garbageNorm := make(map[string]struct{})
	if a.Cfg.SaveGarbage && fileExists(a.Paths.GarbageFile) {
		if lines, err := dedup.ReadLines(a.Paths.GarbageFile); err == nil {
			for _, cfg := range lines {
				garbageNorm[extract.NormalizeConfig(cfg)] = struct{}{}
			}
			logx.Printf("Загружено %d мусорных конфигов (будут пропущены)\n", len(garbageNorm))
		}
	}

	if a.Cfg.TCPCheck {
		logx.Println("TCP pre-filter: включён (быстрый host:port check)")
	}
	a.coresWarning()

	lines, err := dedup.ReadLines(input)
	if err != nil {
		logx.Printf("Не удалось прочитать %s: %v\n", input, err)
		return
	}
	urls := make([]string, 0, len(lines))
	skipped := 0
	for _, line := range lines {
		if !extract.IsValidConfig(line) {
			continue
		}
		if a.Cfg.SaveGarbage {
			if _, bad := garbageNorm[extract.NormalizeConfig(line)]; bad {
				skipped++
				continue
			}
		}
		urls = append(urls, line)
	}
	if skipped > 0 {
		logx.Printf("Пропущено мусорных конфигов: %d (из %d)\n", skipped, skipped+len(urls))
	}
	if len(urls) == 0 {
		logx.Println("Нет новых конфигов для проверки (все в мусоре).")
		return
	}
	logx.Printf("Таймаут: %d сек, потоков: %d\n", a.Cfg.CheckTimeout, a.Cfg.CheckThreads)
	logx.Printf("Проверяем %d конфигов\n", len(urls))

	chk := checker.New(a.Paths, a.Cfg.CheckTimeout)
	tempDir, err := os.MkdirTemp(a.Paths.TempDir, "checker_")
	if err != nil {
		logx.Printf("Не удалось создать временную папку: %v\n", err)
		return
	}
	defer os.RemoveAll(tempDir)

	var mu sync.Mutex
	alive := make([]aliveConfig, 0, len(urls))
	checked := make(map[string]struct{}, len(urls))
	aliveByProto := make(map[string]int)
	logx.RunPool(ctx, urls, a.Cfg.CheckThreads, "Проверка", func(ctx context.Context, raw string) {
		ok, ping := chk.CheckConfig(ctx, raw, tempDir, tempDir, a.Cfg.TCPCheck, a.Cfg.CheckViaXray)
		if ctx.Err() != nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		checked[raw] = struct{}{}
		if ok {
			alive = append(alive, aliveConfig{url: raw, ping: ping})
			if ep, parsed := extract.ParseConfig(raw); parsed {
				aliveByProto[ep.Label()]++
			}
		}
	})
	logx.Printf("Итог проверки: проверено %d/%d | Работает: %d\n", len(checked), len(urls), len(alive))
	if len(aliveByProto) > 0 {
		parts := make([]string, 0, len(aliveByProto))
		for proto, count := range aliveByProto {
			if count > 0 {
				parts = append(parts, proto+": "+itoa(count))
			}
		}
		logx.Println(strings.Join(parts, " | "))
	}

	if a.Cfg.SaveGarbage {
		a.saveGarbage(checked, alive)
	}

	if len(alive) == 0 {
		if err := dedup.WriteLines(output, nil); err != nil {
			logx.Printf("Не удалось записать %s: %v\n", output, err)
		}
		logx.Println("Нет рабочих конфигов, выходной файл пуст.")
		return
	}

	if !a.Cfg.DetermineCountry {
		written := make([]string, 0, len(alive))
		for _, item := range alive {
			written = append(written, item.url)
		}
		if err := dedup.WriteLines(output, written); err != nil {
			logx.Printf("Не удалось записать %s: %v\n", output, err)
		} else {
			logx.Printf("Сохранено %d конфигов без определения страны.\n", len(written))
		}
		return
	}

	logx.Printf("\nОпределение стран для %d рабочих конфигов...\n", len(alive))
	detector := country.New(chk, a.Paths, a.Cfg.UseMaxmind)
	updated := make([]string, len(alive))
	indices := make([]int, len(alive))
	for i := range indices {
		indices[i] = i
	}
	logx.RunPool(ctx, indices, a.Cfg.CountryThreads, "Страны", func(ctx context.Context, i int) {
		info, ok := detector.Detect(ctx, alive[i].url)
		if ok {
			updated[i] = country.UpdateURLTag(alive[i].url, &info, a.Cfg.EncodeNames)
		} else {
			updated[i] = country.UpdateURLTag(alive[i].url, nil, a.Cfg.EncodeNames)
		}
	})

	safe := make([]string, 0, len(updated))
	unsafe := make([]string, 0, len(updated))
	for _, raw := range updated {
		if raw == "" {
			continue
		}
		if extract.IsSecure(raw) {
			safe = append(safe, raw)
		} else {
			unsafe = append(unsafe, raw)
		}
	}
	result := append(safe, unsafe...)
	if err := dedup.WriteLines(output, result); err != nil {
		logx.Printf("Не удалось записать %s: %v\n", output, err)
		return
	}
	logx.Printf("Определение стран завершено. Обновлённые конфиги сохранены в %s\n", output)
	logx.Printf("  Безопасные: %d, Небезопасные (⚠️): %d\n", len(safe), len(unsafe))
}

func (a *App) saveGarbage(checked map[string]struct{}, alive []aliveConfig) {
	aliveSet := make(map[string]struct{}, len(alive))
	for _, item := range alive {
		aliveSet[item.url] = struct{}{}
	}
	existing := make(map[string]struct{})
	if fileExists(a.Paths.GarbageFile) {
		if lines, err := dedup.ReadLines(a.Paths.GarbageFile); err == nil {
			for _, cfg := range lines {
				existing[extract.NormalizeConfig(cfg)] = struct{}{}
			}
		}
	}
	var toAdd []string
	for raw := range checked {
		if _, ok := aliveSet[raw]; ok {
			continue
		}
		norm := extract.NormalizeConfig(raw)
		if _, dup := existing[norm]; dup {
			continue
		}
		existing[norm] = struct{}{}
		toAdd = append(toAdd, raw)
	}
	if len(toAdd) == 0 {
		return
	}
	if err := appendRaw(a.Paths.GarbageFile, toAdd); err != nil {
		logx.Printf("Не удалось записать garbage_conf.txt: %v\n", err)
		return
	}
	logx.Printf("Добавлено в garbage_conf.txt: %d нерабочих конфигов\n", len(toAdd))
}

func appendRaw(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	_, err = f.WriteString(b.String())
	return err
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
