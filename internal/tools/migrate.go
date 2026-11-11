package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/logx"
)

// MigrateReport lists files copied or skipped during migration.
type MigrateReport struct {
	Copied  []string
	Skipped []string
}

// Migrate copies sources and settings from a Python parser directory into the
// Go parser working directory. Empty templates and the default config are
// replaced automatically; real user data is only replaced with force=true.
func Migrate(fromDir string, paths *config.Paths, force bool) (MigrateReport, error) {
	var report MigrateReport
	fromDir = strings.TrimSpace(fromDir)
	if fromDir == "" {
		return report, fmt.Errorf("не указана папка старой версии")
	}
	fromAbs, err := filepath.Abs(fromDir)
	if err != nil {
		return report, err
	}
	srcSources := filepath.Join(fromAbs, "sources", "sources.txt")
	if _, err := os.Stat(srcSources); err != nil {
		return report, fmt.Errorf("в %s нет sources/sources.txt — это не папка RKP_Parser?", fromAbs)
	}
	if err := paths.EnsureDirs(); err != nil {
		return report, err
	}

	files := []struct{ src, dst string }{
		{srcSources, paths.SourcesFile},
		{filepath.Join(fromAbs, "sources", "tg.txt"), paths.TGFile},
		{filepath.Join(fromAbs, "sources", "my_configs.txt"), paths.MyConfigsFile},
		{filepath.Join(fromAbs, "sources", "ip_list.txt"), paths.IPListFile},
		{filepath.Join(fromAbs, "sources", "sni_list.txt"), paths.SNIListFile},
		{filepath.Join(fromAbs, "sources", "banner.txt"), paths.BannerFile},
		{filepath.Join(fromAbs, "configs", "generic", "whitelist.txt"), paths.WhitelistFile},
		{filepath.Join(fromAbs, "configs", "generic", "blacklist.txt"), paths.BlacklistFile},
		{filepath.Join(fromAbs, "temp", "garbage_conf.txt"), paths.GarbageFile},
		{filepath.Join(fromAbs, "temp", "GeoLite2-Country.mmdb"), paths.MaxmindDB},
	}
	for _, item := range files {
		if _, err := os.Stat(item.src); err != nil {
			report.Skipped = append(report.Skipped, relName(item.src, fromAbs)+" (нет в источнике)")
			continue
		}
		replace := force || !fileExists(item.dst) || isTemplateFile(item.dst)
		if !replace {
			report.Skipped = append(report.Skipped, relName(item.src, fromAbs)+" (уже есть)")
			continue
		}
		if err := copyFileTo(item.src, item.dst); err != nil {
			return report, fmt.Errorf("копирование %s: %w", item.src, err)
		}
		report.Copied = append(report.Copied, relName(item.src, fromAbs))
	}

	// config.json: replace only when the destination still has default values.
	srcConfig := filepath.Join(fromAbs, "config.json")
	if _, err := os.Stat(srcConfig); err == nil {
		if _, err := config.Load(srcConfig); err != nil {
			report.Skipped = append(report.Skipped, "config.json (невалидный, пропущен)")
		} else {
			isDefault := !fileExists(paths.ConfigFile)
			if !isDefault {
				if dstCfg, loadErr := config.Load(paths.ConfigFile); loadErr == nil && dstCfg == config.Default() {
					isDefault = true
				}
			}
			if force || isDefault {
				if err := copyFileTo(srcConfig, paths.ConfigFile); err != nil {
					return report, fmt.Errorf("копирование config.json: %w", err)
				}
				report.Copied = append(report.Copied, "config.json")
			} else {
				report.Skipped = append(report.Skipped, "config.json (уже настроен)")
			}
		}
	}

	logx.Printf("Импорт из %s:\n", fromAbs)
	for _, name := range report.Copied {
		logx.Printf("  + %s\n", name)
	}
	for _, name := range report.Skipped {
		logx.Printf("  - %s\n", name)
	}
	logx.Printf("Скопировано: %d, пропущено: %d\n", len(report.Copied), len(report.Skipped))
	if len(report.Copied) == 0 {
		logx.Println("Нечего импортировать. Используйте -force, чтобы перезаписать существующие файлы.")
	}
	return report, nil
}

func copyFileTo(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(src); err == nil {
		mode = st.Mode().Perm()
	}
	return os.WriteFile(dst, data, mode)
}

// isTemplateFile reports whether a file is empty or contains only comments.
func isTemplateFile(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return false
		}
	}
	return true
}

func relName(path, base string) string {
	if rel, err := filepath.Rel(base, path); err == nil {
		return rel
	}
	return path
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
