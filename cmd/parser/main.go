// Command parser-go is a full Go port of RKP_Parser 5.0.1.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kfwle/parser-go/internal/app"
	"github.com/kfwle/parser-go/internal/checker"
	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/logx"
)

const version = "1.0.0"

func main() {
	os.Exit(run())
}

func run() int {
	dir := flag.String("dir", ".", "рабочая папка с config.json, sources, cores")
	configPath := flag.String("config", "", "путь к config.json (по умолчанию <dir>/config.json)")
	showVersion := flag.Bool("version", false, "показать версию")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Printf("parser-go %s (RKP_Parser 5.0.1 port)\n", version)
		return 0
	}

	paths := config.NewPaths(*dir)
	cfgFile := *configPath
	if cfgFile == "" {
		cfgFile = paths.ConfigFile
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		logx.Printf("[!] Ошибка конфигурации: %v\n", err)
		return 1
	}
	logx.SetVerbose(cfg.Verbose)
	if !fileExists(cfgFile) {
		if err := cfg.Save(cfgFile); err != nil {
			logx.Printf("[!] Не удалось создать %s: %v\n", cfgFile, err)
		} else {
			logx.Printf("[+] Создан конфиг по умолчанию: %s\n", cfgFile)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(sigCh)
		cancel()
	}()
	go func() {
		select {
		case <-sigCh:
			logx.Println("\n[!] Получен сигнал остановки. Завершаем после текущей операции...")
			cancel()
		case <-ctx.Done():
		}
	}()

	command := flag.Arg(0)
	if command == "" {
		if stdinIsTerminal() {
			command = "menu"
		} else {
			command = "once"
		}
	}

	switch command {
	case "menu", "run":
		mainMenu(ctx, &cfg, paths, cfgFile)
		return 0
	case "once":
		ensureCores(ctx, paths)
		if err := app.New(cfg, paths).RunOnce(ctx); err != nil {
			logx.Printf("[!] %v\n", err)
			return 1
		}
		return 0
	case "loop":
		ensureCores(ctx, paths)
		cfg.SingleCycle = false
		if err := app.New(cfg, paths).RunLoop(ctx); err != nil {
			logx.Printf("[!] %v\n", err)
			return 1
		}
		return 0
	case "settings":
		settingsMenu(&cfg, cfgFile)
		return 0
	case "tools":
		toolsMenu(ctx, paths)
		return 0
	case "filter-sources":
		if err := filterSources(ctx, paths); err != nil {
			logx.Printf("[!] %v\n", err)
			return 1
		}
		return 0
	case "version":
		fmt.Printf("parser-go %s (RKP_Parser 5.0.1 port)\n", version)
		return 0
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `parser-go %s — парсер VLESS/Trojan/Hysteria2 конфигов

Использование:
  parser-go [флаги] [команда]

Команды:
  menu            интерактивное меню (по умолчанию в терминале)
  once            один полный цикл парсинга
  loop            циклы с паузами (cycles/rest_time)
  settings        редактирование config.json
  tools           сервисные инструменты
  filter-sources  оставить в sources.txt только рабочие источники
  version         версия

Флаги:
`, version)
	flag.PrintDefaults()
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func ensureCores(ctx context.Context, paths *config.Paths) {
	if err := checker.EnsureCores(ctx, paths); err != nil {
		logx.Printf("[!] %v\n", err)
		logx.Println("[!] Парсер не сможет проверять конфиги без ядер.")
	}
}

var input = bufio.NewReader(os.Stdin)

func readLine() string {
	line, _ := input.ReadString('\n')
	return trimNewline(line)
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
