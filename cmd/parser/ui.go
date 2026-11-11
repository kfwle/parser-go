package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kfwle/parser-go/assets"
	"github.com/kfwle/parser-go/internal/app"
	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/logx"
)

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

func header(title string) {
	logx.Println("\n" + strings.Repeat("=", 60))
	logx.Println(" " + title)
	logx.Println(strings.Repeat("=", 60))
}

func showBanner(paths *config.Paths) {
	banner := assets.Banner
	if data, err := os.ReadFile(paths.BannerFile); err == nil && strings.TrimSpace(string(data)) != "" {
		banner = string(data)
	}
	banner = strings.ReplaceAll(banner, "{version}", version)
	banner = strings.ReplaceAll(banner, "RKP_Parser5.0.1.py", "parser-go v"+version)
	banner = strings.ReplaceAll(banner, "RKP_Parser5.0.1", "parser-go v"+version)
	fmt.Print(banner)
	if !strings.HasSuffix(banner, "\n") {
		fmt.Println()
	}
}

func promptEnter() {
	fmt.Print("\nНажмите Enter...")
	readLine()
}

func waitRest(ctx context.Context, minutes int) {
	if minutes <= 0 {
		return
	}
	logx.Printf("Ожидание %d минут перед следующим циклом...\n", minutes)
	select {
	case <-time.After(time.Duration(minutes) * time.Minute):
	case <-ctx.Done():
	}
}

func mainMenu(ctx context.Context, cfg *config.Config, paths *config.Paths, cfgFile string) {
	for {
		if ctx.Err() != nil {
			return
		}
		clearScreen()
		showBanner(paths)
		header("ГЛАВНОЕ МЕНЮ")
		logx.Println("1. Запуск парсера")
		logx.Println("2. Одиночный цикл (тест)")
		logx.Println("3. Настройки парсера")
		logx.Println("4. Инструменты")
		logx.Println("5. Импорт данных из старой Python-версии")
		logx.Println("6. Выход")
		logx.Println(strings.Repeat("=", 60))
		fmt.Print("Выберите пункт (1-6): ")
		choice := readLine()
		switch choice {
		case "1":
			if !app.New(*cfg, paths).HasWork() {
				app.PrintNoWorkHelp(paths)
				promptEnter()
				continue
			}
			ensureCores(ctx, paths)
			if cfg.Cycles == 0 {
				logx.Println("Запуск парсера в бесконечном режиме...")
				_ = app.New(*cfg, paths).RunLoop(ctx)
			} else {
				for i := 0; i < cfg.Cycles; i++ {
					if ctx.Err() != nil {
						break
					}
					logx.Printf("Запуск цикла %d/%d...\n", i+1, cfg.Cycles)
					if err := app.New(*cfg, paths).RunOnce(ctx); err != nil {
						logx.Printf("[!] %v\n", err)
					}
					if i < cfg.Cycles-1 {
						waitRest(ctx, cfg.RestTime)
					}
				}
				logx.Println("Все циклы выполнены.")
			}
			promptEnter()
		case "2":
			if !app.New(*cfg, paths).HasWork() {
				app.PrintNoWorkHelp(paths)
				promptEnter()
				continue
			}
			ensureCores(ctx, paths)
			logx.Println("Одиночный тестовый цикл...")
			if err := app.New(*cfg, paths).RunOnce(ctx); err != nil {
				logx.Printf("[!] %v\n", err)
			}
			promptEnter()
		case "3":
			settingsMenu(cfg, cfgFile)
		case "4":
			toolsMenu(ctx, paths)
		case "5":
			importMenu(paths, cfg, cfgFile)
		case "6":
			logx.Println("Выход.")
			return
		default:
			logx.Println("Неверный ввод.")
			promptEnter()
		}
	}
}

// filterSources is a thin wrapper so the CLI can call the tools package.
func filterSources(ctx context.Context, paths *config.Paths) error {
	return toolsFilterSources(ctx, paths)
}
