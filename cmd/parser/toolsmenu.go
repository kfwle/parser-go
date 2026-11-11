package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/logx"
	"github.com/kfwle/parser-go/internal/tools"
)

func toolsMenu(ctx context.Context, paths *config.Paths) {
	for {
		if ctx.Err() != nil {
			return
		}
		clearScreen()
		header("ИНСТРУМЕНТЫ")
		logx.Println("1. Фильтрация источников")
		logx.Println("2. Очистить temp файлы")
		logx.Println("3. Очистить всё кроме garbage pool")
		logx.Println("4. Обновить ядра Xray/Hysteria2")
		logx.Println("5. Скачать новый IP whitelist")
		logx.Println("6. Скачать новый domain whitelist")
		logx.Println("7. Назад в главное меню")
		logx.Println(strings.Repeat("=", 60))
		fmt.Print("Выберите пункт (1-7): ")
		choice := readLine()
		var err error
		switch choice {
		case "1":
			err = tools.FilterSources(ctx, paths)
		case "2":
			err = tools.ClearTemp(paths)
		case "3":
			err = tools.ClearExceptGarbage(paths)
		case "4":
			err = tools.UpdateCores(ctx, paths)
		case "5":
			err = tools.DownloadIPWhitelist(ctx, paths)
		case "6":
			err = tools.DownloadDomainWhitelist(ctx, paths)
		case "7":
			return
		default:
			logx.Println("Неверный ввод.")
		}
		if err != nil {
			logx.Printf("[!] %v\n", err)
		}
		promptEnter()
	}
}

func toolsFilterSources(ctx context.Context, paths *config.Paths) error {
	return tools.FilterSources(ctx, paths)
}
