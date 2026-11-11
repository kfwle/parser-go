package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/logx"
)

type settingDef struct {
	key   string
	label string
	kind  string // bool | int
	lo    int
	hi    int
}

var settingGroups = []struct {
	name  string
	items []settingDef
}{
	{"ОСНОВНЫЕ", []settingDef{
		{"verbose", "Подробный вывод (verbose)", "bool", 0, 0},
		{"cycles", "Полные циклы (0-бесконечно)", "int", 0, 999},
		{"single_cycle", "Одиночный цикл (для теста)", "bool", 0, 0},
		{"rest_time", "Отдых между циклами (мин, 0-выкл)", "int", 0, 600},
	}},
	{"ЗАГРУЗКА ИСТОЧНИКОВ", []settingDef{
		{"load_sources", "Скачивать источники из sources.txt", "bool", 0, 0},
		{"http_threads", "Потоков загрузки (1-100)", "int", 1, 100},
		{"filter_sources", "Фильтр: только источники с конфигами", "bool", 0, 0},
		{"fix_github_urls", "Исправлять GitHub коммит -> main/master", "bool", 0, 0},
		{"save_vless_http", "Сохранять VLESS из источников", "bool", 0, 0},
		{"save_trojan_http", "Сохранять TROJAN из источников", "bool", 0, 0},
		{"save_hy2_http", "Сохранять HY2 из источников", "bool", 0, 0},
		{"decrypt_happ_http", "Расшифровка Happ из источников", "bool", 0, 0},
		{"decode_base64_http", "Декодировать base64", "bool", 0, 0},
		{"decode_json_http", "Конвертировать JSON", "bool", 0, 0},
		{"decode_yaml_http", "Конвертировать Sing-Box YAML", "bool", 0, 0},
		{"save_failed_sources", "Чёрный список неудачных источников", "bool", 0, 0},
	}},
	{"TELEGRAM (web preview)", []settingDef{
		{"use_telegram", "Использовать Telegram", "bool", 0, 0},
		{"use_mtproto", "MTProto прокси (не нужен web-режиму)", "bool", 0, 0},
		{"save_vless_tg", "VLESS из Telegram", "bool", 0, 0},
		{"save_trojan_tg", "TROJAN из Telegram", "bool", 0, 0},
		{"save_hy2_tg", "HY2 из Telegram", "bool", 0, 0},
		{"decode_base64_tg", "Декодировать base64", "bool", 0, 0},
		{"decode_json_tg", "Конвертировать JSON", "bool", 0, 0},
		{"decode_yaml_tg", "Конвертировать YAML", "bool", 0, 0},
		{"download_files_tg", "Скачивать файлы (только MTProto)", "bool", 0, 0},
		{"decrypt_happ_tg", "Расшифровка Happ", "bool", 0, 0},
		{"save_sources_tg", "Искать источники", "bool", 0, 0},
		{"tg_messages_limit", "Лимит сообщений (20-100000)", "int", 20, 100000},
	}},
	{"ДЕДУПЛИКАЦИЯ И СОРТИРОВКА", []settingDef{
		{"use_dedup", "Дедупликация конфигов", "bool", 0, 0},
		{"dedup_by_sni", "Дедуплицировать по uuid+ip+port+sni", "bool", 0, 0},
		{"sort_grpc_xhttp_top", "GRPC/XHTTP в начало белого списка", "bool", 0, 0},
		{"sort_unsafe_bottom", "Небезопасные конфиги вниз", "bool", 0, 0},
	}},
	{"ФИЛЬТРАЦИЯ ПО IP/SNI", []settingDef{
		{"filter_ip", "Фильтр по IP", "bool", 0, 0},
		{"filter_sni", "Фильтр по SNI", "bool", 0, 0},
		{"filter_others", "Остальные в чёрный список", "bool", 0, 0},
		{"import_whitelist", "Импорт whitelist в configs.txt", "bool", 0, 0},
		{"import_blacklist", "Импорт blacklist в configs.txt", "bool", 0, 0},
	}},
	{"ПРОВЕРКА КОНФИГОВ", []settingDef{
		{"check_whitelist", "Проверять белый список", "bool", 0, 0},
		{"check_blacklist", "Проверять чёрный список", "bool", 0, 0},
		{"check_via_xray", "Проверка через Xray (vless/trojan)", "bool", 0, 0},
		{"tcp_check", "TCP pre-filter (быстрый host:port check)", "bool", 0, 0},
		{"check_timeout", "Таймаут проверки (3-60 сек)", "int", 3, 60},
		{"check_threads", "Потоков проверки (1-500)", "int", 1, 500},
		{"save_garbage", "Сохранять нерабочие в garbage", "bool", 0, 0},
	}},
	{"ОПРЕДЕЛЕНИЕ СТРАНЫ", []settingDef{
		{"determine_country", "Определять страну", "bool", 0, 0},
		{"use_maxmind_country", "Использовать MaxMind DB (вместо API)", "bool", 0, 0},
		{"country_threads", "Потоков (1-100)", "int", 1, 100},
		{"encode_names", "Кодировать названия", "bool", 0, 0},
	}},
	{"ФОРМАТЫ ВЫВОДА", []settingDef{
		{"save_clash", "Конвертировать в Clash", "bool", 0, 0},
		{"save_xray", "Конвертировать в Xray JSON", "bool", 0, 0},
		{"save_singbox", "Конвертировать в Sing-box", "bool", 0, 0},
	}},
}

func settingsMenu(cfg *config.Config, configPath string) {
	for {
		clearScreen()
		header("НАСТРОЙКИ ПАРСЕРА")
		values := configToMap(*cfg)
		num := 0
		flat := make([]settingDef, 0, 64)
		for _, group := range settingGroups {
			logx.Printf("\n── %s ──\n", group.name)
			for _, item := range group.items {
				display := ""
				switch item.kind {
				case "bool":
					if asBool(values[item.key]) {
						display = "Да"
					} else {
						display = "Нет"
					}
				case "int":
					n := asInt(values[item.key])
					if item.key == "cycles" && n == 0 {
						display = "∞"
					} else {
						display = strconv.Itoa(n)
					}
				}
				logx.Printf("  %d. %s | %s\n", num, item.label, display)
				flat = append(flat, item)
				num++
			}
		}
		logx.Printf("\nВсего: %d настроек. Введите номер для изменения, 'q' для выхода:\n", num)
		fmt.Print("-> ")
		choice := strings.TrimSpace(readLine())
		if strings.EqualFold(choice, "q") {
			if err := cfg.Save(configPath); err != nil {
				logx.Printf("Ошибка сохранения: %v\n", err)
			}
			return
		}
		idx, err := strconv.Atoi(choice)
		if err != nil || idx < 0 || idx >= len(flat) {
			logx.Println("Неверный номер.")
			promptEnter()
			continue
		}
		editSetting(values, flat[idx])
		applyMap(cfg, values)
		cfg.Normalize()
		logx.SetVerbose(cfg.Verbose)
		if err := cfg.Save(configPath); err != nil {
			logx.Printf("Ошибка сохранения: %v\n", err)
		} else {
			logx.Println("Настройка сохранена.")
		}
		promptEnter()
	}
}

func editSetting(values map[string]any, item settingDef) {
	switch item.kind {
	case "bool":
		current := asBool(values[item.key])
		state := "Нет"
		if current {
			state = "Да"
		}
		fmt.Printf("Введите 'y' для включения, 'n' для выключения (текущее: %s): ", state)
		switch strings.ToLower(strings.TrimSpace(readLine())) {
		case "y", "yes", "да":
			values[item.key] = true
		case "n", "no", "нет":
			values[item.key] = false
		default:
			logx.Println("Неверный ввод.")
		}
	case "int":
		current := asInt(values[item.key])
		fmt.Printf("Введите значение (%d-%d, текущее: %d): ", item.lo, item.hi, current)
		raw := strings.TrimSpace(readLine())
		n, err := strconv.Atoi(raw)
		if err != nil || n < item.lo || n > item.hi {
			logx.Printf("Некорректное значение. Допустимо %d-%d.\n", item.lo, item.hi)
			return
		}
		values[item.key] = n
	}
}

func configToMap(cfg config.Config) map[string]any {
	data, _ := json.Marshal(cfg)
	out := make(map[string]any)
	_ = json.Unmarshal(data, &out)
	return out
}

func applyMap(cfg *config.Config, values map[string]any) {
	data, err := json.Marshal(values)
	if err != nil {
		return
	}
	var next config.Config
	if err := json.Unmarshal(data, &next); err != nil {
		return
	}
	*cfg = next
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func asInt(v any) int {
	f, ok := v.(float64)
	if !ok {
		return 0
	}
	return int(f)
}
