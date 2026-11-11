# RKP Parser Go

[![CI](https://github.com/kfwle/parser-go/actions/workflows/ci.yml/badge.svg)](https://github.com/kfwle/parser-go/actions/workflows/ci.yml)

Полный порт **RKP_Parser 5.0.1** с Python на Go. Один статический бинарник без Python, Telethon, aiohttp и прочих зависимостей: собирает VLESS / Trojan / Hysteria2 из HTTP-подписок и публичных Telegram-каналов, расшифровывает `happ://crypt*`, проверяет работоспособность через реальные ядра Xray и Hysteria2, определяет страну и генерирует Clash / Xray / sing-box конфиги.

## Возможности

- Загрузка подписок из `sources.txt` в пуле горутин, с HTTP-таймаутами и ограничением размера ответа.
- Обход «Happ»-заголовков (`hwid`, `X-HWID`, Happ User-Agent) для источников, отдающих данные только клиенту Happ.
- Декодирование base64 (включая URL-safe), Xray JSON, Clash/mihomo YAML, sing-box JSON.
- Расшифровка ссылок `happ://crypt/`, `crypt2/`, `crypt3/`, `crypt4/`, `crypt5/` на чистом Go (`crypto/rsa` + ChaCha20-Poly1305).
- Дедупликация по `протокол + id + host + port + SNI`.
- Фильтрация по первым двум октетам IP и по SNI-доменам.
- Проверка через Xray (VLESS/Trojan) и Hysteria2 с SOCKS5-туннелем и несколькими тестовыми URL.
- TCP pre-filter, пул проверки, определение страны через `ipwho.is` / `ip-api.com` или MaxMind GeoLite2.
- Флаги стран в тегах, разделение на безопасные/небезопасные, сортировка xhttp → grpc → tcp.
- Генерация Clash YAML, Xray JSON и sing-box JSON с уникальными именами прокси.
- Telegram через публичные web-превью `t.me/s/<канал>`: без API ID, сессии и MTProto-прокси.
- Меню, настройки и инструменты (фильтрация источников, очистка, обновление ядер, загрузка whitelist-ов).
- Кроссплатформенность: Linux, macOS, Windows (amd64/arm64).

## Что исправлено по сравнению с Python-версией

- Убраны гонки: общий набор `existing_norm` и статистика защищены мьютексом.
- Исправлен баг, из-за которого `my_configs.txt` никогда не попадал в `configs.txt`.
- Убрано двойное URL-кодирование `path` / `serviceName`, ломавшее часть конфигов.
- Убран принудительный `flow=xtls-rprx-vision` для VLESS без Reality.
- `country_threads` теперь реально используется (раньше был мёртвой настройкой).
- Починена проверка: только HTTPS `generate_204` URL, таймаут распределяется между ними — заблокированный первый хост не съедает попытку.
- Уникальные имена прокси в Clash; запятые вычищаются, чтобы не ломать `MATCH`-правило.
- MaxMind теперь умеет резолвить домены, а не только IP-хосты.
- Корректное завершение по Ctrl+C: контекст отменяет загрузки, проверки и дочерние ядра; повторный Ctrl+C завершает процесс сразу.
- Ограничение размера HTTP-ответов, таймауты TLS/соединения, атомарная запись конфигов и списков.
- При первом запуске создаются пустые `sources/*.txt` с подсказками.

## Безопасность и устойчивость

- Ядра Xray/Hysteria2 скачиваются только по проверенному TLS; SHA-256 сверяется с digest из GitHub API, когда он доступен.
- Telegram (`t.me`), MaxMind и whitelist-ы скачиваются с проверкой сертификата. Подписки — в режиме совместимости с Python (`verify=False`), потому что часть источников использует самоподписанные сертификаты.
- SSRF-защита: источники и редиректы на loopback/private/link-local/CGNAT блокируются. Для локального сервера подписок: `PARSER_ALLOW_PRIVATE=1`.
- Лимиты: 8 МБ на источник, 16 КБ на конфиг, 256 МБ на файл ядра; длинные строки не ломают сканер списков.
- Happ `crypt5` защищён от переполнения длины сегмента, Telegram-парсер не путает цитируемый reply с текстом сообщения.
- Если нужного ядра нет или **все** конфиги не прошли проверку, старые whitelist/blacklist не перезаписываются, а `garbage_conf.txt` не пополняется.
- Hysteria2 не входит в Xray JSON (Xray её не поддерживает); она генерируется в Clash и sing-box.

## Отличие Telegram-режима

Python-версия использовала Telethon и MTProto. Go-версия читает **публичные** каналы через `https://t.me/s/<name>` с пагинацией `?before=<id>`:

- не нужны `API_ID` / `API_HASH`, сессия и MTProto-прокси;
- работают только публичные каналы (у приватных web-превью нет);
- вложения-документы не скачиваются (в web-превью их нет) — конфиги берутся из текста сообщений;
- настройка `download_files_tg` остаётся для совместимости и игнорируется;
- остальные флаги (`save_*_tg`, `decode_*_tg`, `decrypt_happ_tg`, `save_sources_tg`) работают как раньше.

## Готовые бинарники

Готовые сборки для Linux, macOS и Windows (amd64/arm64) лежат в [Releases](https://github.com/kfwle/parser-go/releases). Скачайте файл под свою ОС и запускайте:

```bash
chmod +x parser-go-linux-amd64
./parser-go-linux-amd64
```

## Сборка

Нужен Go **1.26+**.

```bash
git clone https://github.com/kfwle/parser-go.git
cd parser-go
go build -trimpath -ldflags="-s -w" -o parser-go ./cmd/parser
```

Или:

```bash
make build      # бинарник ./parser-go
make test       # go test ./...
make vet        # go vet ./...
make cross      # linux/darwin/windows amd64+arm64
```

При первом запуске ядра Xray и Hysteria2 автоматически скачиваются в `cores/` с GitHub Releases. Без них можно работать, отключив `check_via_xray` (конфиги будут помечаться рабочими без проверки) — но Hysteria2 всё равно проверяется своим клиентом.

## Быстрый старт

```bash
./parser-go                 # интерактивное меню (в терминале)
./parser-go once            # один цикл без меню
./parser-go loop            # циклы с паузами (cycles / rest_time)
./parser-go settings        # редактирование config.json
./parser-go tools           # сервисные инструменты
./parser-go -dir /opt/rkp once
```

### Переезд с Python-версии

Не нужно вручную копировать 11 тысяч ссылок: перенесите источники и настройки одной командой.

```bash
./parser-go -dir /opt/rkp migrate /путь/к/RKP_Parser5.0.1
```

Или в интерактивном меню: **5. Импорт данных из старой Python-версии**.

Импортируются `sources/*.txt`, `config.json`, `configs/generic/whitelist.txt` и `blacklist.txt`. Пустые шаблоны и конфиг по умолчанию заменяются автоматически; реальные пользовательские файлы не перезаписываются без флага `-force`.

Если источников нет, парсер не уходит в пустой бесконечный цикл, а показывает, что именно пусто и как импортировать данные.

Структура рабочей папки:

```
config.json            настройки (создаётся автоматически)
sources/
  sources.txt          ссылки на подписки
  tg.txt               ссылки на Telegram-каналы
  my_configs.txt       свои конфиги (приоритетнее источников)
  ip_list.txt          IP-префиксы для белого списка (1.2)
  sni_list.txt         SNI-домены для белого списка
  banner.txt           ASCII-баннер (необязательно)
cores/                 xray, hysteria2 (скачиваются автоматически)
temp/                  промежуточные файлы, garbage, configs.txt
configs/generic/       whitelist.txt, blacklist.txt
configs/clash/         whitelist.yaml, blacklist.yaml
configs/xray/          whitelist.json, blacklist.json
configs/sing-box/      whitelist.json, blacklist.json
backups/               бэкапы sources.txt
```

1. Заполните `sources/sources.txt` (по одной ссылке на строку).
2. Для белого списка скачайте списки через меню **Инструменты → 5/6** или положите свои `ip_list.txt` / `sni_list.txt`.
3. Запустите `./parser-go once` или меню **1**.

Если фильтры IP/SNI включены, а списки пусты, все конфиги уйдут в чёрный список — это ожидаемое поведение. Для первого теста можно отключить `filter_ip` / `filter_sni` и `filter_others` в настройках.

## Конфигурация

Все ключи совпадают с Python-версией, поэтому старый `config.json` подходит без изменений. Полный пример — [config.example.json](config.example.json). Основные группы:

| Группа | Ключи |
| --- | --- |
| Основные | `verbose`, `cycles`, `single_cycle`, `rest_time` |
| Источники | `load_sources`, `http_threads`, `filter_sources`, `fix_github_urls`, `save_*_http`, `decode_*_http`, `decrypt_happ_http` |
| Telegram | `use_telegram`, `tg_messages_limit`, `save_*_tg`, `decode_*_tg`, `decrypt_happ_tg`, `save_sources_tg` |
| Дедуп/сортировка | `use_dedup`, `dedup_by_sni`, `sort_grpc_xhttp_top`, `sort_unsafe_bottom` |
| Фильтрация | `filter_ip`, `filter_sni`, `filter_others`, `import_whitelist`, `import_blacklist` |
| Проверка | `check_timeout`, `check_threads`, `check_whitelist`, `check_blacklist`, `check_via_xray`, `tcp_check`, `save_garbage` |
| Страна | `determine_country`, `use_maxmind_country`, `country_threads`, `encode_names` |
| Форматы | `save_clash`, `save_xray`, `save_singbox` |

`use_mtproto` сохранён для совместимости, но web-парсеру Telegram он не нужен.

## Архитектура

```
cmd/parser/            CLI и интерактивное меню
internal/config/       настройки, пути, шаблоны sources
internal/extract/      regex, base64, JSON/YAML → URL, парсинг vless/trojan/hy2
internal/happ/         расшифровка happ://crypt1-5
internal/fetch/        HTTP, Happ-заголовки, GitHub URL fix
internal/dedup/        дедупликация
internal/filter/       IP/SNI фильтрация
internal/checker/      ядра Xray/Hysteria2, SOCKS5, TCP pre-filter, скачивание ядер
internal/country/      ipwho.is / ip-api.com / MaxMind
internal/outbound/     Xray streamSettings, sing-box outbounds
internal/format/       Clash YAML, Xray JSON, sing-box JSON
internal/sortcfg/      сортировка итоговых списков
internal/telegram/     публичные каналы через t.me/s
internal/app/          пайплайн и этапы
internal/tools/        сервисные инструменты
assets/keys/           ключи Happ (embed)
```

## Тесты

```bash
go test ./...
go test -race ./...
go vet ./...
```

Покрыты: парсинг и round-trip конфигов, base64, JSON/YAML-конвертеры, Happ crypt1–5 (полный цикл шифрование→расшифровка), дедупликация, фильтрация, генерация всех форматов, Telegram HTML, настройки и полный интеграционный прогон пайплайна на локальном HTTP-сервере.

## Лицензия

GPL-3.0 — как у оригинального RKP_Parser. См. [LICENSE](LICENSE).

Проект предназначен для образовательных и исследовательских целей. Используйте на свой страх и риск и соблюдайте законодательство своей юрисдикции.