// Package config stores runtime settings and resolves all filesystem paths.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Config mirrors config.json of the original Python parser. JSON tags are kept
// identical so existing configuration files keep working.
type Config struct {
	Verbose     bool `json:"verbose"`
	Cycles      int  `json:"cycles"`
	SingleCycle bool `json:"single_cycle"`
	RestTime    int  `json:"rest_time"` // minutes

	ImportWhitelist bool `json:"import_whitelist"`
	ImportBlacklist bool `json:"import_blacklist"`

	UseTelegram     bool `json:"use_telegram"`
	UseMTProto      bool `json:"use_mtproto"` // reserved; web parser needs no MTProto
	SaveVlessTG     bool `json:"save_vless_tg"`
	SaveTrojanTG    bool `json:"save_trojan_tg"`
	SaveHy2TG       bool `json:"save_hy2_tg"`
	DownloadFilesTG bool `json:"download_files_tg"`
	DecryptHappTG   bool `json:"decrypt_happ_tg"`
	SaveSourcesTG   bool `json:"save_sources_tg"`
	DecodeBase64TG  bool `json:"decode_base64_tg"`
	DecodeJSONTG    bool `json:"decode_json_tg"`
	DecodeYAMLTG    bool `json:"decode_yaml_tg"`
	TGMessagesLimit int  `json:"tg_messages_limit"`

	LoadSources      bool `json:"load_sources"`
	HTTPThreads      int  `json:"http_threads"`
	SaveVlessHTTP    bool `json:"save_vless_http"`
	SaveTrojanHTTP   bool `json:"save_trojan_http"`
	SaveHy2HTTP      bool `json:"save_hy2_http"`
	DecryptHappHTTP  bool `json:"decrypt_happ_http"`
	DecodeBase64HTTP bool `json:"decode_base64_http"`
	DecodeJSONHTTP   bool `json:"decode_json_http"`
	DecodeYAMLHTTP   bool `json:"decode_yaml_http"`
	FilterSources    bool `json:"filter_sources"`
	FixGithubURLs    bool `json:"fix_github_urls"`
	SaveFailedSource bool `json:"save_failed_sources"`

	UseDedup         bool `json:"use_dedup"`
	DedupBySNI       bool `json:"dedup_by_sni"`
	SortGRPCXHTTPTop bool `json:"sort_grpc_xhttp_top"`
	SortUnsafeBottom bool `json:"sort_unsafe_bottom"`

	FilterIP     bool `json:"filter_ip"`
	FilterSNI    bool `json:"filter_sni"`
	FilterOthers bool `json:"filter_others"`

	CheckTimeout   int  `json:"check_timeout"`
	CheckThreads   int  `json:"check_threads"`
	CountryThreads int  `json:"country_threads"`
	CheckWhitelist bool `json:"check_whitelist"`
	CheckBlacklist bool `json:"check_blacklist"`
	CheckViaXray   bool `json:"check_via_xray"`
	TCPCheck       bool `json:"tcp_check"`
	SaveGarbage    bool `json:"save_garbage"`

	DetermineCountry bool `json:"determine_country"`
	UseMaxmind       bool `json:"use_maxmind_country"`
	EncodeNames      bool `json:"encode_names"`

	SaveClash   bool `json:"save_clash"`
	SaveXray    bool `json:"save_xray"`
	SaveSingbox bool `json:"save_singbox"`
}

// Default returns the same defaults as RKP_Parser 5.0.1.
func Default() Config {
	return Config{
		Verbose:          true,
		Cycles:           0,
		SingleCycle:      false,
		RestTime:         30,
		ImportWhitelist:  true,
		ImportBlacklist:  true,
		UseTelegram:      false,
		UseMTProto:       true,
		SaveVlessTG:      true,
		SaveTrojanTG:     true,
		SaveHy2TG:        true,
		DownloadFilesTG:  true,
		DecryptHappTG:    true,
		SaveSourcesTG:    true,
		DecodeBase64TG:   true,
		DecodeJSONTG:     true,
		DecodeYAMLTG:     true,
		TGMessagesLimit:  1000,
		LoadSources:      true,
		HTTPThreads:      50,
		SaveVlessHTTP:    true,
		SaveTrojanHTTP:   true,
		SaveHy2HTTP:      true,
		DecryptHappHTTP:  true,
		DecodeBase64HTTP: true,
		DecodeJSONHTTP:   true,
		DecodeYAMLHTTP:   true,
		FilterSources:    true,
		FixGithubURLs:    true,
		SaveFailedSource: true,
		UseDedup:         true,
		DedupBySNI:       true,
		SortGRPCXHTTPTop: true,
		SortUnsafeBottom: true,
		FilterIP:         true,
		FilterSNI:        true,
		FilterOthers:     true,
		CheckTimeout:     12,
		CheckThreads:     80,
		CountryThreads:   20,
		CheckWhitelist:   true,
		CheckBlacklist:   true,
		CheckViaXray:     true,
		TCPCheck:         false,
		SaveGarbage:      true,
		DetermineCountry: true,
		UseMaxmind:       false,
		EncodeNames:      true,
		SaveClash:        true,
		SaveXray:         true,
		SaveSingbox:      true,
	}
}

// Load reads path over the defaults. A missing file is not an error: defaults
// are returned instead. Malformed JSON is reported to the caller.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Default(), fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.Normalize()
	return cfg, nil
}

// Save writes the configuration atomically.
func (c Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		// os.Rename does not replace an existing file on Windows.
		_ = os.Remove(path)
	}
	return os.Rename(tmp, path)
}

// Normalize clamps unsafe values to sensible ranges.
func (c *Config) Normalize() {
	c.HTTPThreads = clamp(c.HTTPThreads, 1, 200)
	c.CheckThreads = clamp(c.CheckThreads, 1, 500)
	c.CountryThreads = clamp(c.CountryThreads, 1, 100)
	c.CheckTimeout = clamp(c.CheckTimeout, 3, 60)
	c.RestTime = clamp(c.RestTime, 0, 1440)
	c.TGMessagesLimit = clamp(c.TGMessagesLimit, 20, 100000)
	if c.Cycles < 0 {
		c.Cycles = 0
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Paths resolves every file and directory used by the parser.
type Paths struct {
	Base string

	SourcesDir string
	ConfigsDir string
	CoresDir   string
	TempDir    string
	BackupsDir string

	GenericDir string
	ClashDir   string
	XrayDir    string
	SingboxDir string

	ConfigFile        string
	SourcesFile       string
	TGFile            string
	MyConfigsFile     string
	IPListFile        string
	SNIListFile       string
	BannerFile        string
	ConfigsFile       string
	CleanFile         string
	WhitelistFile     string
	BlacklistFile     string
	BlacklistSources  string
	GarbageFile       string
	WLFilteredFile    string
	BLFilteredFile    string
	TelegramFilesDir  string
	DownloadedIDsFile string
	MaxmindDB         string
	XrayPath          string
	Hysteria2Path     string
}

// NewPaths builds paths rooted at base (empty means current directory).
func NewPaths(base string) *Paths {
	if base == "" {
		base = "."
	}
	abs, err := filepath.Abs(base)
	if err == nil {
		base = abs
	}
	p := &Paths{Base: base}
	p.SourcesDir = filepath.Join(base, "sources")
	p.ConfigsDir = filepath.Join(base, "configs")
	p.CoresDir = filepath.Join(base, "cores")
	p.TempDir = filepath.Join(base, "temp")
	p.BackupsDir = filepath.Join(base, "backups")
	p.GenericDir = filepath.Join(p.ConfigsDir, "generic")
	p.ClashDir = filepath.Join(p.ConfigsDir, "clash")
	p.XrayDir = filepath.Join(p.ConfigsDir, "xray")
	p.SingboxDir = filepath.Join(p.ConfigsDir, "sing-box")

	p.ConfigFile = filepath.Join(base, "config.json")
	p.SourcesFile = filepath.Join(p.SourcesDir, "sources.txt")
	p.TGFile = filepath.Join(p.SourcesDir, "tg.txt")
	p.MyConfigsFile = filepath.Join(p.SourcesDir, "my_configs.txt")
	p.IPListFile = filepath.Join(p.SourcesDir, "ip_list.txt")
	p.SNIListFile = filepath.Join(p.SourcesDir, "sni_list.txt")
	p.BannerFile = filepath.Join(p.SourcesDir, "banner.txt")
	p.ConfigsFile = filepath.Join(p.TempDir, "configs.txt")
	p.CleanFile = filepath.Join(p.TempDir, "clean.txt")
	p.WhitelistFile = filepath.Join(p.GenericDir, "whitelist.txt")
	p.BlacklistFile = filepath.Join(p.GenericDir, "blacklist.txt")
	p.BlacklistSources = filepath.Join(p.TempDir, "blacklist_sources.txt")
	p.GarbageFile = filepath.Join(p.TempDir, "garbage_conf.txt")
	p.WLFilteredFile = filepath.Join(p.TempDir, "wl_filtered.txt")
	p.BLFilteredFile = filepath.Join(p.TempDir, "bl_filtered.txt")
	p.TelegramFilesDir = filepath.Join(p.TempDir, "telegram_files")
	p.DownloadedIDsFile = filepath.Join(p.TempDir, "downloaded_ids.txt")
	p.MaxmindDB = filepath.Join(p.TempDir, "GeoLite2-Country.mmdb")
	p.XrayPath = filepath.Join(p.CoresDir, "xray"+exeSuffix())
	p.Hysteria2Path = filepath.Join(p.CoresDir, "hysteria2"+exeSuffix())
	return p
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// EnsureDirs creates every directory the parser writes to and seeds empty
// source files so the first run has a clear place to put data.
func (p *Paths) EnsureDirs() error {
	dirs := []string{
		p.SourcesDir, p.CoresDir, p.TempDir, p.BackupsDir,
		p.GenericDir, p.ClashDir, p.XrayDir, p.SingboxDir,
		p.TelegramFilesDir,
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	templates := map[string]string{
		p.SourcesFile:   "# Ссылки на подписки (по одной на строку)\n",
		p.TGFile:        "# Ссылки на Telegram-каналы, например https://t.me/example\n",
		p.MyConfigsFile: "# Ваши собственные конфиги (vless://, trojan://, hy2://)\n",
		p.IPListFile:    "# IP-префиксы для белого списка, например 1.2\n",
		p.SNIListFile:   "# SNI-домены для белого списка, например example.com\n",
	}
	for path, content := range templates {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				return fmt.Errorf("create %s: %w", path, err)
			}
		}
	}
	return nil
}
