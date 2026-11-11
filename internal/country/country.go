// Package country detects the exit country of a working proxy through its
// SOCKS5 inbound (ipwho.is / ip-api.com) or a local MaxMind database.
package country

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"github.com/kfwle/parser-go/internal/checker"
	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/extract"
	"github.com/kfwle/parser-go/internal/fetch"
	"github.com/kfwle/parser-go/internal/logx"
	"github.com/kfwle/parser-go/internal/model"
)

const maxmindURL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

const unknownTag = "🌐 Неизвестно [#РКП]"

// Info is a country name and ISO code.
type Info struct {
	Name string
	Code string
}

// Detector resolves exit countries.
type Detector struct {
	checker  *checker.Checker
	paths    *config.Paths
	useMaxDB bool

	once   sync.Once
	reader *maxminddb.Reader
	dbErr  error
}

// New creates a country detector.
func New(c *checker.Checker, paths *config.Paths, useMaxmind bool) *Detector {
	return &Detector{checker: c, paths: paths, useMaxDB: useMaxmind}
}

// Detect returns the country for raw. ok=false means it could not be determined.
func (d *Detector) Detect(ctx context.Context, raw string) (Info, bool) {
	ep, ok := extract.ParseConfig(raw)
	if !ok {
		return Info{}, false
	}
	if d.useMaxDB {
		return d.detectMaxmind(ctx, ep.Host)
	}
	var info Info
	var found bool
	workDir := d.paths.TempDir
	run := func(socksAddr string) error {
		info, found = d.lookupViaSocks(ctx, socksAddr)
		return nil
	}
	var err error
	if ep.Protocol == model.Hysteria2 {
		err = d.checker.WithHysteria2Socks(ctx, raw, workDir, run)
	} else {
		err = d.checker.WithXraySocks(ctx, raw, workDir, run)
	}
	if err != nil || !found {
		return Info{}, false
	}
	return info, true
}

type ipwhoResponse struct {
	Success     bool   `json:"success"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
}

type ipapiResponse struct {
	Status      string `json:"status"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
}

func (d *Detector) lookupViaSocks(ctx context.Context, socksAddr string) (Info, bool) {
	apis := []struct {
		url  string
		name string
	}{
		{"https://ipwho.is?lang=ru", "ipwho.is"},
		{"http://ip-api.com/json/?fields=country,countryCode&lang=ru", "ip-api.com"},
	}
	for attempt := 1; attempt <= 2; attempt++ {
		for _, api := range apis {
			reqCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
			body, err := checker.HTTPGetViaSocks(reqCtx, socksAddr, api.url, 6*time.Second)
			cancel()
			if err != nil {
				continue
			}
			switch api.name {
			case "ipwho.is":
				var resp ipwhoResponse
				if json.Unmarshal(body, &resp) == nil && resp.Success && resp.Country != "" && resp.CountryCode != "" {
					return Info{Name: strings.TrimSpace(resp.Country), Code: strings.TrimSpace(resp.CountryCode)}, true
				}
			case "ip-api.com":
				var resp ipapiResponse
				if json.Unmarshal(body, &resp) == nil && resp.Status == "success" && resp.Country != "" && resp.CountryCode != "" {
					return Info{Name: strings.TrimSpace(resp.Country), Code: strings.TrimSpace(resp.CountryCode)}, true
				}
			}
		}
		if attempt == 1 {
			select {
			case <-time.After(500 * time.Millisecond):
			case <-ctx.Done():
				return Info{}, false
			}
		}
	}
	return Info{}, false
}

func (d *Detector) detectMaxmind(ctx context.Context, host string) (Info, bool) {
	reader, err := d.openDB(ctx)
	if err != nil {
		logx.Printf("MaxMind DB недоступна: %v\n", err)
		return Info{}, false
	}
	lookupHost := host
	if net.ParseIP(lookupHost) == nil {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", lookupHost)
		if err != nil || len(ips) == 0 {
			return Info{}, false
		}
		lookupHost = ips[0].String()
	}
	var record struct {
		Country struct {
			ISOCode string            `maxminddb:"iso_code"`
			Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
	}
	if err := reader.Lookup(net.ParseIP(lookupHost), &record); err != nil {
		return Info{}, false
	}
	code := strings.TrimSpace(record.Country.ISOCode)
	name := record.Country.Names["ru"]
	if name == "" {
		name = record.Country.Names["en"]
	}
	if code == "" || name == "" {
		return Info{}, false
	}
	return Info{Name: name, Code: code}, true
}

func (d *Detector) openDB(ctx context.Context) (*maxminddb.Reader, error) {
	d.once.Do(func() {
		if _, err := os.Stat(d.paths.MaxmindDB); err != nil {
			logx.Println("Скачивание MaxMind GeoLite2-Country базы данных...")
			data, err := fetch.Get(ctx, maxmindURL, 180*time.Second, nil)
			if err != nil {
				d.dbErr = fmt.Errorf("download: %w", err)
				return
			}
			if err := os.MkdirAll(d.paths.TempDir, 0o755); err != nil {
				d.dbErr = err
				return
			}
			if err := os.WriteFile(d.paths.MaxmindDB, []byte(data), 0o644); err != nil {
				d.dbErr = err
				return
			}
			logx.Printf("База данных MaxMind сохранена: %s\n", d.paths.MaxmindDB)
		}
		reader, err := maxminddb.Open(d.paths.MaxmindDB)
		if err != nil {
			d.dbErr = err
			return
		}
		d.reader = reader
	})
	return d.reader, d.dbErr
}

// UpdateURLTag replaces the fragment with flag, country name and project tag.
func UpdateURLTag(raw string, info *Info, encode bool) string {
	tag := unknownTag
	if info != nil && info.Name != "" && info.Code != "" {
		tag = fmt.Sprintf("%s %s [#РКП]", FlagEmoji(info.Code), info.Name)
	}
	encoded := tag
	if encode {
		encoded = extract.PercentEncode(tag)
	}
	base := raw
	if i := strings.IndexByte(base, '#'); i >= 0 {
		base = base[:i]
	}
	return base + "#" + encoded
}

// FlagEmoji returns the regional-indicator flag for a two-letter country code.
func FlagEmoji(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	runes := []rune(code)
	if len(runes) != 2 {
		return "🌐"
	}
	var b strings.Builder
	for _, r := range runes {
		if r < 'A' || r > 'Z' {
			return "🌐"
		}
		b.WriteRune(rune(127397) + r)
	}
	return b.String()
}
