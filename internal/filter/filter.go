// Package filter splits configs into whitelist/blacklist buckets based on the
// first two octets of an IP host or an exact SNI match.
package filter

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/kfwle/parser-go/internal/dedup"
	"github.com/kfwle/parser-go/internal/extract"
	"github.com/kfwle/parser-go/internal/logx"
)

// Options controls which filters are active.
type Options struct {
	FilterIP     bool
	FilterSNI    bool
	FilterOthers bool
	IPListPath   string
	SNIListPath  string
}

// Stats reports filter results.
type Stats struct {
	Total      int
	IPMatched  int
	SNIMatched int
	Others     int
}

// LoadIPPrefixes reads a list of "a.b" prefixes (four-octet addresses are
// truncated to the first two octets, like the original).
func LoadIPPrefixes(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	set := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ".")
		if len(parts) >= 2 {
			set[parts[0]+"."+parts[1]] = struct{}{}
		}
	}
	return set, sc.Err()
}

// LoadSNISet reads SNI domains; matching is case-insensitive.
func LoadSNISet(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	set := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[strings.ToLower(line)] = struct{}{}
	}
	return set, sc.Err()
}

// Apply reads cleanFile and writes wlFile/blFile.
func Apply(cleanFile, wlFile, blFile string, opt Options) (Stats, error) {
	var stats Stats
	if !opt.FilterIP && !opt.FilterSNI {
		logx.Println("IP и SNI фильтрация отключены. Все конфиги идут в чёрный список.")
		lines, err := dedup.ReadLines(cleanFile)
		if err != nil {
			return stats, err
		}
		stats.Total = len(lines)
		stats.Others = len(lines)
		if err := dedup.WriteLines(blFile, lines); err != nil {
			return stats, err
		}
		return stats, dedup.WriteLines(wlFile, nil)
	}

	ipSet := map[string]struct{}{}
	sniSet := map[string]struct{}{}
	if opt.FilterIP {
		set, err := LoadIPPrefixes(opt.IPListPath)
		if err != nil {
			logx.Printf("Файл %s не найден (%v). IP-фильтрация пропущена.\n", opt.IPListPath, err)
			opt.FilterIP = false
		} else {
			ipSet = set
		}
	}
	if opt.FilterSNI {
		set, err := LoadSNISet(opt.SNIListPath)
		if err != nil {
			logx.Printf("Файл %s не найден (%v). SNI-фильтрация пропущена.\n", opt.SNIListPath, err)
			opt.FilterSNI = false
		} else {
			sniSet = set
		}
	}
	logx.Printf("Загружено IP-префиксов: %d\n", len(ipSet))
	logx.Printf("Загружено SNI: %d\n", len(sniSet))

	configs, err := dedup.ReadLines(cleanFile)
	if err != nil {
		return stats, err
	}
	stats.Total = len(configs)
	logx.Printf("Всего конфигов для фильтрации: %d\n", stats.Total)

	white := make([]string, 0, stats.Total)
	black := make([]string, 0, stats.Total)
	for _, cfg := range configs {
		host, _, ok := extract.HostPort(cfg)
		if opt.FilterIP && ok {
			if prefix, isIPv4 := ipPrefix(host); isIPv4 {
				if _, matched := ipSet[prefix]; matched {
					white = append(white, cfg)
					stats.IPMatched++
					continue
				}
			}
		}
		if opt.FilterSNI {
			if sni := extract.ExtractSNI(cfg); sni != "" {
				if _, matched := sniSet[strings.ToLower(sni)]; matched {
					white = append(white, cfg)
					stats.SNIMatched++
					continue
				}
			}
		}
		black = append(black, cfg)
	}
	stats.Others = len(black)

	if err := dedup.WriteLines(wlFile, white); err != nil {
		return stats, err
	}
	if opt.FilterOthers {
		if err := dedup.WriteLines(blFile, black); err != nil {
			return stats, err
		}
	} else {
		if err := dedup.WriteLines(blFile, nil); err != nil {
			return stats, err
		}
		logx.Println("Сохранение остальных конфигов отключено (bl_filtered.txt очищен).")
	}
	return stats, nil
}

// ipPrefix returns "a.b" for an IPv4 literal.
func ipPrefix(host string) (string, bool) {
	ip := net.ParseIP(host)
	if ip == nil {
		return "", false
	}
	v4 := ip.To4()
	if v4 == nil {
		return "", false
	}
	return strconv.Itoa(int(v4[0])) + "." + strconv.Itoa(int(v4[1])), true
}

// PrintStats prints a human-readable summary.
func PrintStats(s Stats) {
	logx.Printf("Результаты фильтрации:\n")
	logx.Printf("  IP-совпадения: %d\n", s.IPMatched)
	logx.Printf("  SNI-совпадения: %d\n", s.SNIMatched)
	logx.Printf("  Остальные: %d\n", s.Others)
}
