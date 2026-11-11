// Package dedup removes duplicate proxy configurations by protocol, id, host,
// port and (optionally) SNI.
package dedup

import (
	"bufio"
	"os"
	"strings"

	"github.com/kfwle/parser-go/internal/extract"
	"github.com/kfwle/parser-go/internal/logx"
)

// ReadLines reads a text file, trimming whitespace and skipping empty lines.
func ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

// LoadSet returns a set of duplicate keys for all configs in path.
func LoadSet(path string, bySNI bool) (map[extract.Key]struct{}, error) {
	lines, err := ReadLines(path)
	if err != nil {
		return nil, err
	}
	set := make(map[extract.Key]struct{}, len(lines))
	for _, line := range lines {
		if key, ok := extract.DedupKey(line, bySNI); ok {
			set[key] = struct{}{}
		}
	}
	return set, nil
}

// Deduplicate writes unique configs from input to output and returns the number
// of unique configurations.
func Deduplicate(input, output string, bySNI bool) (int, error) {
	configs, err := ReadLines(input)
	if err != nil {
		return 0, err
	}
	seen := make(map[extract.Key]struct{}, len(configs))
	unique := make([]string, 0, len(configs))
	for _, cfg := range configs {
		key, ok := extract.DedupKey(cfg, bySNI)
		if !ok {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, cfg)
	}
	if err := writeLines(output, unique); err != nil {
		return 0, err
	}
	logx.Printf("Дедупликация: %s -> %s, уникальных: %d (удалено %d)\n",
		input, output, len(unique), len(configs)-len(unique))
	return len(unique), nil
}

// WriteLines writes lines terminated by \n.
func WriteLines(path string, lines []string) error { return writeLines(path, lines) }

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := w.WriteString(line + "\n"); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
