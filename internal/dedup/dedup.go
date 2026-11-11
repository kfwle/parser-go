// Package dedup removes duplicate proxy configurations by protocol, id, host,
// port and (optionally) SNI.
package dedup

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kfwle/parser-go/internal/extract"
	"github.com/kfwle/parser-go/internal/logx"
)

// maxLineBytes prevents a single hostile line from aborting list processing.
const maxLineBytes = 1 << 20

// ReadLines reads a text file, trimming whitespace and skipping empty and
// over-long lines. Unlike bufio.Scanner it survives a multi-megabyte line
// without failing the whole stage.
func ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	r := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" && len(line) <= maxLineBytes {
			lines = append(lines, line)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	return lines, nil
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

// WriteLines writes lines atomically: data goes to a temp file, is synced and
// then renamed over the destination. A crash cannot leave a truncated list.
func WriteLines(path string, lines []string) error { return writeLines(path, lines) }

func writeLines(path string, lines []string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() {
		f.Close()
		os.Remove(tmp)
	}
	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := w.WriteString(line + "\n"); err != nil {
			cleanup()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(path) // os.Rename cannot replace an existing file there
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
