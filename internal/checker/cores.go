package checker

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/fetch"
	"github.com/kfwle/parser-go/internal/logx"
)

// Asset names for the current platform.
func xrayAsset() string {
	switch runtime.GOOS {
	case "darwin":
		if runtime.GOARCH == "arm64" {
			return "Xray-macos-arm64-v8a.zip"
		}
		return "Xray-macos-64.zip"
	case "windows":
		if runtime.GOARCH == "386" {
			return "Xray-windows-32.zip"
		}
		if runtime.GOARCH == "arm64" {
			return "Xray-windows-arm64-v8a.zip"
		}
		return "Xray-windows-64.zip"
	default:
		switch runtime.GOARCH {
		case "arm64":
			return "Xray-linux-arm64-v8a.zip"
		case "386":
			return "Xray-linux-32.zip"
		default:
			return "Xray-linux-64.zip"
		}
	}
}

func hysteriaAsset() string {
	arch := runtime.GOARCH
	switch runtime.GOOS {
	case "darwin":
		if arch == "arm64" {
			return "hysteria-darwin-arm64"
		}
		return "hysteria-darwin-amd64"
	case "windows":
		if arch == "arm64" {
			return "hysteria-windows-arm64.exe"
		}
		return "hysteria-windows-amd64.exe"
	default:
		switch arch {
		case "arm64":
			return "hysteria-linux-arm64"
		case "386":
			return "hysteria-linux-386"
		default:
			return "hysteria-linux-amd64"
		}
	}
}

func xrayDownloadURL() string {
	return "https://github.com/XTLS/Xray-core/releases/latest/download/" + xrayAsset()
}

func hysteriaDownloadURL() string {
	return "https://github.com/apernet/hysteria/releases/latest/download/" + hysteriaAsset()
}

// EnsureCores downloads Xray and Hysteria2 if they are missing.
func EnsureCores(ctx context.Context, paths *config.Paths) error {
	if err := paths.EnsureDirs(); err != nil {
		return err
	}
	downloaded := false
	if !fileExists(paths.XrayPath) {
		logx.Printf("[+] Xray-core не найден. Скачиваю (%s/%s)...\n", runtime.GOOS, runtime.GOARCH)
		if err := downloadArchive(ctx, xrayDownloadURL(), paths.XrayPath, "xray"+exeSuffix()); err != nil {
			return fmt.Errorf("xray: %w", err)
		}
		downloaded = true
	}
	if !fileExists(paths.Hysteria2Path) {
		logx.Println("[+] Hysteria2 не найден. Скачиваю...")
		if err := downloadFile(ctx, hysteriaDownloadURL(), paths.Hysteria2Path); err != nil {
			return fmt.Errorf("hysteria2: %w", err)
		}
		downloaded = true
	}
	if downloaded {
		logx.Println("[+] Ядра успешно загружены.")
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{paths.XrayPath, paths.Hysteria2Path} {
			_ = os.Chmod(p, 0o755)
		}
	}
	return nil
}

// UpdateCores forces a re-download of both cores.
func UpdateCores(ctx context.Context, paths *config.Paths) error {
	for _, p := range []string{paths.XrayPath, paths.Hysteria2Path} {
		if fileExists(p) {
			if err := os.Remove(p); err != nil {
				return fmt.Errorf("remove %s: %w", p, err)
			}
			logx.Printf("  Удалён старый: %s\n", p)
		}
	}
	return EnsureCores(ctx, paths)
}

func downloadFile(ctx context.Context, rawURL, dest string) error {
	return downloadWithRetries(ctx, rawURL, func(body io.Reader, size int64) error {
		return writeFileFromReader(dest, body, size)
	})
}

func downloadArchive(ctx context.Context, rawURL, dest, innerName string) error {
	zipPath := dest + ".zip"
	err := downloadWithRetries(ctx, rawURL, func(body io.Reader, size int64) error {
		return writeFileFromReader(zipPath, body, size)
	})
	if err != nil {
		return err
	}
	defer os.Remove(zipPath)
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer zr.Close()
	for _, file := range zr.File {
		if filepath.Base(file.Name) != innerName {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		if err := writeFileFromReader(dest, rc, int64(file.UncompressedSize64)); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("file %q not found in archive", innerName)
}

func downloadWithRetries(ctx context.Context, rawURL string, write func(io.Reader, int64) error) error {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		logx.Printf("  Загрузка: %s\n", rawURL)
		err := downloadOnce(ctx, rawURL, write)
		if err == nil {
			return nil
		}
		lastErr = err
		logx.Printf("\n  Попытка %d/3 не удалась: %v\n", attempt, err)
		if attempt < 3 {
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return lastErr
}

func downloadOnce(ctx context.Context, rawURL string, write func(io.Reader, int64) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", fetch.DefaultUserAgent)
	resp, err := fetch.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	bar := logx.NewBar("Загрузка", resp.ContentLength)
	defer bar.Finish()
	return write(io.TeeReader(resp.Body, barWriter{bar}), resp.ContentLength)
}

type barWriter struct{ bar *logx.Bar }

func (w barWriter) Write(p []byte) (int, error) {
	w.bar.Add(int64(len(p)))
	return len(p), nil
}

func writeFileFromReader(dest string, r io.Reader, size int64) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// FindHysteria2 returns the configured Hysteria2 binary, falling back to the
// legacy file names used by the Python parser.
func FindHysteria2(paths *config.Paths) string {
	if fileExists(paths.Hysteria2Path) {
		return paths.Hysteria2Path
	}
	patterns := []string{
		"hysteria2-*", "hysteria-*", "hysteria2.exe", "hysteria.exe",
	}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(paths.CoresDir, pattern))
		for _, m := range matches {
			if !strings.HasSuffix(strings.ToLower(m), ".zip") {
				return m
			}
		}
	}
	return paths.Hysteria2Path
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
