package checker

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
		if err := downloadArchive(ctx, "XTLS/Xray-core", xrayAsset(), xrayDownloadURL(),
			paths.XrayPath, "xray"+exeSuffix()); err != nil {
			return fmt.Errorf("xray: %w", err)
		}
		downloaded = true
	}
	if !fileExists(paths.Hysteria2Path) {
		logx.Println("[+] Hysteria2 не найден. Скачиваю...")
		if err := downloadFile(ctx, "apernet/hysteria", hysteriaAsset(), hysteriaDownloadURL(),
			paths.Hysteria2Path); err != nil {
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

// UpdateCores forces a re-download of both cores. New binaries are downloaded
// next to the old ones and only replace them after both downloads succeed.
func UpdateCores(ctx context.Context, paths *config.Paths) error {
	if err := paths.EnsureDirs(); err != nil {
		return err
	}
	newXray := paths.XrayPath + ".new"
	newHy2 := paths.Hysteria2Path + ".new"
	_ = os.Remove(newXray)
	_ = os.Remove(newHy2)
	defer os.Remove(newXray)
	defer os.Remove(newHy2)

	if err := downloadArchive(ctx, "XTLS/Xray-core", xrayAsset(), xrayDownloadURL(),
		newXray, "xray"+exeSuffix()); err != nil {
		return fmt.Errorf("xray: %w", err)
	}
	if err := downloadFile(ctx, "apernet/hysteria", hysteriaAsset(), hysteriaDownloadURL(),
		newHy2); err != nil {
		return fmt.Errorf("hysteria2: %w", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(newXray, 0o755)
		_ = os.Chmod(newHy2, 0o755)
	}
	if err := replaceFile(newXray, paths.XrayPath); err != nil {
		return fmt.Errorf("replace xray: %w", err)
	}
	if err := replaceFile(newHy2, paths.Hysteria2Path); err != nil {
		return fmt.Errorf("replace hysteria2: %w", err)
	}
	logx.Println("Ядра успешно обновлены.")
	return nil
}

// maxCoreBytes limits both the downloaded archive and each extracted file.
const maxCoreBytes = 256 << 20

func downloadFile(ctx context.Context, repo, assetName, fallbackURL, dest string) error {
	rawURL, digest := resolveReleaseAsset(ctx, repo, assetName, fallbackURL)
	return downloadWithRetries(ctx, rawURL, digest, dest)
}

func downloadArchive(ctx context.Context, repo, assetName, fallbackURL, dest, innerName string) error {
	rawURL, digest := resolveReleaseAsset(ctx, repo, assetName, fallbackURL)
	zipPath := dest + ".zip"
	if err := downloadWithRetries(ctx, rawURL, digest, zipPath); err != nil {
		return err
	}
	defer os.Remove(zipPath)
	return extractZipFile(zipPath, dest, innerName)
}

type releaseResponse struct {
	Assets []struct {
		Name   string `json:"name"`
		URL    string `json:"browser_download_url"`
		Digest string `json:"digest"`
	} `json:"assets"`
}

// resolveReleaseAsset asks the GitHub API for the asset URL and its SHA-256
// digest. If the API is unavailable (rate limit/network), it falls back to the
// public download URL; TLS verification still protects that path.
func resolveReleaseAsset(ctx context.Context, repo, assetName, fallbackURL string) (string, string) {
	apiCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(apiCtx, http.MethodGet,
		"https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return fallbackURL, ""
	}
	req.Header.Set("User-Agent", fetch.DefaultUserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := fetch.SecureClient.Do(req)
	if err != nil {
		logx.Verbosef("  GitHub API недоступен (%v), проверяю только TLS\n", err)
		return fallbackURL, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logx.Verbosef("  GitHub API: HTTP %d, проверяю только TLS\n", resp.StatusCode)
		return fallbackURL, ""
	}
	var data releaseResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&data); err != nil {
		logx.Verbosef("  GitHub API: %v, проверяю только TLS\n", err)
		return fallbackURL, ""
	}
	for _, asset := range data.Assets {
		if asset.Name == assetName && asset.URL != "" {
			return asset.URL, strings.TrimPrefix(asset.Digest, "sha256:")
		}
	}
	return fallbackURL, ""
}

type barWriter struct{ bar *logx.Bar }

func (w barWriter) Write(p []byte) (int, error) {
	w.bar.Add(int64(len(p)))
	return len(p), nil
}

func downloadWithRetries(ctx context.Context, rawURL, expectedSHA256, dest string) error {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		logx.Printf("  Загрузка: %s\n", rawURL)
		err := downloadOnce(ctx, rawURL, expectedSHA256, dest)
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

func downloadOnce(ctx context.Context, rawURL, expectedSHA256, dest string) error {
	dlCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", fetch.DefaultUserAgent)
	resp, err := fetch.SecureClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxCoreBytes {
		return fmt.Errorf("файл слишком большой: %d байт", resp.ContentLength)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	cleanup := func() {
		f.Close()
		os.Remove(tmp)
	}
	hash := sha256.New()
	bar := logx.NewBar("Загрузка", resp.ContentLength)
	defer bar.Finish()
	written, err := io.Copy(io.MultiWriter(f, hash, barWriter{bar}),
		io.LimitReader(resp.Body, maxCoreBytes+1))
	if err != nil {
		cleanup()
		return err
	}
	if written > maxCoreBytes {
		cleanup()
		return fmt.Errorf("файл слишком большой: %d байт", written)
	}
	if expectedSHA256 != "" {
		actual := hex.EncodeToString(hash.Sum(nil))
		if !strings.EqualFold(actual, expectedSHA256) {
			cleanup()
			return fmt.Errorf("SHA-256 не совпал: получено %s, ожидалось %s", actual, expectedSHA256)
		}
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(dest)
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func extractZipFile(zipPath, dest, innerName string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer zr.Close()
	for _, file := range zr.File {
		if filepath.Base(file.Name) != innerName {
			continue
		}
		if file.UncompressedSize64 > maxCoreBytes {
			return fmt.Errorf("файл в архиве слишком большой: %d байт", file.UncompressedSize64)
		}
		rc, err := file.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		if err := writeLimitedFile(dest, rc); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("file %q not found in archive", innerName)
}

func writeLimitedFile(dest string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp := dest + ".extract"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	cleanup := func() {
		f.Close()
		os.Remove(tmp)
	}
	written, err := io.Copy(f, io.LimitReader(r, maxCoreBytes+1))
	if err != nil {
		cleanup()
		return err
	}
	if written > maxCoreBytes {
		cleanup()
		return fmt.Errorf("извлечённый файл слишком большой")
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(dest)
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func replaceFile(src, dst string) error {
	if runtime.GOOS == "windows" {
		_ = os.Remove(dst)
	}
	return os.Rename(src, dst)
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
