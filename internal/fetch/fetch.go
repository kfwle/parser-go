// Package fetch downloads HTTP sources with the same resilience tricks as the
// original parser (Happ headers, base64 unwrapping, GitHub commit URL repair).
package fetch

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/kfwle/parser-go/internal/extract"
	"github.com/kfwle/parser-go/internal/logx"
)

const (
	// DefaultUserAgent is sent for regular requests.
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	// HappHWID is the device id expected by Happ subscription servers.
	HappHWID = "d060e73eb61d1ba7"
	// HappUserAgent is the Happ client user agent.
	HappUserAgent = "Happ/3.26.0/Android/17771400994551771562"

	maxBodyBytes = 64 << 20
)

var githubRawRe = regexp.MustCompile(`^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([a-fA-F0-9]{40})(/.*)$`)

// Client is a shared, pooled HTTP client.
var Client = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        300,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
		ForceAttemptHTTP2:   true,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// Get performs a GET request and returns the response body as text.
func Get(ctx context.Context, rawURL string, timeout time.Duration, headers map[string]string) (string, error) {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("Accept", "*/*")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// FetchSource downloads a subscription URL. When the normal request fails or
// returns almost nothing, it retries with Happ client headers.
func FetchSource(ctx context.Context, rawURL string, allowHapp bool, timeout time.Duration) (content string, usedHapp bool, err error) {
	content, err = Get(ctx, rawURL, timeout, nil)
	if err == nil && len(strings.TrimSpace(content)) >= 10 {
		return content, false, nil
	}
	if !allowHapp {
		if err == nil {
			err = fmt.Errorf("response too short")
		}
		return "", false, err
	}
	happContent, happErr := fetchWithHapp(ctx, rawURL, timeout)
	if happErr == nil && len(strings.TrimSpace(happContent)) >= 10 {
		return happContent, true, nil
	}
	if err == nil {
		err = fmt.Errorf("response too short")
	}
	if happErr != nil && err == nil {
		err = happErr
	}
	return "", false, err
}

// fetchWithHapp tries the URL with hwid and Happ headers. Trial order matches
// the original: hwid URL first, then the original, for every user agent.
func fetchWithHapp(ctx context.Context, rawURL string, timeout time.Duration) (string, error) {
	withHWID := rawURL
	if !strings.Contains(rawURL, "hwid=") {
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		withHWID = rawURL + sep + "hwid=" + HappHWID
	}
	var lastErr error
	for _, tryURL := range []string{withHWID, rawURL} {
		headers := map[string]string{
			"User-Agent": HappUserAgent,
			"X-HWID":     HappHWID,
			"Accept":     "*/*",
		}
		content, err := Get(ctx, tryURL, timeout, headers)
		if err != nil {
			lastErr = err
			continue
		}
		content = strings.TrimSpace(content)
		if content == "" || strings.Contains(strings.ToLower(content), "<html") {
			continue
		}
		if extract.IsBase64Blob(content) {
			if decoded, decErr := extract.DecodeBase64(content); decErr == nil {
				content = string(decoded)
			}
		}
		return content, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable Happ response")
	}
	return "", lastErr
}

// FixGitHubURL replaces a commit hash in raw.githubusercontent.com URLs with
// "main" or "master" when that branch exists.
func FixGitHubURL(ctx context.Context, rawURL string) string {
	m := githubRawRe.FindStringSubmatch(rawURL)
	if m == nil {
		return rawURL
	}
	user, repo, path := m[1], m[2], m[4]
	for _, branch := range []string{"main", "master"} {
		candidate := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s%s", user, repo, branch, path)
		if headOK(ctx, candidate, 5*time.Second) {
			return candidate
		}
	}
	return rawURL
}

func headOK(ctx context.Context, rawURL string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", DefaultUserAgent)
	resp, err := Client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// ValidateURL checks that a source looks like an absolute http(s) URL.
func ValidateURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// LogError prints a cleaned-up fetch error.
func LogError(rawURL string, err error) {
	if logx.Verbose() {
		logx.Printf("  [!] %s: %v\n", rawURL, err)
	}
}
