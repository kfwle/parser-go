// Package checker validates proxy configs by running local Xray/Hysteria2 cores
// and sending a request through their SOCKS5 inbound.
package checker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/extract"
	"github.com/kfwle/parser-go/internal/logx"
	"github.com/kfwle/parser-go/internal/model"
	"github.com/kfwle/parser-go/internal/outbound"
)

const (
	// CoreStartupTimeout is how long we wait for a SOCKS port to open.
	CoreStartupTimeout = 3 * time.Second
	// CoreKillDelay lets the OS release ports between attempts.
	CoreKillDelay = 300 * time.Millisecond
)

// Checker owns core paths and timeouts.
type Checker struct {
	Paths    *config.Paths
	Timeout  time.Duration
	TestURLs []string
}

// New creates a checker; timeout is in seconds.
func New(paths *config.Paths, timeoutSeconds int) *Checker {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 12
	}
	return &Checker{
		Paths:   paths,
		Timeout: time.Duration(timeoutSeconds) * time.Second,
		TestURLs: []string{
			"https://www.gstatic.com/generate_204",
			"https://cp.cloudflare.com/generate_204",
			"https://connectivitycheck.gstatic.com/generate_204",
			"https://www.google.com/generate_204",
		},
	}
}

// CheckConfig validates one config. It mirrors the original logic:
//   - optional TCP pre-filter;
//   - Hysteria2 is checked by its own client;
//   - VLESS/Trojan are checked through Xray, unless check_via_xray is disabled,
//     in which case they are accepted as-is.
func (c *Checker) CheckConfig(ctx context.Context, raw, workDir, tempDir string, tcpPrefilter, viaXray bool) (bool, int) {
	ep, ok := extract.ParseConfig(raw)
	if !ok {
		return false, 0
	}
	// Hysteria2 runs over UDP: a TCP pre-filter would reject working configs.
	if tcpPrefilter && !ep.IsHysteria2() {
		host, port, ok := extract.HostPort(raw)
		if !ok || !TCPAlive(ctx, host, port, minDuration(c.Timeout, 3*time.Second)) {
			return false, 0
		}
	}
	if ep.IsHysteria2() {
		return c.checkHysteria2(ctx, raw, tempDir)
	}
	if !viaXray {
		return true, 0
	}
	return c.checkXray(ctx, raw, workDir)
}

func (c *Checker) checkXray(ctx context.Context, raw, workDir string) (bool, int) {
	for attempt := 1; attempt <= 3; attempt++ {
		ping := 0
		started := false
		err := c.WithXraySocks(ctx, raw, workDir, func(socksAddr string) error {
			started = true
			var pingErr error
			ping, pingErr = c.Ping(ctx, socksAddr)
			return pingErr
		})
		if err == nil && ping > 0 {
			return true, ping
		}
		if ctx.Err() != nil {
			break
		}
		// If the core started but the proxy did not pass traffic, retrying the
		// same config is pointless (matches the original Python behaviour).
		if started {
			return false, 0
		}
	}
	return false, 0
}

func (c *Checker) checkHysteria2(ctx context.Context, raw, tempDir string) (bool, int) {
	var ping int
	err := c.WithHysteria2Socks(ctx, raw, tempDir, func(socksAddr string) error {
		var pingErr error
		ping, pingErr = c.Ping(ctx, socksAddr)
		return pingErr
	})
	if err != nil || ping == 0 {
		return false, 0
	}
	return true, ping
}

// Ping measures latency through a local SOCKS5 proxy. The whole call is capped
// by the per-config timeout, but every fallback URL gets its own slice so a
// blackholed first target cannot starve the rest.
func (c *Checker) Ping(ctx context.Context, socksAddr string) (int, error) {
	deadlineCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	if len(c.TestURLs) == 0 {
		return 0, errors.New("no test URL")
	}
	perAttempt := c.Timeout / time.Duration(len(c.TestURLs))
	if perAttempt < 2*time.Second {
		perAttempt = 2 * time.Second
	}
	var lastErr error
	for _, testURL := range c.TestURLs {
		if deadlineCtx.Err() != nil {
			break
		}
		start := time.Now()
		attemptCtx, attemptCancel := context.WithTimeout(deadlineCtx, perAttempt)
		body, err := HTTPGetViaSocks(attemptCtx, socksAddr, testURL, perAttempt)
		attemptCancel()
		if err == nil {
			_ = body
			return int(time.Since(start).Milliseconds()), nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no test URL")
	}
	return 0, lastErr
}

// WithXraySocks starts a temporary Xray instance for raw and calls fn with the
// local SOCKS5 address.
func (c *Checker) WithXraySocks(ctx context.Context, raw, workDir string, fn func(socksAddr string) error) error {
	ep, ok := extract.ParseConfig(raw)
	if !ok || ep.IsHysteria2() {
		return fmt.Errorf("xray: unsupported config")
	}
	if !fileExists(c.Paths.XrayPath) {
		return fmt.Errorf("xray: клиент не найден (%s)", c.Paths.XrayPath)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return err
	}
	port, err := freePort()
	if err != nil {
		return err
	}
	tag := fmt.Sprintf("out_%d", port)
	out := outbound.Xray(ep, tag)
	if out == nil {
		return fmt.Errorf("xray: не удалось построить outbound")
	}
	inTag := fmt.Sprintf("in_%d", port)
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"port": port, "listen": "127.0.0.1", "protocol": "socks",
			"tag": inTag, "settings": map[string]any{"udp": false},
		}},
		"outbounds": []any{out},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{map[string]any{
				"type": "field", "inboundTag": []any{inTag}, "outboundTag": tag,
			}},
		},
	}
	cfgFile, err := os.CreateTemp(workDir, fmt.Sprintf("config_%d_*.json", port))
	if err != nil {
		return err
	}
	cfgPath := cfgFile.Name()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		cfgFile.Close()
		os.Remove(cfgPath)
		return err
	}
	if _, err := cfgFile.Write(data); err != nil {
		cfgFile.Close()
		os.Remove(cfgPath)
		return err
	}
	if err := cfgFile.Close(); err != nil {
		os.Remove(cfgPath)
		return err
	}
	defer os.Remove(cfgPath)

	h, err := startCore(ctx, c.Paths.XrayPath, "run", "-c", cfgPath)
	if err != nil {
		return fmt.Errorf("xray start: %w", err)
	}
	defer func() {
		h.Stop()
		time.Sleep(CoreKillDelay)
	}()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if !waitForPortOrExit(ctx, addr, CoreStartupTimeout, h) {
		h.Stop()
		return fmt.Errorf("xray не запустился: %s", h.LastOutput(300))
	}
	return fn(addr)
}

// WithHysteria2Socks starts hysteria2 client for raw and calls fn with the
// local SOCKS5 address.
func (c *Checker) WithHysteria2Socks(ctx context.Context, raw, tempDir string, fn func(socksAddr string) error) error {
	ep, ok := extract.ParseConfig(raw)
	if !ok || !ep.IsHysteria2() {
		return fmt.Errorf("hy2: unsupported config")
	}
	bin := FindHysteria2(c.Paths)
	if !fileExists(bin) {
		return fmt.Errorf("hysteria2: клиент не найден (%s)", bin)
	}
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return err
	}
	port, err := freePort()
	if err != nil {
		return err
	}
	cfg, err := hysteria2Config(ep, port)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(tempDir, fmt.Sprintf("hy2_%d.yaml", port))
	defer os.Remove(cfgPath)
	if err := os.WriteFile(cfgPath, cfg, 0o644); err != nil {
		return err
	}

	variants := [][]string{
		{"client", "-c", cfgPath},
		{"-c", cfgPath},
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	var lastOutput string
	for i, args := range variants {
		h, err := startCore(ctx, bin, args...)
		if err != nil {
			lastOutput = err.Error()
			continue
		}
		started := waitForPortOrExit(ctx, addr, 12*time.Second, h)
		if started {
			err := fn(addr)
			h.Stop()
			time.Sleep(CoreKillDelay)
			return err
		}
		h.Stop()
		lastOutput = h.LastOutput(300)
		if i == 0 {
			logx.Verbosef("  hysteria2: первый режим запуска не сработал, пробую legacy\n")
		}
		time.Sleep(CoreKillDelay)
	}
	return fmt.Errorf("hysteria2 не запустился: %s", lastOutput)
}

type coreHandle struct {
	cmd      *exec.Cmd
	output   bytes.Buffer
	done     chan struct{}
	stopOnce sync.Once
}

func startCore(ctx context.Context, bin string, args ...string) (*coreHandle, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	h := &coreHandle{cmd: cmd, done: make(chan struct{})}
	cmd.Stdout = &h.output
	cmd.Stderr = &h.output
	setProcAttr(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		_ = cmd.Wait()
		close(h.done)
	}()
	return h, nil
}

func (h *coreHandle) Exited() bool {
	select {
	case <-h.done:
		return true
	default:
		return false
	}
}

func (h *coreHandle) Stop() {
	h.stopOnce.Do(func() {
		for i := 0; i < 3 && !h.Exited(); i++ {
			killProcessTree(h.cmd)
			select {
			case <-h.done:
				return
			case <-time.After(300 * time.Millisecond):
			}
		}
		select {
		case <-h.done:
		case <-time.After(2 * time.Second):
		}
	})
}

func (h *coreHandle) LastOutput(max int) string {
	// os/exec writes into the buffer from its own goroutine. Reading it while
	// the process is still alive would race; only read after Wait returned.
	select {
	case <-h.done:
	default:
		return ""
	}
	s := strings.TrimSpace(h.output.String())
	if len(s) > max {
		s = s[len(s)-max:]
	}
	return s
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitForPortOrExit(ctx context.Context, addr string, maxWait time.Duration, h *coreHandle) bool {
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		if h != nil && h.Exited() {
			return false
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

// TCPAlive performs a quick TCP connect check.
func TCPAlive(ctx context.Context, host string, port int, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func hysteria2Config(ep *model.Endpoint, socksPort int) ([]byte, error) {
	var auth any = ep.ID
	if ep.ID == "" {
		auth = "auto"
	} else if user, pass, ok := strings.Cut(ep.ID, ":"); ok {
		auth = map[string]any{"username": user, "password": pass}
	}
	sni := ep.SNI
	if sni == "" {
		sni = ep.Host
	}
	alpn := outbound.SplitALPN(ep.ALPN)
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	cfg := map[string]any{
		"server": net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port)),
		"auth":   auth,
		"tls": map[string]any{
			"sni":      sni,
			"insecure": ep.Insecure,
			"alpn":     alpn,
		},
		"socks5": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", socksPort)},
		"quic": map[string]any{
			"initStreamReceiveWindow": 8388608,
			"maxStreamReceiveWindow":  8388608,
			"initConnReceiveWindow":   20971520,
			"maxConnReceiveWindow":    20971520,
			"maxIdleTimeout":          "30s",
			"maxIncomingStreams":      1024,
		},
	}
	if ep.ObfsPassword != "" {
		cfg["transport"] = map[string]any{"udp": map[string]any{"obfs": map[string]any{
			"type": "salamander", "password": ep.ObfsPassword,
		}}}
	}
	bandwidth := map[string]any{}
	if ep.UpMbps != "" {
		bandwidth["up"] = ep.UpMbps + " mbps"
	}
	if ep.DownMbps != "" {
		bandwidth["down"] = ep.DownMbps + " mbps"
	}
	if len(bandwidth) > 0 {
		cfg["bandwidth"] = bandwidth
	}
	return yaml.Marshal(cfg)
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
