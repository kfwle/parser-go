package checker

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// socks5Dialer dials through a local SOCKS5 proxy (Xray/Hysteria2 inbound).
type socks5Dialer struct {
	proxyAddr string
	dialer    net.Dialer
}

func (d *socks5Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	}
	if err := socks5Handshake(conn, address); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func socks5Handshake(conn net.Conn, target string) error {
	// Greeting: version 5, one method, no auth.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return fmt.Errorf("socks5: auth method rejected")
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("socks5: bad target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("socks5: bad port %q", portStr)
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("socks5: hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	req = append(req, portBytes[:]...)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	// Reply: VER REP RSV ATYP + bound address + port.
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return fmt.Errorf("socks5: bad version %d", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5: connect failed (code %d)", head[1])
	}
	switch head[3] {
	case 0x01:
		if _, err := io.CopyN(io.Discard, conn, 4+2); err != nil {
			return err
		}
	case 0x04:
		if _, err := io.CopyN(io.Discard, conn, 16+2); err != nil {
			return err
		}
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		if _, err := io.CopyN(io.Discard, conn, int64(length[0])+2); err != nil {
			return err
		}
	default:
		return fmt.Errorf("socks5: unknown address type %d", head[3])
	}
	return nil
}

func socks5HTTPClient(proxyAddr string, timeout time.Duration) *http.Client {
	dialer := &socks5Dialer{proxyAddr: proxyAddr}
	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: timeout,
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}

// HTTPGetViaSocks fetches rawURL through the local SOCKS5 proxy.
func HTTPGetViaSocks(ctx context.Context, socksAddr, rawURL string, timeout time.Duration) ([]byte, error) {
	client := socks5HTTPClient(socksAddr, timeout)
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}
