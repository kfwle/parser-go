package checker

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// startSocks5Server runs a minimal no-auth SOCKS5 proxy for tests.
func startSocks5Server(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSocks5(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func handleSocks5(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03:
		length, err := br.ReadByte()
		if err != nil {
			return
		}
		name := make([]byte, int(length))
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		host = string(name)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(br, portBytes); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBytes)
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 3*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	go io.Copy(target, br)
	_, _ = io.Copy(conn, target)
}

func TestHTTPGetViaSocks(t *testing.T) {
	proxyAddr, stop := startSocks5Server(t)
	defer stop()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello through socks"))
	}))
	defer target.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body, err := HTTPGetViaSocks(ctx, proxyAddr, target.URL, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello through socks" {
		t.Fatalf("body=%q", body)
	}
}

func TestTCPAlive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	if !TCPAlive(context.Background(), "127.0.0.1", addr.Port, 2*time.Second) {
		t.Fatal("TCPAlive returned false for a listening port")
	}
	if TCPAlive(context.Background(), "127.0.0.1", 1, 300*time.Millisecond) {
		t.Fatal("TCPAlive returned true for port 1")
	}
}
