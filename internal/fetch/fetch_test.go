package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchSourceAndHappFallback(t *testing.T) {
	AllowPrivate = true // httptest listens on 127.0.0.1
	body := "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls#source"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte(body))
		case "/bad":
			w.WriteHeader(http.StatusInternalServerError)
		case "/happ":
			// Simulate a server that only answers the Happ client properly.
			if r.Header.Get("X-HWID") == "" {
				_, _ = w.Write([]byte("short"))
				return
			}
			_, _ = w.Write([]byte(body))
		case "/b64happ":
			if r.Header.Get("X-HWID") == "" {
				_, _ = w.Write([]byte("short"))
				return
			}
			_, _ = w.Write([]byte("dmxlc3M6Ly8xMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTVAMS4yLjMuNDo0NDM/c2VjdXJpdHk9dGxzI3NvdXJjZQ=="))
		}
	}))
	defer server.Close()

	ctx := context.Background()
	content, usedHapp, err := FetchSource(ctx, server.URL+"/ok", true, 3*time.Second)
	if err != nil || usedHapp || content != body {
		t.Fatalf("normal fetch: content=%q happ=%v err=%v", content, usedHapp, err)
	}
	content, usedHapp, err = FetchSource(ctx, server.URL+"/happ", true, 3*time.Second)
	if err != nil || !usedHapp || content != body {
		t.Fatalf("happ fetch: content=%q happ=%v err=%v", content, usedHapp, err)
	}
	content, usedHapp, err = FetchSource(ctx, server.URL+"/b64happ", true, 3*time.Second)
	if err != nil || !usedHapp || !strings.Contains(content, "vless://") {
		t.Fatalf("b64 happ fetch: content=%q happ=%v err=%v", content, usedHapp, err)
	}
	if _, _, err := FetchSource(ctx, server.URL+"/bad", false, 3*time.Second); err == nil {
		t.Fatal("500 must be an error")
	}
}

func TestValidateURL(t *testing.T) {
	if !ValidateURL("https://example.com/sub") {
		t.Fatal("valid URL rejected")
	}
	if ValidateURL("ftp://example.com/x") || ValidateURL("not a url") {
		t.Fatal("invalid URL accepted")
	}
}
