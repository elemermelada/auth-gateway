package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// testHandler builds a gateway whose two backends echo their identity, so tests
// can assert which backend a request was routed to.
func testHandler(t *testing.T) (http.Handler, func()) {
	t.Helper()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "backend=primary")
	}))
	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "backend=secondary")
	}))
	proxies := map[string]http.Handler{
		"primary":   newProxy(mustParse(t, primary.URL)),
		"secondary": newProxy(mustParse(t, secondary.URL)),
	}
	h := newHandler("auth_mode", true, []byte("<html>SELECTOR</html>"), proxies)
	return h, func() { primary.Close(); secondary.Close() }
}

func TestRoutingByCookie(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	cases := []struct {
		cookie string
		want   string
	}{
		{"primary", "backend=primary"},
		{"secondary", "backend=secondary"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tc.cookie})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("cookie=%s: status = %d, want 200", tc.cookie, rec.Code)
		}
		if got := rec.Body.String(); got != tc.want {
			t.Fatalf("cookie=%s: body = %q, want %q", tc.cookie, got, tc.want)
		}
	}
}

func TestNoCookieServesSelector(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SELECTOR") {
		t.Fatalf("body = %q, want selector page", rec.Body.String())
	}
}

func TestUnknownCookieTreatedAsAbsent(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "bogus"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "SELECTOR") {
		t.Fatalf("unknown cookie should fall back to selector: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestNoCookieNonHTMLReturns401(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/api/thing", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type = %q, want json", ct)
	}
}

func TestHealthz(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthz: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestSelectSetsCookieAndRedirects(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/.auth/select?mode=secondary&rd=/dashboard", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Fatalf("location = %q, want /dashboard", loc)
	}
	sc := rec.Result().Cookies()
	if len(sc) != 1 || sc[0].Value != "secondary" || !sc[0].Secure || !sc[0].HttpOnly {
		t.Fatalf("cookie not set correctly: %+v", sc)
	}
}

// TestSelectInsecureCookie verifies that with cookieSecure=false the routing
// cookie is written without the Secure attribute, so browsers attach it to
// plaintext http/ws requests (local dev, before a TLS-terminating ingress).
func TestSelectInsecureCookie(t *testing.T) {
	proxies := map[string]http.Handler{}
	h := newHandler("auth_mode", false, nil, proxies)

	req := httptest.NewRequest(http.MethodGet, "/.auth/select?mode=primary", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	sc := rec.Result().Cookies()
	if len(sc) != 1 || sc[0].Value != "primary" {
		t.Fatalf("cookie not set: %+v", sc)
	}
	if sc[0].Secure {
		t.Fatalf("cookie should not be Secure when cookieSecure=false")
	}
	if !sc[0].HttpOnly {
		t.Fatalf("cookie should remain HttpOnly")
	}
}

func TestSelectInvalidMode(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/.auth/select?mode=evil", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestSelectOpenRedirectGuard(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	// A malicious rd should be dropped in favor of "/".
	req := httptest.NewRequest(http.MethodGet, "/.auth/select?mode=primary&rd=//evil.com/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("open-redirect not blocked: location = %q, want /", loc)
	}
}

func TestSafeRedirect(t *testing.T) {
	cases := map[string]bool{
		"":                 false,
		"/":                true,
		"/dashboard":       true,
		"/a/b?c=d":         true,
		"//evil.com":       false,
		"/\\evil.com":      false,
		"http://evil.com":  false,
		"https://evil.com": false,
		"evil.com":         false,
		"javascript:x":     false,
	}
	for in, want := range cases {
		if got := safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestWebSocketUpgradeProxied verifies the gateway losslessly proxies a
// protocol upgrade: it hijacks the connection and copies bytes bidirectionally.
// This is the core wss-reliability guarantee. We use a minimal raw upgrade
// (101 Switching Protocols + byte echo) rather than full RFC6455 framing,
// because the byte-copy path is identical for real WebSockets.
func TestWebSocketUpgradeProxied(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "echo") {
			http.Error(w, "expected upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("backend hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		// Echo everything back.
		_, _ = io.Copy(conn, conn)
	}))
	defer backend.Close()

	proxies := map[string]http.Handler{"primary": newProxy(mustParse(t, backend.URL))}
	gw := httptest.NewServer(newHandler("auth_mode", true, nil, proxies))
	defer gw.Close()

	gwURL := mustParse(t, gw.URL)
	conn, err := net.Dial("tcp", gwURL.Host)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()

	// Send an upgrade request carrying the routing cookie.
	_, _ = io.WriteString(conn, "GET /ws HTTP/1.1\r\n"+
		"Host: "+gwURL.Host+"\r\n"+
		"Cookie: auth_mode=primary\r\n"+
		"Connection: Upgrade\r\n"+
		"Upgrade: echo\r\n\r\n")

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	// Now the connection is a raw bidirectional pipe: write and read the echo.
	const msg = "hello-websocket-piping"
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

// Ensure newProxy preserves the inbound Host header (oauth2-proxy redirects
// depend on it) and sets X-Forwarded-* headers.
func TestProxyPreservesHostAndSetsXForwarded(t *testing.T) {
	var gotHost, gotXFF, gotProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotProto = r.Header.Get("X-Forwarded-Proto")
	}))
	defer backend.Close()

	p := newProxy(mustParse(t, backend.URL))
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/x", nil)
	req.RemoteAddr = "203.0.113.7:12345"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if gotHost != "app.example.com" {
		t.Fatalf("backend Host = %q, want app.example.com", gotHost)
	}
	if !strings.Contains(gotXFF, "203.0.113.7") {
		t.Fatalf("X-Forwarded-For = %q, want to contain client IP", gotXFF)
	}
	if gotProto == "" {
		t.Fatalf("X-Forwarded-Proto not set")
	}
}
