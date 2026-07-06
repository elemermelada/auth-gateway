// Command auth-gateway is a tiny cookie-based mode selector that sits between the
// ingress and two oauth2-proxy instances. It routes every request to a backend
// based on its own routing cookie (auth_mode), and serves a selector page
// when no valid mode has been chosen yet.
//
// Design goals: stdlib only, stateless, and lossless proxying for WebSockets,
// SSE, long-polling, and large injected auth headers.
package main

import (
	"embed"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

//go:embed selector.html
var selectorFS embed.FS

const cookieMaxAge = 365 * 24 * 60 * 60 // ~1 year, in seconds

func main() {
	var (
		listenAddr       = env("LISTEN_ADDR", ":8080")
		cookieName       = env("COOKIE_NAME", "auth_mode")
		backendPrimary   = mustURL("BACKEND_PRIMARY")
		backendSecondary = mustURL("BACKEND_SECONDARY")
	)

	selectorHTML, err := selectorFS.ReadFile("selector.html")
	if err != nil {
		log.Fatalf("embed selector.html: %v", err)
	}

	proxies := map[string]http.Handler{
		"primary":   newProxy(backendPrimary),
		"secondary": newProxy(backendSecondary),
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           newHandler(cookieName, selectorHTML, proxies),
		MaxHeaderBytes:    1 << 20,           // large injected auth headers (X-Forwarded-Access-Token)
		ReadHeaderTimeout: 10 * time.Second,  // slow-loris guard on headers only
		// Deliberately NO ReadTimeout/WriteTimeout/IdleTimeout: they would sever
		// long-lived WebSocket / SSE / long-polling connections.
	}

	log.Printf("auth-gateway listening on %s (primary=%s secondary=%s cookie=%s)",
		listenAddr, backendPrimary, backendSecondary, cookieName)
	log.Fatal(srv.ListenAndServe())
}

// newHandler wires the gateway routing: control endpoints first, then cookie-based
// backend selection, falling back to the selector page / JSON 401.
func newHandler(cookieName string, selectorHTML []byte, proxies map[string]http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Gateway-owned control endpoints, handled regardless of cookie state.
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		case "/.auth/select":
			handleSelect(w, r, cookieName)
			return
		}

		// Route by our own cookie. Unknown/absent values are treated as absent.
		if p := proxies[mode(r, cookieName)]; p != nil {
			p.ServeHTTP(w, r)
			return
		}
		handleNoMode(w, r, selectorHTML)
	})
}

// newProxy builds a reverse proxy to a single backend, tuned for lossless
// streaming and WebSocket upgrades. httputil.ReverseProxy natively hijacks and
// bidirectionally copies Upgrade connections, so no websocket library is needed.
func newProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = target.Scheme
			r.Out.URL.Host = target.Host
			r.Out.Host = r.In.Host // preserve Host — oauth2-proxy redirects depend on it
			r.SetXForwarded()      // append to X-Forwarded-For coming from nginx
		},
		FlushInterval: -1, // flush every write, so SSE/streaming isn't buffered
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 0, // no cap — long-polling / streaming safe
			DisableCompression:    true,
		},
	}
}

// mode returns the validated routing mode from the cookie, or "" if the cookie
// is missing or holds an unrecognized value (never an error path).
func mode(r *http.Request, cookieName string) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	switch c.Value {
	case "primary", "secondary":
		return c.Value
	default:
		return ""
	}
}

// handleSelect sets the routing cookie and redirects back to a validated,
// same-origin relative path.
func handleSelect(w http.ResponseWriter, r *http.Request, cookieName string) {
	q := r.URL.Query()
	m := q.Get("mode")
	if m != "primary" && m != "secondary" {
		http.Error(w, "invalid mode", http.StatusBadRequest)
		return
	}

	rd := q.Get("rd")
	if !safeRedirect(rd) {
		rd = "/"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    m,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, rd, http.StatusFound)
}

// handleNoMode serves the selector page for browser GETs, and a small JSON 401
// for everything else.
func handleNoMode(w http.ResponseWriter, r *http.Request, selectorHTML []byte) {
	if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(selectorHTML)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "auth mode not selected"})
}

// safeRedirect reports whether rd is a safe same-origin relative path: it must
// start with a single "/" and must not be scheme-relative ("//host") or carry a
// scheme/host. This is the open-redirect guard.
func safeRedirect(rd string) bool {
	if rd == "" || rd[0] != '/' {
		return false
	}
	// Reject scheme-relative ("//evil.com") and backslash variants ("/\evil.com"),
	// which some browsers normalize to "//".
	if len(rd) > 1 && (rd[1] == '/' || rd[1] == '\\') {
		return false
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return false
	}
	return true
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustURL(key string) *url.URL {
	raw := os.Getenv(key)
	if raw == "" {
		log.Fatalf("%s is required", key)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		log.Fatalf("%s must be a full URL (got %q)", key, raw)
	}
	return u
}
