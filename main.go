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
	"strconv"
	"strings"
	"time"
)

//go:embed selector.html
var selectorFS embed.FS

const (
	cookieMaxAge = 365 * 24 * 60 * 60 // ~1 year, in seconds
	// tempSuffix marks a cookie that was just issued by the selector and has not
	// yet been confirmed by a successful authenticated request.
	tempSuffix = ":tmp"
)

// cookieCfg is everything needed to issue, refresh and delete the routing cookie.
type cookieCfg struct {
	name string
	// maxAge is the full lifetime, granted only once the choice is proven good.
	maxAge int
	// tempMaxAge is the short lifetime a fresh selection gets, so a wrong choice
	// expires on its own instead of sticking for a year.
	tempMaxAge int
}

func main() {
	var (
		listenAddr       = env("LISTEN_ADDR", ":8080")
		backendPrimary   = mustURL("BACKEND_PRIMARY")
		backendSecondary = mustURL("BACKEND_SECONDARY")
		cookie           = cookieCfg{
			name:       env("COOKIE_NAME", "auth_mode"),
			maxAge:     cookieMaxAge,
			tempMaxAge: envInt("COOKIE_TEMP_MAX_AGE", 600),
		}
	)

	selectorHTML, err := selectorFS.ReadFile("selector.html")
	if err != nil {
		log.Fatalf("embed selector.html: %v", err)
	}

	proxies := map[string]http.Handler{
		"primary":   newProxy(backendPrimary, cookie),
		"secondary": newProxy(backendSecondary, cookie),
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           newHandler(cookie, selectorHTML, proxies),
		MaxHeaderBytes:    1 << 20,           // large injected auth headers (X-Forwarded-Access-Token)
		ReadHeaderTimeout: 10 * time.Second,  // slow-loris guard on headers only
		// Deliberately NO ReadTimeout/WriteTimeout/IdleTimeout: they would sever
		// long-lived WebSocket / SSE / long-polling connections.
	}

	log.Printf("auth-gateway listening on %s (primary=%s secondary=%s cookie=%s temp_max_age=%ds)",
		listenAddr, backendPrimary, backendSecondary, cookie.name, cookie.tempMaxAge)
	log.Fatal(srv.ListenAndServe())
}

// newHandler wires the gateway routing: control endpoints first, then cookie-based
// backend selection, falling back to the selector page / JSON 401.
func newHandler(cookie cookieCfg, selectorHTML []byte, proxies map[string]http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Gateway-owned control endpoints, handled regardless of cookie state.
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		case "/.auth/select":
			handleSelect(w, r, cookie)
			return
		case "/.auth/reset":
			handleReset(w, r, cookie)
			return
		}

		// Route by our own cookie. Unknown/absent values are treated as absent.
		if p := proxies[mode(r, cookie.name)]; p != nil {
			p.ServeHTTP(w, r)
			return
		}
		handleNoMode(w, r, selectorHTML)
	})
}

// newProxy builds a reverse proxy to a single backend, tuned for lossless
// streaming and WebSocket upgrades. httputil.ReverseProxy natively hijacks and
// bidirectionally copies Upgrade connections, so no websocket library is needed.
func newProxy(target *url.URL, cookie cookieCfg) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		ModifyResponse: func(resp *http.Response) error {
			if rewriteAuthError(resp) {
				return nil
			}
			promoteCookie(resp, cookie)
			return nil
		},
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
	m, _ := cookieMode(r, cookieName)
	return m
}

// cookieMode returns the validated routing mode plus whether the cookie is still
// the short-lived variant issued at selection time (value suffixed with
// tempSuffix, e.g. "primary:tmp"). Unrecognized values yield ("", false).
func cookieMode(r *http.Request, cookieName string) (m string, temp bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	v := c.Value
	if strings.HasSuffix(v, tempSuffix) {
		v, temp = strings.TrimSuffix(v, tempSuffix), true
	}
	switch v {
	case "primary", "secondary":
		return v, temp
	default:
		return "", false
	}
}

// promoteCookie upgrades a still-temporary routing cookie to its full lifetime
// once the backend proves the choice was right, i.e. it answered 2xx on a
// non-auth path (behind oauth2-proxy that means the session is authenticated).
// /oauth2/* is excluded: oauth2-proxy serves its own sign-in page with 200 there,
// which says nothing about whether the user can actually get in.
func promoteCookie(resp *http.Response, cookie cookieCfg) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return
	}
	if resp.Request == nil || isAuthPath(resp.Request.URL.Path) {
		return
	}
	m, temp := cookieMode(resp.Request, cookie.name)
	if m == "" || !temp {
		return // absent/unknown cookie, or already promoted — don't re-set every request
	}
	resp.Header.Add("Set-Cookie", routingCookie(cookie.name, m, cookie.maxAge).String())
}

// rewriteAuthError turns oauth2-proxy's own failure responses into a redirect to
// /.auth/reset, so a user who picked the wrong IdP lands back on the selector
// instead of on a dead sign-in error page. It reports whether it rewrote.
//
// Loop guard: this only fires on oauth2-proxy's own endpoints (/oauth2/*), never
// on application 4xx responses, and /.auth/reset is served by the gateway itself
// (never proxied) and clears the cookie — so the next request hits the selector.
func rewriteAuthError(resp *http.Response) bool {
	if resp.Request == nil || !isAuthPath(resp.Request.URL.Path) {
		return false
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError:
	default:
		return false
	}

	_ = resp.Body.Close()
	resp.Body = http.NoBody
	resp.ContentLength = 0
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Type")
	resp.Header.Del("Etag")
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Set("Location", "/.auth/reset?rd=/")
	resp.StatusCode = http.StatusFound
	resp.Status = strconv.Itoa(http.StatusFound) + " " + http.StatusText(http.StatusFound)
	return true
}

// isAuthPath reports whether a path belongs to oauth2-proxy's own endpoints
// (sign-in page, callback, sign-out) rather than to the application.
func isAuthPath(path string) bool {
	return strings.HasPrefix(path, "/oauth2/")
}

// handleSelect sets the routing cookie and redirects back to a validated,
// same-origin relative path. The cookie is deliberately short-lived until a
// successful authenticated request promotes it (see promoteCookie), so a wrong
// choice expires by itself.
func handleSelect(w http.ResponseWriter, r *http.Request, cookie cookieCfg) {
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

	http.SetCookie(w, routingCookie(cookie.name, m+tempSuffix, cookie.tempMaxAge))
	http.Redirect(w, r, rd, http.StatusFound)
}

// handleReset deletes the routing cookie and redirects back to a validated,
// same-origin relative path (default "/", where the selector page is served).
// This is the escape hatch from a wrong provider choice.
func handleReset(w http.ResponseWriter, r *http.Request, cookie cookieCfg) {
	rd := r.URL.Query().Get("rd")
	if !safeRedirect(rd) {
		rd = "/"
	}

	// MaxAge < 0 deletes. Path and the other attributes must match the ones used
	// when setting it, or the browser keeps the original cookie alongside.
	http.SetCookie(w, routingCookie(cookie.name, "", -1))
	http.Redirect(w, r, rd, http.StatusFound)
}

// routingCookie builds the routing cookie with the one canonical set of
// attributes, so a delete (maxAge < 0) always matches a previously issued cookie.
func routingCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
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

// envInt reads a positive integer env var, falling back to def when unset,
// unparseable or non-positive (a zero/negative MaxAge would change the cookie's
// meaning to session/delete).
func envInt(key string, def int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		log.Printf("%s = %q is not a positive integer, using %d", key, raw, def)
		return def
	}
	return n
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
