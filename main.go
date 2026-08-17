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
	"path"
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

// authCfg describes the auth front-door sitting behind the gateway. The defaults
// are oauth2-proxy's, but nothing here is hardcoded to it — any front door that
// owns a path prefix and sets a session cookie on its callback works.
type authCfg struct {
	// pathPrefixes are the front door's own endpoints (sign-in, callback,
	// sign-out), normalized without a trailing slash.
	pathPrefixes []string
	// callbackPath is the exact path the IdP redirects back to.
	callbackPath string
	// sessionCookie is the name prefix of the cookie the front door sets once a
	// session exists. A prefix, because oauth2-proxy splits large sessions into
	// _oauth2_proxy_0, _1, ….
	sessionCookie string
}

func main() {
	var (
		listenAddr       = env("LISTEN_ADDR", ":8080")
		backendPrimary   = mustURL("BACKEND_PRIMARY")
		backendSecondary = mustURL("BACKEND_SECONDARY")
		cookie           = cookieCfg{
			name:       env("COOKIE_NAME", "auth_mode"),
			maxAge:     cookieMaxAge,
			// 15m matches oauth2-proxy's default CSRF cookie expiry: past that the
			// in-flight login can't complete anyway, so a longer window buys nothing.
			tempMaxAge: envInt("COOKIE_TEMP_MAX_AGE", 900),
		}
		auth = authCfg{
			pathPrefixes:  envPrefixes("AUTH_PATH_PREFIXES", "/oauth2/"),
			callbackPath:  cleanPath(env("AUTH_CALLBACK_PATH", "/oauth2/callback")),
			sessionCookie: env("AUTH_SESSION_COOKIE", "_oauth2_proxy"),
		}
	)

	selectorHTML, err := selectorFS.ReadFile("selector.html")
	if err != nil {
		log.Fatalf("embed selector.html: %v", err)
	}

	proxies := map[string]http.Handler{
		"primary":   newProxy(backendPrimary, cookie, auth),
		"secondary": newProxy(backendSecondary, cookie, auth),
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           newHandler(cookie, selectorHTML, proxies),
		MaxHeaderBytes:    1 << 20,           // large injected auth headers (X-Forwarded-Access-Token)
		ReadHeaderTimeout: 10 * time.Second,  // slow-loris guard on headers only
		// Deliberately NO ReadTimeout/WriteTimeout/IdleTimeout: they would sever
		// long-lived WebSocket / SSE / long-polling connections.
	}

	log.Printf("auth-gateway listening on %s (primary=%s secondary=%s cookie=%s temp_max_age=%ds auth_paths=%s callback=%s session_cookie=%s)",
		listenAddr, backendPrimary, backendSecondary, cookie.name, cookie.tempMaxAge,
		strings.Join(auth.pathPrefixes, ","), auth.callbackPath, auth.sessionCookie)
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
func newProxy(target *url.URL, cookie cookieCfg, auth authCfg) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		ModifyResponse: func(resp *http.Response) error {
			if rewriteAuthError(resp, auth) {
				return nil
			}
			promoteCookie(resp, cookie, auth)
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
// once the auth front door proves the choice was right: a 302 off the callback
// path that also sets the session cookie. That combination only happens when the
// code exchange succeeded — a failed callback answers 4xx/5xx and sets no
// session — so no wrong choice is ever promoted.
func promoteCookie(resp *http.Response, cookie cookieCfg, auth authCfg) {
	if resp.StatusCode != http.StatusFound {
		return
	}
	if resp.Request == nil || cleanPath(resp.Request.URL.Path) != auth.callbackPath {
		return
	}
	if !setsSessionCookie(resp, auth.sessionCookie) {
		return
	}
	m, temp := cookieMode(resp.Request, cookie.name)
	if m == "" || !temp {
		return // absent/unknown cookie, or already promoted — don't re-set every request
	}
	resp.Header.Add("Set-Cookie", routingCookie(cookie.name, m, cookie.maxAge).String())
}

// setsSessionCookie reports whether the response sets the front door's session
// cookie. Matched by prefix: oauth2-proxy splits sessions too large for one
// cookie into _oauth2_proxy_0, _oauth2_proxy_1, … and never sets the bare name.
func setsSessionCookie(resp *http.Response, name string) bool {
	if name == "" {
		return false
	}
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, name) && c.Value != "" && c.MaxAge >= 0 {
			return true
		}
	}
	return false
}

// rewriteAuthError turns oauth2-proxy's own failure responses into a redirect to
// /.auth/reset, so a user who picked the wrong IdP lands back on the selector
// instead of on a dead sign-in error page. It reports whether it rewrote.
//
// It is deliberately narrow:
//   - Only the front door's own endpoints (AUTH_PATH_PREFIXES), never application
//     4xx responses. /.auth/reset is served by the gateway itself (never proxied)
//     and clears the cookie, so this cannot loop.
//   - Only 401/403. A 500 passes through so the user sees the real error page;
//     the temp cookie expires by itself, and a reload lands on the selector.
//   - Only top-level navigations. An XHR to /oauth2/* keeps its raw 401/403
//     instead of being dragged through /.auth/reset and silently losing the
//     routing cookie under a page that is still running.
func rewriteAuthError(resp *http.Response, auth authCfg) bool {
	if resp.Request == nil || !auth.isAuthPath(resp.Request.URL.Path) {
		return false
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
	default:
		return false
	}
	if !isNavigation(resp.Request) {
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

// isAuthPath reports whether a path belongs to the auth front door's own
// endpoints (sign-in page, callback, sign-out) rather than to the application.
// The path is cleaned first, so "/oauth2/../app" is classified as the app path
// it actually resolves to.
func (a authCfg) isAuthPath(p string) bool {
	p = cleanPath(p)
	for _, prefix := range a.pathPrefixes {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

// cleanPath normalizes a request path (resolving "." / ".." and duplicate
// slashes) so prefix and equality matches can't be skewed by traversal segments.
// It always returns a rooted path.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	return path.Clean(p)
}

// isNavigation reports whether a request is a top-level browser navigation, the
// only case where turning a response into a redirect makes sense. Sec-Fetch-Mode
// is authoritative where present; older clients fall back to the Accept header.
func isNavigation(r *http.Request) bool {
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" {
		return m == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// sameOriginRequest reports whether a request plausibly originated from our own
// site, used as the CSRF guard on /.auth/reset. Sec-Fetch-Site is sent by every
// current browser; when it's absent (old clients, non-browser agents) we allow,
// since the endpoint has to stay reachable by a plain GET.
func sameOriginRequest(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	default:
		return false
	}
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
//
// It stays a GET on purpose — the auth-error rewrite needs a reset reachable by
// redirect — so cross-site requests are neutered instead of being made
// impossible: a third-party page embedding /.auth/reset still gets its redirect,
// but the cookie survives, so it can't log the user out of their provider choice.
func handleReset(w http.ResponseWriter, r *http.Request, cookie cookieCfg) {
	rd := r.URL.Query().Get("rd")
	if !safeRedirect(rd) {
		rd = "/"
	}

	if sameOriginRequest(r) {
		// MaxAge < 0 deletes. Path and the other attributes must match the ones used
		// when setting it, or the browser keeps the original cookie alongside.
		http.SetCookie(w, routingCookie(cookie.name, "", -1))
	}
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

// envPrefixes reads a comma-separated path-prefix list, falling back to def when
// unset or empty. Entries are normalized to a rooted, trailing-slash-free form so
// a prefix matches both the path itself and everything below it (and "/oauth2"
// can never match "/oauth2-app").
func envPrefixes(key, def string) []string {
	raw := env(key, def)
	out := splitPrefixes(raw)
	if len(out) == 0 {
		log.Printf("%s = %q has no usable prefixes, using %q", key, raw, def)
		out = splitPrefixes(def)
	}
	return out
}

func splitPrefixes(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		out = append(out, strings.TrimSuffix(cleanPath(p), "/"))
	}
	return out
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
