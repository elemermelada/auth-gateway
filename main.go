// Command auth-gateway is a tiny cookie-based mode selector that sits between the
// ingress and any number of oauth2-proxy instances. It routes every request to a
// backend based on its own routing cookie (auth_mode), and serves a selector page
// when no valid mode has been chosen yet.
//
// Design goals: stdlib only, stateless, and lossless proxying for WebSockets,
// SSE, long-polling, and large injected auth headers.
package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

//go:embed selector.html selector_fragment.html
var selectorFS embed.FS

const (
	cookieMaxAge = 365 * 24 * 60 * 60 // ~1 year, in seconds
	// tempSuffix marks a cookie that was just issued by the selector and has not
	// yet been confirmed by a successful authenticated request.
	tempSuffix = ":tmp"
	// selectorPlaceholder is the token a selector shell must contain exactly once.
	// The gateway splices its own selector fragment in its place, which is what
	// keeps a custom page cosmetic: operators never author the links or the script.
	selectorPlaceholder = "<!--AUTH_GATEWAY_SELECTOR-->"
	// maxSelectorShell caps a custom shell. The rendered page is held in memory for
	// the life of the process, and an auth page has no business being larger.
	maxSelectorShell = 1 << 20 // 1 MiB
)

// entityHeaders are the response headers that describe a body, dropped whenever a
// proxied response's body is replaced (see rewriteAuthError).
var entityHeaders = []string{
	"Content-Length", "Content-Type", "Content-Encoding", "Content-Language",
	"Content-Range", "Etag", "Expires", "Last-Modified", "Vary",
}

// backend is one configured upstream: a stable key that identifies it in the
// routing cookie and in ?mode=, the label its selector button shows, and the URL
// to proxy to. The key — never a position in the list — is the identity, so
// adding or removing a backend never re-maps an existing cookie to another IdP.
type backend struct {
	key   string
	label string
	url   *url.URL
}

// backendKeyPattern locks down the charset of a backend key. Keys travel in the
// routing cookie value, in ?mode= query params and into generated HTML class
// names, so the charset is constrained once, here, instead of escaped in four
// places downstream.
var backendKeyPattern = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// legacyBackendVars are the removed single-upstream vars BACKENDS replaced.
var legacyBackendVars = []string{"BACKEND_PRIMARY", "BACKEND_SECONDARY"}

// parseBackends parses the BACKENDS / BACKEND_LABELS pair into the ordered
// backend list. Order is the button order on the selector page, which is why
// this returns a slice and not a map: Go map iteration order would shuffle the
// buttons on every process start.
//
// Both vars are comma-separated key=value lists. Entries are split on the first
// "=" only, so a URL may contain "=" itself; a label may not contain a comma
// (documented limitation of the comma-list format).
//
// Everything questionable is an error rather than a best effort — a bad key, a
// duplicate, an empty list, a label for a key that does not exist. main() turns
// each into a failed startup, because a gateway with a mistyped backend routes
// users to a page that cannot explain itself.
func parseBackends(list, labels string) ([]backend, error) {
	var out []backend
	index := map[string]int{}
	for _, entry := range strings.Split(list, ",") {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		key, raw, ok := strings.Cut(entry, "=")
		key, raw = strings.TrimSpace(key), strings.TrimSpace(raw)
		if !ok || raw == "" {
			return nil, fmt.Errorf("backend %q is not in key=url form", entry)
		}
		if !backendKeyPattern.MatchString(key) {
			return nil, fmt.Errorf("backend key %q must match %s", key, backendKeyPattern)
		}
		if _, dup := index[key]; dup {
			return nil, fmt.Errorf("backend key %q is listed more than once", key)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("backend %q must be a full URL (got %q)", key, raw)
		}
		index[key] = len(out)
		out = append(out, backend{key: key, label: defaultLabel(key), url: u})
	}
	if len(out) == 0 {
		return nil, errors.New("no backends configured, want a comma-separated key=url list")
	}

	for _, entry := range strings.Split(labels, ",") {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		key, label, ok := strings.Cut(entry, "=")
		key, label = strings.TrimSpace(key), strings.TrimSpace(label)
		if !ok || label == "" {
			return nil, fmt.Errorf("label %q is not in key=label form", entry)
		}
		i, known := index[key]
		if !known {
			return nil, fmt.Errorf("label for unknown backend key %q", key)
		}
		out[i].label = label
	}
	return out, nil
}

// defaultLabel is the button text for a backend with no explicit label: the key
// with its first letter upper-cased ("corp" -> "Corp"). Keys are ASCII by
// backendKeyPattern, so slicing the first byte is safe.
func defaultLabel(key string) string {
	return strings.ToUpper(key[:1]) + key[1:]
}

// modeSet is the set of routing-cookie values the gateway accepts: exactly the
// configured backend keys.
func modeSet(backends []backend) map[string]bool {
	set := make(map[string]bool, len(backends))
	for _, b := range backends {
		set[b.key] = true
	}
	return set
}

// describeBackends renders the backend list for the startup log line, in config
// (button) order, so an unexpected routing target is auditable from the logs.
func describeBackends(backends []backend) string {
	parts := make([]string, 0, len(backends))
	for _, b := range backends {
		parts = append(parts, b.key+"="+b.url.String())
	}
	return strings.Join(parts, ",")
}

// checkLegacyBackendVars rejects a deploy that still sets the removed
// BACKEND_PRIMARY / BACKEND_SECONDARY vars. Ignoring them silently would start a
// gateway with no backends at all (or with the wrong ones) and show every user
// the selector page with no clue why, so this is fatal and carries the migration.
func checkLegacyBackendVars() error {
	for _, key := range legacyBackendVars {
		if os.Getenv(key) != "" {
			return fmt.Errorf("%s is no longer supported: list every upstream in BACKENDS instead "+
				"(BACKENDS=primary=$BACKEND_PRIMARY,secondary=$BACKEND_SECONDARY reproduces the old "+
				"behavior and keeps existing routing cookies valid)", key)
		}
	}
	return nil
}

// cookieCfg is everything needed to issue, refresh and delete the routing cookie.
type cookieCfg struct {
	name string
	// maxAge is the full lifetime, granted only once the choice is proven good.
	maxAge int
	// tempMaxAge is the short lifetime a fresh selection gets, so a wrong choice
	// expires on its own instead of sticking for a year.
	tempMaxAge int
	// modes is the set of accepted cookie values: exactly the configured backend
	// keys. It lives here because every place that reads or writes the routing
	// cookie needs to know which values are real.
	modes map[string]bool
}

// authCfg describes the auth front door sitting behind the gateway.
// See README: "Configuration (env vars)" for the AUTH_* vars behind these fields.
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

// selectorPage is the rendered selector response: the page bytes plus the
// Content-Security-Policy served with them. The CSP pins script execution to the
// gateway's own fragment, so a <script> smuggled into a custom shell is dead —
// that is what makes "customization is cosmetic" enforced rather than promised.
type selectorPage struct {
	html []byte
	csp  string
	// source is where the shell came from ("embedded", "inline", or a file path)
	// and sha256 is a digest of html; both are logged at startup so an unexpected
	// page is auditable.
	source string
	sha256 string
}

func main() {
	if err := checkLegacyBackendVars(); err != nil {
		log.Fatalf("config: %v", err)
	}
	backends, err := parseBackends(os.Getenv("BACKENDS"), os.Getenv("BACKEND_LABELS"))
	if err != nil {
		log.Fatalf("BACKENDS: %v", err)
	}

	var (
		listenAddr = env("LISTEN_ADDR", ":8080")
		cookie     = cookieCfg{
			name:       env("COOKIE_NAME", "auth_mode"),
			maxAge:     cookieMaxAge,
			// 15m matches oauth2-proxy's default CSRF cookie expiry: past that the
			// in-flight login can't complete anyway, so a longer window buys nothing.
			tempMaxAge: envInt("COOKIE_TEMP_MAX_AGE", 900),
			modes:      modeSet(backends),
		}
		auth = authCfg{
			pathPrefixes:  envPrefixes("AUTH_PATH_PREFIXES", "/oauth2/"),
			callbackPath:  cleanPath(env("AUTH_CALLBACK_PATH", "/oauth2/callback")),
			sessionCookie: env("AUTH_SESSION_COOKIE", "_oauth2_proxy"),
		}
	)

	sel, err := loadSelector()
	if err != nil {
		// Never fall back to the default page: a silent fallback hides a broken
		// deploy behind something that looks like it works.
		log.Fatalf("selector: %v", err)
	}

	proxies := make(map[string]http.Handler, len(backends))
	for _, b := range backends {
		proxies[b.key] = newProxy(b.url, cookie, auth)
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           newHandler(cookie, sel, proxies),
		MaxHeaderBytes:    1 << 20,           // large injected auth headers (X-Forwarded-Access-Token)
		ReadHeaderTimeout: 10 * time.Second,  // slow-loris guard on headers only
		// Deliberately NO ReadTimeout/WriteTimeout/IdleTimeout: they would sever
		// long-lived WebSocket / SSE / long-polling connections.
	}

	log.Printf("auth-gateway listening on %s (backends=%s cookie=%s temp_max_age=%ds auth_paths=%s callback=%s session_cookie=%s selector=%s sha256=%s)",
		listenAddr, describeBackends(backends), cookie.name, cookie.tempMaxAge,
		strings.Join(auth.pathPrefixes, ","), auth.callbackPath, auth.sessionCookie,
		sel.source, sel.sha256)
	log.Fatal(srv.ListenAndServe())
}

// loadSelector resolves the selector page from the environment: SELECTOR_HTML_FILE
// (a shell read once, here at startup) or SELECTOR_HTML (an inline shell), falling
// back to the embedded default. The two vars are mutually exclusive, and every
// problem — both set, unreadable file, oversized or malformed shell — is an error,
// never a fallback.
//
// Reading the file exactly once is deliberate: after boot there is no runtime file
// access, so no traversal or symlink games and no reload primitive to abuse.
func loadSelector() (selectorPage, error) {
	fragment, err := selectorFS.ReadFile("selector_fragment.html")
	if err != nil {
		return selectorPage{}, fmt.Errorf("embed selector_fragment.html: %w", err)
	}

	file, inline := os.Getenv("SELECTOR_HTML_FILE"), os.Getenv("SELECTOR_HTML")
	var (
		shell  []byte
		source string
	)
	switch {
	case file != "" && inline != "":
		// Ambiguous config: fail loud rather than quietly letting one win.
		return selectorPage{}, errors.New("SELECTOR_HTML_FILE and SELECTOR_HTML are mutually exclusive, set at most one")
	case file != "":
		if shell, err = os.ReadFile(file); err != nil {
			return selectorPage{}, fmt.Errorf("read SELECTOR_HTML_FILE: %w", err)
		}
		source = file
	case inline != "":
		shell, source = []byte(inline), "inline"
	default:
		if shell, err = selectorFS.ReadFile("selector.html"); err != nil {
			return selectorPage{}, fmt.Errorf("embed selector.html: %w", err)
		}
		source = "embedded"
	}

	html, err := renderSelector(shell, fragment)
	if err != nil {
		return selectorPage{}, fmt.Errorf("shell %s: %w", source, err)
	}
	csp, err := selectorCSP(fragment)
	if err != nil {
		return selectorPage{}, err
	}
	sum := sha256.Sum256(html)
	return selectorPage{html: html, csp: csp, source: source, sha256: hex.EncodeToString(sum[:])}, nil
}

// renderSelector splices the gateway's fixed fragment into a shell at its single
// placeholder. The default shell goes through this too, so there is exactly one
// rendering path — and when the selector becomes dynamic (>2 IdPs) the gateway
// renders more ag-btn anchors into the same slot, leaving every shell unchanged.
func renderSelector(shell, fragment []byte) ([]byte, error) {
	if len(shell) > maxSelectorShell {
		return nil, fmt.Errorf("is %d bytes, over the %d byte limit", len(shell), maxSelectorShell)
	}
	switch n := bytes.Count(shell, []byte(selectorPlaceholder)); n {
	case 1:
	case 0:
		return nil, fmt.Errorf("does not contain the %s placeholder", selectorPlaceholder)
	default:
		return nil, fmt.Errorf("contains the %s placeholder %d times, want exactly 1", selectorPlaceholder, n)
	}
	return bytes.Replace(shell, []byte(selectorPlaceholder), fragment, 1), nil
}

// selectorCSP builds the policy served with the selector page. It is deliberately
// close to deny-all: only the gateway's own inline script may run (pinned by
// hash), styles may be inline, and images may only be same-origin or data: URIs.
// External scripts, stylesheets and fonts are all blocked — the contract is one
// self-contained document, with assets travelling inside it as data: URIs.
func selectorCSP(fragment []byte) (string, error) {
	hash, err := inlineScriptHash(fragment)
	if err != nil {
		return "", err
	}
	return "default-src 'none'; style-src 'unsafe-inline'; script-src '" + hash + "'; " +
		"img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'", nil
}

// inlineScriptHash returns the CSP source expression for the fragment's single
// inline script. It is computed from the embedded bytes at startup rather than
// hardcoded, so the hash can never drift from the script that actually ships.
// Browsers hash a script element's text content verbatim, which is exactly the
// byte range between the tags.
//
// It also asserts the fragment holds exactly one bare <script> tag: this
// function only hashes the first literal <script>…</script> pair, so a second
// script or an attribute-bearing tag would ship unhashed and be blocked by the
// CSP at runtime. Failing here makes that a failed rollout instead.
func inlineScriptHash(fragment []byte) (string, error) {
	const openTag, closeTag = "<script>", "</script>"
	if n := bytes.Count(fragment, []byte("<script")); n != 1 {
		return "", fmt.Errorf("selector fragment contains %d <script> tags, want exactly 1", n)
	}
	i := bytes.Index(fragment, []byte(openTag))
	j := bytes.Index(fragment, []byte(closeTag))
	if i < 0 || j < i {
		return "", errors.New("selector fragment has no bare inline <script> to hash")
	}
	sum := sha256.Sum256(fragment[i+len(openTag) : j])
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:]), nil
}

// newHandler wires the gateway routing: control endpoints first, then cookie-based
// backend selection, falling back to the selector page / JSON 401.
func newHandler(cookie cookieCfg, sel selectorPage, proxies map[string]http.Handler) http.Handler {
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
		if p := proxies[mode(r, cookie)]; p != nil {
			p.ServeHTTP(w, r)
			return
		}
		handleNoMode(w, r, sel)
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
func mode(r *http.Request, cookie cookieCfg) string {
	m, _ := cookieMode(r, cookie)
	return m
}

// cookieMode returns the validated routing mode plus whether the cookie is still
// the short-lived variant issued at selection time (value suffixed with
// tempSuffix, e.g. "corp:tmp"). A value outside the configured backend keys
// yields ("", false), so a cookie naming a backend that has since been removed
// from BACKENDS degrades to the selector page instead of routing somewhere else.
func cookieMode(r *http.Request, cookie cookieCfg) (m string, temp bool) {
	c, err := r.Cookie(cookie.name)
	if err != nil {
		return "", false
	}
	v := c.Value
	if strings.HasSuffix(v, tempSuffix) {
		v, temp = strings.TrimSuffix(v, tempSuffix), true
	}
	if !cookie.modes[v] {
		return "", false
	}
	return v, temp
}

// promoteCookie upgrades a still-temporary routing cookie to its full lifetime
// once the auth front door proves the choice was right: a 302 off the callback
// path that also sets the session cookie.
// See README: "Recovering from a wrong choice" (mechanism 2).
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
	m, temp := cookieMode(resp.Request, cookie)
	if m == "" || !temp {
		return // absent/unknown cookie, or already promoted — don't re-set every request
	}
	resp.Header.Add("Set-Cookie", routingCookie(cookie.name, m, cookie.maxAge).String())
}

// setsSessionCookie reports whether the response sets the front door's session
// cookie. Matched by prefix: oauth2-proxy splits sessions too large for one
// cookie into _oauth2_proxy_0, _oauth2_proxy_1, … and never sets the bare name.
// MaxAge >= 0 rather than > 0: an absent Max-Age attribute parses as 0, which is
// what oauth2-proxy's Expires-based session cookies look like. Only an explicit
// negative Max-Age (a deletion) disqualifies the cookie.
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

// rewriteAuthError turns a 401/403 on one of the front door's own endpoints into
// a redirect to /.auth/reset, so a user who picked the wrong IdP lands back on the
// selector instead of on a dead sign-in error page. It reports whether it rewrote.
// See README: "Recovering from a wrong choice" (mechanism 3) for why each of the
// three conditions below is required.
//
// It cannot loop: /.auth/reset is served by the gateway itself, never proxied.
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
	// The body is gone, so every header describing it has to go too — a stale
	// Content-Encoding or Etag on an empty 302 confuses strict clients.
	for _, h := range entityHeaders {
		resp.Header.Del(h)
	}
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

// mayDeleteCookie is the CSRF guard on /.auth/reset: it reports whether the
// request is one we're willing to clear the routing cookie for.
// See README: "Recovering from a wrong choice" (mechanism 1).
//
// Absent Sec-Fetch-Site is allowed — old clients and non-browser agents must
// still reach the endpoint by a plain GET. A cross-origin request is allowed only
// as a top-level navigation, which a third-party page cannot silently forge the
// way it can an <img>/fetch subresource.
func mayDeleteCookie(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	default:
		return r.Header.Get("Sec-Fetch-Mode") == "navigate"
	}
}

// handleSelect sets the routing cookie and redirects back to a validated,
// same-origin relative path. The cookie is deliberately short-lived until a
// successful authenticated request promotes it (see promoteCookie), so a wrong
// choice expires by itself.
func handleSelect(w http.ResponseWriter, r *http.Request, cookie cookieCfg) {
	q := r.URL.Query()
	m := q.Get("mode")
	if !cookie.modes[m] {
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
// It stays a GET on purpose, so the auth-error rewrite can reach it by redirect;
// requests that fail the CSRF guard get the redirect but keep their cookie.
// See README: "Recovering from a wrong choice" (mechanism 1).
func handleReset(w http.ResponseWriter, r *http.Request, cookie cookieCfg) {
	rd := r.URL.Query().Get("rd")
	if !safeRedirect(rd) {
		rd = "/"
	}

	if mayDeleteCookie(r) {
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
func handleNoMode(w http.ResponseWriter, r *http.Request, sel selectorPage) {
	if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		// The page reflects cookie state, so a copy cached after a selection is
		// simply wrong — and an auth page must not sit in a shared proxy cache.
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		// Selection puts rd in the URL; keep those paths out of Referer headers.
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", sel.csp)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sel.html)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
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
// unset or left with no usable entry. Entries are normalized to a rooted,
// trailing-slash-free form so a prefix matches both the path itself and
// everything below it (and "/oauth2" can never match "/oauth2-app").
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
		p = strings.TrimSuffix(cleanPath(p), "/")
		// A root prefix would classify every path as an auth path and void the
		// "never touch application 4xx" guarantee, so it is dropped.
		if p == "" {
			log.Print(`auth path prefix "/" covers every path, ignoring it`)
			continue
		}
		out = append(out, p)
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
