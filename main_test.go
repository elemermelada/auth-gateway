package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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

// testSelector is the stand-in selector page served by the test gateway. Tests
// that care about the real rendered page go through loadSelector instead.
var testSelector = selectorPage{
	html: []byte("<html>SELECTOR</html>"),
	csp:  "default-src 'none'; script-src 'sha256-stub'",
}

// testCookie is the cookie config used by the test gateway. Its mode set is what
// makes "primary"/"secondary" valid cookie values here; nothing in the gateway
// knows those names any more.
var testCookie = cookieCfg{
	name:          "auth_mode",
	maxAge:        cookieMaxAge,
	tempMaxAge:    900,
	tempMaxStarts: 1,
	modes:         map[string]bool{"primary": true, "secondary": true},
}

// testCookieFor is testCookie with a different set of backend keys.
func testCookieFor(keys ...string) cookieCfg {
	cookie := testCookie
	cookie.modes = map[string]bool{}
	for _, k := range keys {
		cookie.modes[k] = true
	}
	return cookie
}

// testAuth mirrors the production defaults for the oauth2-proxy front door.
var testAuth = authCfg{
	pathPrefixes:  splitPrefixes("/oauth2/"),
	callbackPath:  "/oauth2/callback",
	sessionCookie: "_oauth2_proxy",
}

// navGET builds a top-level-navigation GET, the only request shape the auth-error
// rewrite acts on.
func navGET(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	return req
}

// setSession writes the split session cookie oauth2-proxy sets on a successful
// code exchange (_oauth2_proxy_0, never the bare name).
func setSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "_oauth2_proxy_0", Value: "session-blob", Path: "/"})
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
		"primary":   newProxy(mustParse(t, primary.URL), testCookie, testAuth),
		"secondary": newProxy(mustParse(t, secondary.URL), testCookie, testAuth),
	}
	h := newHandler(testCookie, testAuth, testSelector, proxies)
	return h, func() { primary.Close(); secondary.Close() }
}

// testGatewayKeys builds a gateway over an arbitrary number of keyed backends,
// each echoing its own key, so a test can assert which one a request reached.
func testGatewayKeys(t *testing.T, keys ...string) (http.Handler, cookieCfg, func()) {
	t.Helper()
	var servers []*httptest.Server
	cookie := testCookieFor(keys...)
	proxies := map[string]http.Handler{}
	for _, key := range keys {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "backend="+key)
		}))
		servers = append(servers, srv)
		proxies[key] = newProxy(mustParse(t, srv.URL), cookie, testAuth)
	}
	h := newHandler(cookie, testAuth, testSelector, proxies)
	return h, cookie, func() {
		for _, srv := range servers {
			srv.Close()
		}
	}
}

// testGatewayTo builds a gateway whose "primary" backend is the given handler,
// for tests that need to control the backend's status code.
func testGatewayTo(t *testing.T, backend http.HandlerFunc) (http.Handler, func()) {
	t.Helper()
	srv := httptest.NewServer(backend)
	proxies := map[string]http.Handler{"primary": newProxy(mustParse(t, srv.URL), testCookie, testAuth)}
	return newHandler(testCookie, testAuth, testSelector, proxies), srv.Close
}

// routingCookieOf returns the Set-Cookie entry for the routing cookie, or nil.
func routingCookieOf(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == testCookie.name {
			return c
		}
	}
	return nil
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
	for k, v := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := rec.Header().Get(k); got != v {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
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
	if len(sc) != 1 || sc[0].Value != tempCookieValue("secondary", 0) || !sc[0].Secure || !sc[0].HttpOnly {
		t.Fatalf("cookie not set correctly: %+v", sc)
	}
	// A fresh selection is unproven: it only gets the short lifetime.
	if sc[0].MaxAge != testCookie.tempMaxAge {
		t.Fatalf("MaxAge = %d, want temp %d", sc[0].MaxAge, testCookie.tempMaxAge)
	}
}

// A temp cookie routes exactly like a promoted one — the marker must not break
// backend selection.
func TestTempCookieRoutes(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "secondary" + tempSuffix})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Body.String(); got != "backend=secondary" {
		t.Fatalf("body = %q, want backend=secondary", got)
	}
}

// The temp cookie can expire while the user is still at the IdP. The login must
// survive that: the callback arrives with no routing cookie, the gateway serves
// the selector, and re-selecting the provider must land back on the callback URL
// with `code`/`state` intact so oauth2-proxy can finish the exchange — the user
// does not authenticate again.
func TestExpiredTempCookieMidLoginResumesCallback(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	const callback = "/oauth2/callback?code=abc123&state=xyz789"

	// 1. Callback lands cookieless: selector page, not a 401 and not proxied.
	req := httptest.NewRequest(http.MethodGet, callback, nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "SELECTOR") {
		t.Fatalf("cookieless callback: code=%d body=%q, want the selector page", rec.Code, rec.Body.String())
	}

	// 2. Re-select with rd = the callback URL, exactly as selector.html encodes it.
	req = httptest.NewRequest(http.MethodGet, "/.auth/select?mode=primary&rd="+url.QueryEscape(callback), nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != callback {
		t.Fatalf("location = %q, want %q — the authorization code and state must survive", loc, callback)
	}

	// 3. With the cookie back, the callback reaches the backend that began the flow.
	req = httptest.NewRequest(http.MethodGet, callback, nil)
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary" + tempSuffix})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Body.String(); got != "backend=primary" {
		t.Fatalf("body = %q, want backend=primary", got)
	}
}

// successfulCallback is what oauth2-proxy answers when the code exchange worked:
// a 302 onward with the session cookie attached. That is the promotion signal.
func successfulCallback(w http.ResponseWriter, r *http.Request) {
	setSession(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func TestPromotionOnSuccessfulCallback(t *testing.T) {
	h, cleanup := testGatewayTo(t, successfulCallback)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/callback?code=x&state=y", nil)
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary" + tempSuffix})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	c := routingCookieOf(t, rec)
	if c == nil {
		t.Fatalf("temp cookie was not promoted (no Set-Cookie)")
	}
	if c.Value != "primary" || c.MaxAge != testCookie.maxAge {
		t.Fatalf("promoted cookie = %+v, want value=primary MaxAge=%d", c, testCookie.maxAge)
	}
}

// A 302 off the callback without a session cookie is a failed exchange (or a
// bounce back to the sign-in page) — the choice is not proven.
func TestNoPromotionOnCallbackWithoutSession(t *testing.T) {
	h, cleanup := testGatewayTo(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/oauth2/sign_in", http.StatusFound)
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/callback?code=x", nil)
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary" + tempSuffix})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if c := routingCookieOf(t, rec); c != nil {
		t.Fatalf("sessionless callback promoted the cookie: %+v", c)
	}
}

func TestNoPromotionOnCallbackFailure(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		h, cleanup := testGatewayTo(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		})

		req := navGET("/oauth2/callback?code=x")
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary" + tempSuffix})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if c := routingCookieOf(t, rec); c != nil {
			t.Errorf("status %d promoted the cookie: %+v", status, c)
		}
		cleanup()
	}
}

// A plain 2xx from the app used to promote. It no longer does: only the callback
// proves the choice, so an app that answers 200 to anonymous requests (or any
// backend quirk) can't lock in a provider the user can't actually sign in to.
func TestNoPromotionOnAppSuccess(t *testing.T) {
	h, cleanup := testGatewayTo(t, func(w http.ResponseWriter, r *http.Request) {
		setSession(w) // even with a session cookie in play
		w.WriteHeader(http.StatusOK)
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/app", nil)
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary" + tempSuffix})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if c := routingCookieOf(t, rec); c != nil {
		t.Fatalf("2xx on an app path promoted the cookie: %+v", c)
	}
}

// An already-promoted cookie must not be re-set on every proxied request.
func TestNoRepromotionOfFullCookie(t *testing.T) {
	h, cleanup := testGatewayTo(t, successfulCallback)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/callback?code=x", nil)
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if c := routingCookieOf(t, rec); c != nil {
		t.Fatalf("full cookie was re-set: %+v", c)
	}
}

// oauth2-proxy answering 403 with its sign-in error page is the dead end users
// got stuck on; it must become a redirect to /.auth/reset.
func TestAuthErrorRewrittenToReset(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		h, cleanup := testGatewayTo(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "sign-in failed", status)
		})

		req := navGET("/oauth2/callback?code=x")
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary" + tempSuffix})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("backend %d: gateway status = %d, want 302", status, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/.auth/reset?rd=/" {
			t.Errorf("backend %d: location = %q, want /.auth/reset?rd=/", status, loc)
		}
		if body := rec.Body.String(); strings.Contains(body, "sign-in failed") {
			t.Errorf("backend %d: error page leaked through: %q", status, body)
		}
		cleanup()
	}
}

// A 500 is oauth2-proxy's own breakage, not a wrong-provider dead end. Showing
// the real error beats hiding it behind a reset — and the temp cookie expires on
// its own, so a reload still lands on the selector.
func TestAuthError500PassesThrough(t *testing.T) {
	h, cleanup := testGatewayTo(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal oauth2-proxy failure", http.StatusInternalServerError)
	})
	defer cleanup()

	req := navGET("/oauth2/callback?code=x")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary" + tempSuffix})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 passed through", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "internal oauth2-proxy failure") {
		t.Fatalf("error page not preserved: %q", rec.Body.String())
	}
}

// An XHR/fetch to /oauth2/* must keep its raw 401/403. Rewriting it would drag a
// background request through /.auth/reset and silently drop the routing cookie
// under a page that is still running.
func TestAuthErrorNotRewrittenForNonNavigation(t *testing.T) {
	for _, mode := range []string{"cors", "no-cors", "same-origin"} {
		h, cleanup := testGatewayTo(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "sign-in failed", http.StatusForbidden)
		})

		req := httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil)
		req.Header.Set("Sec-Fetch-Mode", mode)
		req.Header.Set("Accept", "text/html") // must not override Sec-Fetch-Mode
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Sec-Fetch-Mode=%s: status = %d, want 403 passed through", mode, rec.Code)
		}
		cleanup()
	}
}

// Old clients send no Sec-Fetch-Mode; Accept: text/html is the navigation proxy.
func TestAuthErrorRewrittenForLegacyHTMLRequest(t *testing.T) {
	h, cleanup := testGatewayTo(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "sign-in failed", http.StatusForbidden)
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/callback?code=x", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/.auth/reset?rd=/" {
		t.Fatalf("legacy navigation not rewritten: code=%d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
}

// A non-browser client sends neither Sec-Fetch-Mode nor Accept: text/html, so the
// navigation check must fail closed and pass the raw status through.
func TestAuthErrorNotRewrittenForNonBrowserClient(t *testing.T) {
	h, cleanup := testGatewayTo(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "sign-in failed", http.StatusUnauthorized)
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil)
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 passed through", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "sign-in failed") {
		t.Fatalf("body not preserved: %q", rec.Body.String())
	}
}

// The rewritten 302 carries no body, so no header may still describe one.
func TestAuthErrorRewriteClearsEntityHeaders(t *testing.T) {
	h, cleanup := testGatewayTo(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Etag", `"abc"`)
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		w.Header().Set("Vary", "Accept-Encoding")
		http.Error(w, "sign-in failed", http.StatusForbidden)
	})
	defer cleanup()

	req := navGET("/oauth2/callback?code=x")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary" + tempSuffix})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	for _, name := range entityHeaders {
		if v := rec.Header().Get(name); v != "" {
			t.Errorf("%s survived the rewrite: %q", name, v)
		}
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// Application 4xx responses are none of the gateway's business — rewriting them
// would break every app that returns 403 legitimately, and could loop.
func TestAppErrorNotRewritten(t *testing.T) {
	h, cleanup := testGatewayTo(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "app says no", http.StatusForbidden)
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/app/secret", nil)
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 passed through", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "app says no") {
		t.Fatalf("app error body not preserved: %q", rec.Body.String())
	}
}

// The normal oauth2 flow (302 to the provider, 200 sign-in page) must pass through.
func TestAuthPathNonErrorNotRewritten(t *testing.T) {
	h, cleanup := testGatewayTo(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://idp.example.com/authorize", http.StatusFound)
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/start", nil)
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if loc := rec.Header().Get("Location"); loc != "https://idp.example.com/authorize" {
		t.Fatalf("location = %q, want the IdP redirect untouched", loc)
	}
}

func TestCookieMode(t *testing.T) {
	cases := []struct {
		value      string
		wantMode   string
		wantTemp   bool
		wantStarts int
	}{
		{"primary", "primary", false, 0},
		{"secondary", "secondary", false, 0},
		// The bare ":tmp" form is what older versions issued; it must keep working
		// across a rollout, counting as no starts yet.
		{"primary" + tempSuffix, "primary", true, 0},
		{"secondary" + tempSuffix, "secondary", true, 0},
		{tempCookieValue("primary", 0), "primary", true, 0},
		{tempCookieValue("primary", 3), "primary", true, 3},
		{"bogus", "", false, 0},
		{"bogus" + tempSuffix, "", false, 0},
		{tempSuffix, "", false, 0},
		// A counter that is not a non-negative integer invalidates the whole cookie:
		// a hand-edited value must not buy extra trips to the IdP.
		{tempCookieValue("primary", -1), "", false, 0},
		{"primary" + tempSuffix + ":x", "", false, 0},
		{"primary" + tempSuffix + ":", "", false, 0},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tc.value})
		m, temp, starts := cookieMode(req, testCookie)
		if m != tc.wantMode || temp != tc.wantTemp || starts != tc.wantStarts {
			t.Errorf("cookieMode(%q) = (%q, %v, %d), want (%q, %v, %d)",
				tc.value, m, temp, starts, tc.wantMode, tc.wantTemp, tc.wantStarts)
		}
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

func TestResetDeletesCookieAndRedirects(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/.auth/reset?rd=/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Fatalf("location = %q, want /dashboard", loc)
	}
	sc := rec.Result().Cookies()
	if len(sc) != 1 {
		t.Fatalf("want exactly one Set-Cookie, got %+v", sc)
	}
	if sc[0].Name != "auth_mode" || sc[0].MaxAge >= 0 || sc[0].Value != "" {
		t.Fatalf("cookie not deleted: %+v", sc[0])
	}
	// Deletion only takes effect if the attributes match the ones used to set it.
	if sc[0].Path != "/" || !sc[0].Secure || !sc[0].HttpOnly || sc[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("delete cookie attrs don't match the set cookie: %+v", sc[0])
	}
}

func TestResetDefaultsToRoot(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/.auth/reset", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("location = %q, want /", loc)
	}
}

func TestResetOpenRedirectGuard(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/.auth/reset?rd=//evil.com/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("open-redirect not blocked: location = %q, want /", loc)
	}
}

// Reset must win over cookie-based routing: a user stuck on the wrong backend
// still needs the endpoint to answer.
func TestResetHandledEvenWithValidCookie(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/.auth/reset", nil)
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "secondary"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "backend=") {
		t.Fatalf("reset was proxied to a backend: %q", rec.Body.String())
	}
}

// A cross-origin subresource GET to /.auth/reset (an <img> on someone else's
// page) must not be able to clear the routing cookie. The redirect still happens —
// the endpoint stays GET-reachable for the error rewrite — but the cookie stays.
func TestResetIgnoresCrossSiteSubresource(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	for _, site := range []string{"cross-site", "same-site"} {
		req := httptest.NewRequest(http.MethodGet, "/.auth/reset", nil)
		req.Header.Set("Sec-Fetch-Site", site)
		req.Header.Set("Sec-Fetch-Mode", "no-cors")
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("Sec-Fetch-Site=%s: status = %d, want 302", site, rec.Code)
		}
		if c := routingCookieOf(t, rec); c != nil {
			t.Errorf("Sec-Fetch-Site=%s: cookie was cleared cross-site: %+v", site, c)
		}
	}
}

func TestResetAllowedForSameOriginAndDirectNavigation(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	// "none" = typed in the URL bar; "" = old client that sends no Sec-Fetch-Site.
	for _, site := range []string{"same-origin", "none", ""} {
		req := httptest.NewRequest(http.MethodGet, "/.auth/reset", nil)
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		c := routingCookieOf(t, rec)
		if c == nil || c.MaxAge >= 0 {
			t.Errorf("Sec-Fetch-Site=%q: cookie not deleted: %+v", site, c)
		}
	}
}

// A link from Slack/email into the app that ends up on /.auth/reset arrives
// cross-site, and must still clear the cookie — otherwise the user lands back on
// the wrong backend and can re-enter the same dead end. A top-level navigation
// can't be silently forged, so allowing it costs nothing.
func TestResetAllowedForCrossSiteNavigation(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	for _, site := range []string{"cross-site", "same-site"} {
		req := httptest.NewRequest(http.MethodGet, "/.auth/reset", nil)
		req.Header.Set("Sec-Fetch-Site", site)
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("Sec-Fetch-Site=%s: status = %d, want 302", site, rec.Code)
		}
		c := routingCookieOf(t, rec)
		if c == nil || c.MaxAge >= 0 {
			t.Errorf("Sec-Fetch-Site=%s: cookie not deleted on navigation: %+v", site, c)
		}
	}
}

func TestIsAuthPath(t *testing.T) {
	cases := map[string]bool{
		"/oauth2/":          true,
		"/oauth2":           true,
		"/oauth2/callback":  true,
		"/oauth2/sign_in":   true,
		"/app":              false,
		"/":                 false,
		"/oauth2-app/thing": false, // prefix must not match a sibling path
		// Traversal must be resolved before classifying, in both directions.
		"/oauth2/../app":      false,
		"/app/../oauth2/auth": true,
		"//oauth2//callback":  true,
	}
	for in, want := range cases {
		if got := testAuth.isAuthPath(in); got != want {
			t.Errorf("isAuthPath(%q) = %v, want %v", in, got, want)
		}
	}
}

// A multi-prefix front door (e.g. oauth2-proxy plus a custom sign-in route).
func TestIsAuthPathMultiplePrefixes(t *testing.T) {
	a := authCfg{pathPrefixes: splitPrefixes(" /oauth2/ , /auth ")}
	for in, want := range map[string]bool{
		"/oauth2/start": true,
		"/auth/login":   true,
		"/auth":         true,
		"/authorize":    false,
		"/app":          false,
	} {
		if got := a.isAuthPath(in); got != want {
			t.Errorf("isAuthPath(%q) = %v, want %v", in, got, want)
		}
	}
}

// A root prefix would classify every path as an auth path, voiding the "never
// touch application 4xx" guarantee, so it is dropped rather than honored.
func TestSplitPrefixesDropsRoot(t *testing.T) {
	if got := splitPrefixes("/"); len(got) != 0 {
		t.Errorf(`splitPrefixes("/") = %v, want empty`, got)
	}
	if got := splitPrefixes("/, /oauth2/"); len(got) != 1 || got[0] != "/oauth2" {
		t.Errorf(`splitPrefixes("/, /oauth2/") = %v, want ["/oauth2"]`, got)
	}
	// Nothing usable left → envPrefixes falls back to the default.
	if got := envPrefixes("AUTH_PATH_PREFIXES_TEST_UNSET", "/oauth2/"); len(got) != 1 || got[0] != "/oauth2" {
		t.Errorf("envPrefixes default = %v, want [\"/oauth2\"]", got)
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

	proxies := map[string]http.Handler{"primary": newProxy(mustParse(t, backend.URL), testCookie, testAuth)}
	gw := httptest.NewServer(newHandler(testCookie, testAuth, testSelector, proxies))
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

	p := newProxy(mustParse(t, backend.URL), testCookie, testAuth)
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

// testShell is a minimal selector shell for the rendering tests.
const testShell = "<html><body>" + selectorPlaceholder + "</body></html>"

// clearSelectorEnv unsets both selector vars, so a test asserting on the default
// page is not at the mercy of the developer's own environment.
func clearSelectorEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SELECTOR_HTML_FILE", "")
	t.Setenv("SELECTOR_HTML", "")
}

// testBackendList is the two-backend configuration the rendering tests render
// against. It keeps the historical primary/secondary keys, so these tests also
// pin that a deploy migrating with those keys keeps its old-looking page.
const testBackendList = "primary=http://primary:4180,secondary=http://secondary:4181"

// mustLoadSelector renders the selector page from the current environment, for
// the given backend list (defaulting to testBackendList).
func mustLoadSelector(t *testing.T, list ...string) selectorPage {
	t.Helper()
	raw := testBackendList
	if len(list) == 1 {
		raw = list[0]
	}
	sel, err := loadSelector(mustBackends(t, raw, ""))
	if err != nil {
		t.Fatalf("loadSelector: %v", err)
	}
	return sel
}

// mustFragment builds the spliced-in widget for a backend list.
func mustFragment(t *testing.T, list, labels string) string {
	t.Helper()
	fragment, err := selectorFragment(mustBackends(t, list, labels))
	if err != nil {
		t.Fatalf("selectorFragment: %v", err)
	}
	return string(fragment)
}

// inlineScriptOf returns the text content of the single inline <script> in page,
// i.e. exactly the bytes a browser hashes for a script-src 'sha256-…' match.
func inlineScriptOf(t *testing.T, page []byte) []byte {
	t.Helper()
	i, j := strings.Index(string(page), "<script>"), strings.Index(string(page), "</script>")
	if i < 0 || j < i {
		t.Fatalf("page has no inline <script>:\n%s", page)
	}
	return page[i+len("<script>") : j]
}

func TestDefaultSelectorRendersFragment(t *testing.T) {
	clearSelectorEnv(t)

	sel := mustLoadSelector(t)

	if sel.source != "embedded" {
		t.Fatalf("source = %q, want %q", sel.source, "embedded")
	}
	if sel.sha256 == "" {
		t.Fatal("sha256 is empty")
	}
	got := string(sel.html)
	if strings.Contains(got, selectorPlaceholder) {
		t.Fatal("rendered page still contains the placeholder")
	}
	if strings.Contains(got, anchorsPlaceholder) {
		t.Fatal("rendered page still contains the anchors placeholder")
	}
	for _, want := range []string{
		`class="ag-btn ag-btn-primary"`,
		`class="ag-btn ag-btn-secondary"`,
		"/.auth/select?mode=primary",
		"/.auth/select?mode=secondary",
		"&rd=",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered page missing %q:\n%s", want, got)
		}
	}
	// The default shell keeps its own look, and only its own look.
	if !strings.Contains(got, "a.ag-btn {") {
		t.Fatal("rendered page lost the default shell styling")
	}
}

func TestSelectorFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selector.html")
	if err := os.WriteFile(path, []byte(testShell), 0o644); err != nil {
		t.Fatalf("write shell: %v", err)
	}
	t.Setenv("SELECTOR_HTML_FILE", path)

	sel := mustLoadSelector(t)
	if sel.source != path {
		t.Fatalf("source = %q, want %q", sel.source, path)
	}
	if got := string(sel.html); !strings.HasPrefix(got, "<html><body><div class=\"ag-options\">") {
		t.Fatalf("fragment not spliced into the file shell:\n%s", got)
	}
}

func TestSelectorFromInline(t *testing.T) {
	t.Setenv("SELECTOR_HTML", testShell)

	sel := mustLoadSelector(t)
	if sel.source != "inline" {
		t.Fatalf("source = %q, want %q", sel.source, "inline")
	}
	if got := string(sel.html); !strings.Contains(got, `class="ag-btn ag-btn-primary"`) {
		t.Fatalf("fragment not spliced into the inline shell:\n%s", got)
	}
}

// A custom shell only ever replaces the cosmetics: the served links, modes and
// script come from the gateway's fragment no matter what the shell tried to say.
func TestCustomShellCannotOverrideTheWidget(t *testing.T) {
	t.Setenv("SELECTOR_HTML", "<html><body>"+
		`<a href="https://evil.example/steal">Primary</a>`+
		selectorPlaceholder+"</body></html>")

	sel := mustLoadSelector(t)
	got := string(sel.html)
	if !strings.Contains(got, "/.auth/select?mode=primary") {
		t.Fatalf("rendered page lost the gateway select link:\n%s", got)
	}
	// The shell's own markup survives (it is just cosmetics), but the widget the
	// gateway spliced in is the one wired to /.auth/select.
	if strings.Count(got, "<script>") != 1 {
		t.Fatalf("want exactly one inline script, got %d:\n%s", strings.Count(got, "<script>"), got)
	}
}

func TestSelectorBothVarsRejected(t *testing.T) {
	t.Setenv("SELECTOR_HTML_FILE", filepath.Join(t.TempDir(), "selector.html"))
	t.Setenv("SELECTOR_HTML", testShell)

	if _, err := loadSelector(mustBackends(t, testBackendList, "")); err == nil {
		t.Fatal("loadSelector accepted both SELECTOR_HTML_FILE and SELECTOR_HTML")
	}
}

func TestSelectorUnreadableFileRejected(t *testing.T) {
	t.Setenv("SELECTOR_HTML_FILE", filepath.Join(t.TempDir(), "does-not-exist.html"))

	if _, err := loadSelector(mustBackends(t, testBackendList, "")); err == nil {
		t.Fatal("loadSelector accepted an unreadable SELECTOR_HTML_FILE")
	}
}

func TestSelectorBadShellRejected(t *testing.T) {
	fragment := []byte("<div>fragment</div>")
	cases := []struct {
		name  string
		shell string
	}{
		{"no placeholder", "<html><body>no slot here</body></html>"},
		{"two placeholders", "<html><body>" + selectorPlaceholder + selectorPlaceholder + "</body></html>"},
		{"oversized", strings.Repeat("x", maxSelectorShell) + selectorPlaceholder},
	}
	for _, tc := range cases {
		if _, err := renderSelector([]byte(tc.shell), fragment); err == nil {
			t.Fatalf("%s: renderSelector accepted it", tc.name)
		}
	}
}

func TestSelectorResponseHeaders(t *testing.T) {
	clearSelectorEnv(t)

	sel := mustLoadSelector(t)
	h := newHandler(testCookie, testAuth, sel, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	want := map[string]string{
		"Content-Type":           "text/html; charset=utf-8",
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'none'",
		"style-src 'unsafe-inline'",
		"img-src 'self' data:",
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP %q missing %q", csp, want)
		}
	}
}

// The teeth behind "customization is cosmetic": the script-src hash in the served
// CSP must match the script in the served body, or the gateway's own script would
// be blocked (and any other script would be allowed to stand in for it).
func TestSelectorCSPHashMatchesServedScript(t *testing.T) {
	clearSelectorEnv(t)

	sel := mustLoadSelector(t)
	h := newHandler(testCookie, testAuth, sel, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	sum := sha256.Sum256(inlineScriptOf(t, rec.Body.Bytes()))
	want := "script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, want) {
		t.Fatalf("CSP %q does not pin the served script (%s)", csp, want)
	}
}

// inlineScriptHash only hashes the first bare <script>…</script> pair, so a
// fragment with a second script or an attribute-bearing tag must fail at
// startup rather than ship a script the CSP would block.
func TestInlineScriptHashRequiresExactlyOneBareScript(t *testing.T) {
	cases := []struct {
		name     string
		fragment string
	}{
		{"no script", `<div class="ag-options"></div>`},
		{"two scripts", "<script>a()</script><script>b()</script>"},
		{"attribute-bearing tag", `<script defer>a()</script>`},
	}
	for _, tc := range cases {
		if _, err := inlineScriptHash([]byte(tc.fragment)); err == nil {
			t.Fatalf("%s: inlineScriptHash accepted it", tc.name)
		}
	}

	if _, err := inlineScriptHash([]byte(mustFragment(t, testBackendList, ""))); err != nil {
		t.Fatalf("inlineScriptHash rejected the shipped fragment: %v", err)
	}
}

// Pins the fragment's structure from a shell author's perspective: the ag-*
// class names are a public styling contract, so future fragment edits must not
// break shells that rely on them.
func TestSelectorFragmentStylingContract(t *testing.T) {
	got := mustFragment(t, "corp=http://corp,guest=http://guest,partner=http://partner", "")

	if !strings.Contains(got, `<div class="ag-options">`) {
		t.Fatalf("fragment lost the .ag-options wrapper:\n%s", got)
	}
	buttons := regexp.MustCompile(`<a [^>]*class="ag-btn [^"]*"[^>]*>`).FindAllString(got, -1)
	if len(buttons) != 3 {
		t.Fatalf("want 3 ag-btn anchors, got %d:\n%s", len(buttons), got)
	}
	// Every key gets its own class, so a shell can style one provider alone.
	for _, class := range []string{"ag-btn-corp", "ag-btn-guest", "ag-btn-partner"} {
		if !strings.Contains(got, class) {
			t.Fatalf("fragment missing %s:\n%s", class, got)
		}
	}
	// Each button carries a dedicated logo hook, zero-size until a shell styles it.
	if n := strings.Count(got, `<span class="ag-logo" aria-hidden="true"></span>`); n != len(buttons) {
		t.Fatalf("want one ag-logo per button (%d), got %d:\n%s", len(buttons), n, got)
	}
}

// The button order is the BACKENDS order — the one thing an operator controls
// about the page without writing a shell.
func TestSelectorAnchorsFollowConfigOrder(t *testing.T) {
	got := mustFragment(t, "guest=http://guest,corp=http://corp,partner=http://partner", "")

	links := regexp.MustCompile(`/\.auth/select\?mode=([a-z0-9_-]+)`).FindAllStringSubmatch(got, -1)
	var keys []string
	for _, m := range links {
		keys = append(keys, m[1])
	}
	want := []string{"guest", "corp", "partner"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("anchor order = %v, want %v:\n%s", keys, want, got)
	}
}

// Labels are the only free-form config that reaches the page, so they are the
// only thing that has to be escaped.
func TestSelectorLabelsAreEscaped(t *testing.T) {
	got := mustFragment(t, "corp=http://corp", `corp=<script>alert(1)</script> & co`)

	if strings.Contains(got, "<script>alert(1)</script>") {
		t.Fatalf("label was not escaped:\n%s", got)
	}
	if !strings.Contains(got, "&lt;script&gt;alert(1)&lt;/script&gt; &amp; co") {
		t.Fatalf("escaped label missing:\n%s", got)
	}
	// And the fragment still holds exactly the one script the CSP pins.
	if _, err := inlineScriptHash([]byte(got)); err != nil {
		t.Fatalf("a label smuggled a script past inlineScriptHash: %v", err)
	}
}

// The script is generated once and never varies with the backend list: that is
// what lets the CSP hash be computed from the fragment and stay stable across
// deploys with different numbers of IdPs.
func TestSelectorScriptIsIdenticalForAnyBackendCount(t *testing.T) {
	two := mustFragment(t, testBackendList, "")
	five := mustFragment(t, "a=http://a,b=http://b,c=http://c,d=http://d,e=http://e", "")

	if got, want := string(inlineScriptOf(t, []byte(five))), string(inlineScriptOf(t, []byte(two))); got != want {
		t.Fatalf("script differs with the backend count:\n%q\nvs\n%q", got, want)
	}
	twoHash, err := inlineScriptHash([]byte(two))
	if err != nil {
		t.Fatalf("inlineScriptHash: %v", err)
	}
	fiveHash, err := inlineScriptHash([]byte(five))
	if err != nil {
		t.Fatalf("inlineScriptHash: %v", err)
	}
	if twoHash != fiveHash {
		t.Fatalf("CSP hash %s != %s", fiveHash, twoHash)
	}
}

// A custom shell is written once and must keep working as backends come and go.
func TestCustomShellRendersEveryBackend(t *testing.T) {
	t.Setenv("SELECTOR_HTML", testShell)

	sel := mustLoadSelector(t, "corp=http://corp,guest=http://guest,partner=http://partner")

	got := string(sel.html)
	for _, key := range []string{"corp", "guest", "partner"} {
		if !strings.Contains(got, "/.auth/select?mode="+key) {
			t.Fatalf("custom shell missing the %s button:\n%s", key, got)
		}
	}
}

// mustBackends parses a BACKENDS list that the test expects to be valid.
func mustBackends(t *testing.T, list, labels string) []backend {
	t.Helper()
	b, err := parseBackends(list, labels)
	if err != nil {
		t.Fatalf("parseBackends(%q, %q): %v", list, labels, err)
	}
	return b
}

// The list order is the button order on the selector page, so it must survive
// parsing verbatim — and a key with no label gets the key, title-cased.
func TestParseBackendsOrderAndDefaults(t *testing.T) {
	got := mustBackends(t, "corp=http://corp:4180,guest=http://guest:4181,partner-2=http://partner:4182", "")

	want := []struct{ key, label, host string }{
		{"corp", "Corp", "corp:4180"},
		{"guest", "Guest", "guest:4181"},
		{"partner-2", "Partner-2", "partner:4182"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d backends, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].key != w.key || got[i].label != w.label || got[i].url.Host != w.host {
			t.Errorf("backend %d = (%q, %q, %q), want (%q, %q, %q)",
				i, got[i].key, got[i].label, got[i].url.Host, w.key, w.label, w.host)
		}
	}
}

// A URL may contain "=" itself, so entries split on the first one only.
func TestParseBackendsSplitsOnFirstEquals(t *testing.T) {
	got := mustBackends(t, "corp=http://corp:4180/?a=b", "")
	if len(got) != 1 || got[0].url.String() != "http://corp:4180/?a=b" {
		t.Fatalf("got %+v, want one backend with the query intact", got)
	}
}

func TestParseBackendsLabels(t *testing.T) {
	got := mustBackends(t, "corp=http://corp,guest=http://guest", "corp=Corporate SSO")
	if got[0].label != "Corporate SSO" {
		t.Errorf("corp label = %q, want %q", got[0].label, "Corporate SSO")
	}
	if got[1].label != "Guest" {
		t.Errorf("guest label = %q, want the default %q", got[1].label, "Guest")
	}
}

func TestParseBackendsRejectsBadConfig(t *testing.T) {
	cases := []struct{ name, list, labels string }{
		{"empty list", "", ""},
		{"blank entries only", " , ", ""},
		{"no url", "corp", ""},
		{"empty url", "corp=", ""},
		{"relative url", "corp=/corp", ""},
		{"uppercase key", "Corp=http://corp", ""},
		{"dotted key", "corp.eu=http://corp", ""},
		{"empty key", "=http://corp", ""},
		{"key too long", strings.Repeat("a", 65) + "=http://corp", ""},
		{"duplicate key", "corp=http://a,corp=http://b", ""},
		{"label without value", "corp=http://corp", "corp"},
		{"label for unknown key", "corp=http://corp", "guest=Guest access"},
	}
	for _, tc := range cases {
		if _, err := parseBackends(tc.list, tc.labels); err == nil {
			t.Errorf("%s: parseBackends(%q, %q) accepted it", tc.name, tc.list, tc.labels)
		}
	}
}

// The removed vars must fail the deploy, not be ignored: a gateway that silently
// drops them serves the selector page to everyone with no explanation.
func TestLegacyBackendVarsAreFatal(t *testing.T) {
	for _, key := range legacyBackendVars {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "http://localhost:4180")
			err := checkLegacyBackendVars()
			if err == nil {
				t.Fatalf("checkLegacyBackendVars accepted %s", key)
			}
			// The message has to carry the migration, or an operator is left guessing.
			if !strings.Contains(err.Error(), "BACKENDS") {
				t.Errorf("error %q does not point at BACKENDS", err)
			}
		})
	}
	if err := checkLegacyBackendVars(); err != nil {
		t.Fatalf("checkLegacyBackendVars failed with neither var set: %v", err)
	}
}

// Three keyed backends, no "primary"/"secondary" anywhere: each cookie value
// must reach its own upstream.
func TestRoutingByCookieWithManyBackends(t *testing.T) {
	keys := []string{"corp", "guest", "partner"}
	h, _, cleanup := testGatewayKeys(t, keys...)
	defer cleanup()

	for _, key := range keys {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: key})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if want := "backend=" + key; rec.Body.String() != want {
			t.Errorf("cookie %q routed to %q, want %q", key, rec.Body.String(), want)
		}
	}
}

// Dropping a backend from BACKENDS must not re-map its cookies onto another IdP:
// the value is simply no longer valid, and the user gets the selector back.
func TestCookieForRemovedBackendFallsThroughToSelector(t *testing.T) {
	h, _, cleanup := testGatewayKeys(t, "corp", "guest")
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "partner"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != string(testSelector.html) {
		t.Fatalf("status = %d body = %q, want the selector page", rec.Code, rec.Body.String())
	}
}

// Selection works for any configured key, and only for a configured key.
func TestSelectAcceptsConfiguredKeysOnly(t *testing.T) {
	h, _, cleanup := testGatewayKeys(t, "corp", "guest")
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/.auth/select?mode=corp&rd=/app", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	c := routingCookieOf(t, rec)
	if c == nil || c.Value != tempCookieValue("corp", 0) {
		t.Fatalf("routing cookie = %+v, want value %q", c, tempCookieValue("corp", 0))
	}

	req = httptest.NewRequest(http.MethodGet, "/.auth/select?mode=primary", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d for an unconfigured key, want 400", rec.Code)
	}
}

// Promotion is key-agnostic: a successful callback promotes whatever key the
// temp cookie carries.
func TestPromotionForCustomKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(successfulCallback))
	defer srv.Close()

	cookie := testCookieFor("corp")
	proxies := map[string]http.Handler{"corp": newProxy(mustParse(t, srv.URL), cookie, testAuth)}
	h := newHandler(cookie, testAuth, testSelector, proxies)

	req := navGET("/oauth2/callback?code=abc&state=xyz")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "corp" + tempSuffix})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	c := routingCookieOf(t, rec)
	if c == nil {
		t.Fatal("no routing cookie set, want promotion to the full lifetime")
	}
	if c.Value != "corp" || c.MaxAge != cookieMaxAge {
		t.Fatalf("routing cookie = (%q, %d), want (%q, %d)", c.Value, c.MaxAge, "corp", cookieMaxAge)
	}
}

// idpForward is oauth2-proxy handing the browser off to the IdP: a 302 to another
// host. That response, on an auth path, is what the start counter counts.
func idpForward(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://idp.example.com/authorize?client_id=x", http.StatusFound)
}

// navFrom builds a top-level navigation carrying a Sec-Fetch-Site value.
func navFrom(target, site string) *http.Request {
	req := navGET(target)
	req.Header.Set("Sec-Fetch-Site", site)
	return req
}

// The first handoff to the IdP is the one the selection paid for: it goes
// through, and only bumps the counter in the cookie.
func TestFirstStartIsCountedNotBlocked(t *testing.T) {
	h, cleanup := testGatewayTo(t, idpForward)
	defer cleanup()

	req := navFrom("/oauth2/start?rd=%2Fapp", "same-origin")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 0)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://idp.example.com/") {
		t.Fatalf("location = %q, want the IdP handoff to pass through", loc)
	}
	c := routingCookieOf(t, rec)
	if c == nil || c.Value != tempCookieValue("primary", 1) {
		t.Fatalf("routing cookie = %+v, want value %q", c, tempCookieValue("primary", 1))
	}
	if c.MaxAge != testCookie.tempMaxAge {
		t.Fatalf("routing cookie MaxAge = %d, want the temp lifetime %d", c.MaxAge, testCookie.tempMaxAge)
	}
}

// A second handoff under the same unproven cookie means the first trip produced
// no session: the user goes to the selector instead of back to the same IdP.
func TestSecondStartResetsInsteadOfLoopingToIdP(t *testing.T) {
	h, cleanup := testGatewayTo(t, idpForward)
	defer cleanup()

	req := navFrom("/oauth2/start?rd=%2Fapp", "same-origin")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 1)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/.auth/reset?rd=/" {
		t.Fatalf("location = %q, want /.auth/reset?rd=/", loc)
	}
}

// A deep link into the app mid-login is caught one redirect later, when it
// re-enters the funnel — this is what replaced the dropped rd allowlist.
func TestDeepLinkMidLoginResetsAtItsStart(t *testing.T) {
	h, cleanup := testGatewayTo(t, idpForward)
	defer cleanup()

	// The deep link itself is same-origin (an in-app link), so rule 1 lets it by;
	// the redirect it triggers into /oauth2/start is the second start.
	req := navFrom("/oauth2/start?rd=%2Fdeep", "same-origin")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 1)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if loc := rec.Header().Get("Location"); loc != "/.auth/reset?rd=/" {
		t.Fatalf("location = %q, want /.auth/reset?rd=/", loc)
	}
}

// COOKIE_TEMP_MAX_STARTS is the budget, and it is configurable.
func TestStartLimitIsConfigurable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(idpForward))
	defer srv.Close()

	cookie := testCookie
	cookie.tempMaxStarts = 2
	h := newHandler(cookie, testAuth, testSelector,
		map[string]http.Handler{"primary": newProxy(mustParse(t, srv.URL), cookie, testAuth)})

	req := navFrom("/oauth2/start", "same-origin")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 1)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://idp.example.com/") {
		t.Fatalf("location = %q, want the second start allowed at limit 2", loc)
	}
}

// oauth2-proxy's own internal redirects (sign_in -> start, callback -> app) stay
// on our host and are not handoffs, so they must not consume the budget.
func TestInternalRedirectIsNotAStart(t *testing.T) {
	h, cleanup := testGatewayTo(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/oauth2/start?rd=%2Fapp", http.StatusFound)
	})
	defer cleanup()

	req := navFrom("/oauth2/sign_in", "same-origin")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 1)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if loc := rec.Header().Get("Location"); loc != "/oauth2/start?rd=%2Fapp" {
		t.Fatalf("location = %q, want the internal redirect untouched", loc)
	}
	if c := routingCookieOf(t, rec); c != nil {
		t.Fatalf("internal redirect touched the cookie: %+v", c)
	}
}

// An app path that happens to redirect off-site is not a sign-in start.
func TestExternalRedirectOffAnAppPathIsNotAStart(t *testing.T) {
	h, cleanup := testGatewayTo(t, idpForward)
	defer cleanup()

	req := navFrom("/app/go", "same-origin")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 1)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://idp.example.com/") {
		t.Fatalf("location = %q, want the app redirect untouched", loc)
	}
	if c := routingCookieOf(t, rec); c != nil {
		t.Fatalf("app redirect touched the cookie: %+v", c)
	}
}

// AUTH_START_PATH narrows the counter to one exact path.
func TestStartPathNarrowsDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(idpForward))
	defer srv.Close()

	auth := testAuth
	auth.startPath = "/oauth2/start"
	h := newHandler(testCookie, auth, testSelector,
		map[string]http.Handler{"primary": newProxy(mustParse(t, srv.URL), testCookie, auth)})

	// Over the limit, but on a different auth path: not a start any more.
	req := navFrom("/oauth2/sign_in", "same-origin")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 1)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://idp.example.com/") {
		t.Fatalf("location = %q, want /oauth2/sign_in exempt from the counter", loc)
	}

	req = navFrom("/oauth2/start", "same-origin")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 1)})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if loc := rec.Header().Get("Location"); loc != "/.auth/reset?rd=/" {
		t.Fatalf("location = %q, want the configured start path counted", loc)
	}
}

// A proven (full) cookie has nothing to prove: sign-ins are never counted.
func TestStartsNotCountedForFullCookie(t *testing.T) {
	h, cleanup := testGatewayTo(t, idpForward)
	defer cleanup()

	req := navFrom("/oauth2/start", "same-origin")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://idp.example.com/") {
		t.Fatalf("location = %q, want a re-login on a proven cookie to pass", loc)
	}
	if c := routingCookieOf(t, rec); c != nil {
		t.Fatalf("full cookie was rewritten by the start counter: %+v", c)
	}
}

// Coming back from outside mid-login (typed URL, bookmark, the IdP error page's
// "back to the app" link) means the login never finished: reset.
func TestCrossSiteReturnResets(t *testing.T) {
	for _, site := range []string{"cross-site", "none"} {
		h, cleanup := testHandler(t)

		req := navFrom("/app", site)
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 1)})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("%s: status = %d, want 302", site, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/.auth/reset?rd=/" {
			t.Errorf("%s: location = %q, want /.auth/reset?rd=/", site, loc)
		}
		cleanup()
	}
}

// The callback is a cross-site navigation by definition — and it is the login
// working. It must never trip the return check.
func TestCallbackExemptFromReturnCheck(t *testing.T) {
	h, cleanup := testGatewayTo(t, successfulCallback)
	defer cleanup()

	req := navFrom("/oauth2/callback?code=x&state=y", "cross-site")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 1)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	c := routingCookieOf(t, rec)
	if c == nil || c.Value != "primary" {
		t.Fatalf("routing cookie = %+v, want the cross-site callback to promote", c)
	}
}

// The whole login runs same-origin after the selector, so nothing in it trips the
// return check: the select redirect, the rd page and /oauth2/start all pass.
func TestSameOriginNavigationPassesDuringLogin(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	for _, site := range []string{"same-origin", "same-site", ""} {
		req := navFrom("/app", site)
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 0)})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if got := rec.Body.String(); got != "backend=primary" {
			t.Errorf("Sec-Fetch-Site %q: body = %q, want the request proxied", site, got)
		}
	}
}

// Subresources and XHR carry the cookie too (SameSite=Lax only restricts
// cross-site sends), so the return check is navigation-only. Redirecting a
// stylesheet or a fetch would drop the cookie under a page mid-login.
func TestCrossSiteSubresourcePassesUntouched(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	for _, mode := range []string{"cors", "no-cors", "same-origin"} {
		req := httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
		req.Header.Set("Sec-Fetch-Mode", mode)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 0)})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if got := rec.Body.String(); got != "backend=primary" {
			t.Errorf("Sec-Fetch-Mode %q: body = %q, want the subresource proxied", mode, got)
		}
	}
}

// A proven cookie is nobody's mid-login state: an inbound link from anywhere must
// keep routing, not sign the user out.
func TestCrossSiteReturnIgnoresFullCookie(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	req := navFrom("/app", "cross-site")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: "primary"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Body.String(); got != "backend=primary" {
		t.Fatalf("body = %q, want a proven cookie to keep routing", got)
	}
}

// The control endpoints are gateway-owned and run before the return check, so
// /.auth/reset itself can be reached cross-site — otherwise the redirect the
// check emits would loop.
func TestReturnCheckDoesNotLoopOnReset(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	req := navFrom("/.auth/reset?rd=/", "cross-site")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 1)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("location = %q, want the reset endpoint to answer normally", loc)
	}
	if c := routingCookieOf(t, rec); c == nil || c.MaxAge >= 0 {
		t.Fatalf("routing cookie = %+v, want a deletion", c)
	}
}

// A start path is any auth path but the callback, unless AUTH_START_PATH pins it.
func TestIsStartPath(t *testing.T) {
	narrowed := testAuth
	narrowed.startPath = "/oauth2/start"
	cases := []struct {
		auth authCfg
		path string
		want bool
	}{
		{testAuth, "/oauth2/start", true},
		{testAuth, "/oauth2/sign_in", true},
		{testAuth, "/oauth2/callback", false},
		{testAuth, "/app", false},
		{narrowed, "/oauth2/start", true},
		{narrowed, "/oauth2/start/", true},
		{narrowed, "/oauth2/sign_in", false},
	}
	for _, tc := range cases {
		if got := tc.auth.isStartPath(tc.path); got != tc.want {
			t.Errorf("isStartPath(%q) with startPath %q = %v, want %v",
				tc.path, tc.auth.startPath, got, tc.want)
		}
	}
}

func TestEnvPath(t *testing.T) {
	cases := map[string]string{"": "", "  ": "", "/oauth2/start": "/oauth2/start",
		"oauth2/start": "/oauth2/start", "/oauth2//start/": "/oauth2/start"}
	for raw, want := range cases {
		t.Setenv("AUTH_START_PATH", raw)
		if got := envPath("AUTH_START_PATH"); got != want {
			t.Errorf("envPath(%q) = %q, want %q", raw, got, want)
		}
	}
}

// A prefetched or background-loaded auth path must not spend the start budget:
// the user has not started anything, and with the default limit of 1 the real
// click would land as starts=2 and reset.
func TestStartsNotCountedForNonNavigation(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
	}{
		{"xhr", map[string]string{"Sec-Fetch-Mode": "cors"}},
		{"no-cors", map[string]string{"Sec-Fetch-Mode": "no-cors"}},
		{"prefetch", map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Purpose": "prefetch"}},
		{"prerender", map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Purpose": "prefetch;prerender"}},
	}
	for _, tc := range cases {
		h, cleanup := testGatewayTo(t, idpForward)

		// Over the limit already: if this counted, it would be rewritten.
		req := httptest.NewRequest(http.MethodGet, "/oauth2/start?rd=%2Fapp", nil)
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 1)})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://idp.example.com/") {
			t.Errorf("%s: location = %q, want the response untouched", tc.name, loc)
		}
		if c := routingCookieOf(t, rec); c != nil {
			t.Errorf("%s: start counter bumped the cookie: %+v", tc.name, c)
		}
		cleanup()
	}
}

// A client sending no Sec-Fetch-* headers (legacy Safari) still gets rule 2, via
// the Accept fallback — dropping it there would leave those users in the loop.
func TestStartsCountedForLegacyClient(t *testing.T) {
	h, cleanup := testGatewayTo(t, idpForward)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/oauth2/start", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 1)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if loc := rec.Header().Get("Location"); loc != "/.auth/reset?rd=/" {
		t.Fatalf("location = %q, want /.auth/reset?rd=/", loc)
	}
}

// Only a redirect to another *hostname* is a handoff to the IdP. An absolute
// same-host redirect (with or without an explicit port on either side) is
// oauth2-proxy talking to itself and must not spend the budget.
func TestIsExternalRedirect(t *testing.T) {
	cases := []struct {
		reqHost  string
		location string
		want     bool
	}{
		{"app.example.com", "/oauth2/start?rd=%2Fapp", false},
		{"app.example.com", "https://app.example.com/oauth2/start", false},
		{"app.example.com", "https://app.example.com:443/oauth2/start", false},
		{"app.example.com:8443", "https://app.example.com/oauth2/start", false},
		{"app.example.com", "https://APP.example.com/oauth2/start", false},
		{"app.example.com", "https://idp.example.com/authorize", true},
		{"app.example.com", "//idp.example.com/authorize", true},
		{"app.example.com", "", false},
	}
	for _, tc := range cases {
		resp := &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{tc.location}},
			Request:    &http.Request{Host: tc.reqHost},
		}
		if got := isExternalRedirect(resp); got != tc.want {
			t.Errorf("isExternalRedirect(host %q -> %q) = %v, want %v",
				tc.reqHost, tc.location, got, tc.want)
		}
	}
}

// The blocked start is a healthy upstream response being cancelled: its cookies
// (oauth2-proxy's CSRF cookie for a login that will not happen) and its caching
// must not ride along on the reset redirect.
func TestBlockedStartDropsUpstreamCookies(t *testing.T) {
	h, cleanup := testGatewayTo(t, func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "_oauth2_proxy_csrf", Value: "csrf-blob", Path: "/"})
		w.Header().Set("Cache-Control", "max-age=600")
		idpForward(w, r)
	})
	defer cleanup()

	req := navFrom("/oauth2/start", "same-origin")
	req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tempCookieValue("primary", 1)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("Set-Cookie = %q, want the upstream cookies dropped", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}
