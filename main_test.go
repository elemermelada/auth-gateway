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

// testCookie is the cookie config used by the test gateway.
var testCookie = cookieCfg{name: "auth_mode", maxAge: cookieMaxAge, tempMaxAge: 900}

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
	h := newHandler(testCookie, []byte("<html>SELECTOR</html>"), proxies)
	return h, func() { primary.Close(); secondary.Close() }
}

// testGatewayTo builds a gateway whose "primary" backend is the given handler,
// for tests that need to control the backend's status code.
func testGatewayTo(t *testing.T, backend http.HandlerFunc) (http.Handler, func()) {
	t.Helper()
	srv := httptest.NewServer(backend)
	proxies := map[string]http.Handler{"primary": newProxy(mustParse(t, srv.URL), testCookie, testAuth)}
	return newHandler(testCookie, []byte("<html>SELECTOR</html>"), proxies), srv.Close
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
	if len(sc) != 1 || sc[0].Value != "secondary"+tempSuffix || !sc[0].Secure || !sc[0].HttpOnly {
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
		value    string
		wantMode string
		wantTemp bool
	}{
		{"primary", "primary", false},
		{"secondary", "secondary", false},
		{"primary" + tempSuffix, "primary", true},
		{"secondary" + tempSuffix, "secondary", true},
		{"bogus", "", false},
		{"bogus" + tempSuffix, "", false},
		{tempSuffix, "", false},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "auth_mode", Value: tc.value})
		m, temp := cookieMode(req, "auth_mode")
		if m != tc.wantMode || temp != tc.wantTemp {
			t.Errorf("cookieMode(%q) = (%q, %v), want (%q, %v)", tc.value, m, temp, tc.wantMode, tc.wantTemp)
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

// A cross-site GET to /.auth/reset (an <img>/<iframe> on someone else's page)
// must not be able to clear the routing cookie. The redirect still happens —
// the endpoint stays GET-reachable for the error rewrite — but the cookie stays.
func TestResetIgnoresCrossSiteRequest(t *testing.T) {
	h, cleanup := testHandler(t)
	defer cleanup()

	for _, site := range []string{"cross-site", "same-site"} {
		req := httptest.NewRequest(http.MethodGet, "/.auth/reset", nil)
		req.Header.Set("Sec-Fetch-Site", site)
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
	gw := httptest.NewServer(newHandler(testCookie, nil, proxies))
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
