# auth-gateway

Oauth2-Proxy instance selector frontdoor to effectively enable a multi-provider setup.

A tiny, stateless Go reverse proxy that sits between the ingress and two
`oauth2-proxy` instances. Instead of discriminating by **hostname**, it routes by
its **own cookie** (`auth_mode`), so both auth modes can live behind a single
hostname/ingress.

```
ingress ──► auth-gateway ──┬─► oauth2-proxy-primary    ──► app
                           └─► oauth2-proxy-secondary  ──► app
```

## Behavior

| Situation | Response |
| --- | --- |
| Valid `auth_mode` cookie (`primary`\|`secondary`) | Reverse-proxy **all** paths (incl. `/oauth2/*`, WebSockets) to the matching backend |
| No/unknown cookie + `GET` with `Accept: text/html` | `200` selector page (two buttons), `no-store` + `nosniff` + a locked-down CSP. Built-in by default, customizable per deploy — see [Custom selector page](#custom-selector-page) |
| No/unknown cookie + anything else | `401` with small JSON body |
| `GET /.auth/select?mode=<primary\|secondary>&rd=<path>` | Set cookie (short-lived, see below), `302` to `rd` (open-redirect–guarded; defaults to `/`) |
| `GET /.auth/reset?rd=<path>` | **Delete** the cookie, `302` to `rd` (same guard, defaults to `/` → selector page). Cross-origin *subresource* requests get the redirect but keep the cookie |
| `GET /healthz` | `200` (liveness/readiness) |
| Backend returns `401`/`403` on one of its own auth endpoints (`/oauth2/*`), **on a navigation** | `302` to `/.auth/reset?rd=/` |

There is **no mode-switch endpoint** by design — a stale oauth2-proxy session
cookie after a manual switch just re-triggers login. To change provider, hit
`/.auth/reset` and pick again.

## Recovering from a wrong choice

Picking the wrong provider used to be effectively permanent — the cookie lasted
a year and every request was routed to an IdP that would never let the user in.
Three mechanisms make it recoverable:

1. **`/.auth/reset`** — deletes the routing cookie (with the exact attributes it
   was set with, so the deletion actually matches) and sends the user back to the
   selector. This is the manual escape hatch; link it from your app as
   *"wrong provider? start over"* → `/.auth/reset?rd=/`.

   It stays a plain `GET` (mechanism 3 needs a reset reachable by redirect), so
   CSRF abuse is neutered rather than blocked. The cookie is cleared when
   `Sec-Fetch-Site` is `same-origin`/`none`, when the header is absent (old
   clients, curl), or when a cross-origin request is a **top-level navigation**
   (`Sec-Fetch-Mode: navigate`) — a link from Slack or an email that ends up on
   `/.auth/reset` has to work, and a navigation can't be silently forged the way
   an `<img>`/`fetch` subresource can. A cross-origin *subresource* still gets its
   redirect, but keeps the cookie, so a third-party page can't reset someone's
   provider choice behind their back.
2. **Two-stage cookie lifetime, promoted by the callback.** `/.auth/select`
   issues the cookie with `COOKIE_TEMP_MAX_AGE` (default `900`s) and the value
   marked `<mode>:tmp`. It is promoted to the full ~1 year exactly when the auth
   front door proves the choice: a **`302` off `AUTH_CALLBACK_PATH` that also
   sets `AUTH_SESSION_COOKIE`**. That pair only occurs when the code exchange
   succeeded — a failed callback answers `4xx`/`5xx` and sets no session — so a
   provider the user can't actually sign in to is *never* promoted. The `:tmp`
   marker also keeps the gateway from re-setting the cookie on every request.

   The session cookie is matched by **name prefix**, because oauth2-proxy splits
   sessions too large for one cookie into `_oauth2_proxy_0`, `_1`, … and never
   sets the bare name.
3. **Auto-redirect on auth error.** A `401`/`403` from an auth-path endpoint
   (oauth2-proxy's sign-in error page) is rewritten to a `302` to
   `/.auth/reset?rd=/`, so the dead end becomes a fresh selection. It is
   deliberately narrow:
   - scoped to `AUTH_PATH_PREFIXES`, so **application** 4xx responses pass
     through untouched — and it cannot loop, since `/.auth/reset` is served by
     the gateway itself and clears the cookie;
   - `500` passes through, so the user sees oauth2-proxy's real error instead of
     a reset that hides it. Nothing is lost: the temp cookie expires by itself
     and a reload lands on the selector;
   - only on top-level navigations (`Sec-Fetch-Mode: navigate`, falling back to
     `Accept: text/html` for old clients). A background XHR to `/oauth2/auth`
     keeps its raw `401`/`403` instead of being dragged through `/.auth/reset`
     and silently dropping the routing cookie under a live page.

Auth paths are classified on the **cleaned** request path, so
`/oauth2/../app` is treated as the app path it actually resolves to.

Both `<mode>` and `<mode>:tmp` route identically, so the marker is invisible to
routing.

### If the temp cookie expires mid-login

It doesn't cost the user their login. The IdP redirects back to
`/oauth2/callback?code=…&state=…`, the gateway finds no routing cookie and serves
the **selector page at that callback URL**. The selector puts
`location.pathname + location.search` into `rd`, so picking the provider again
redirects straight back to the callback *with `code` and `state` intact* and
oauth2-proxy completes the exchange — one extra click, no re-authentication.

Two consequences worth knowing:

- `COOKIE_TEMP_MAX_AGE` doesn't need slack for slow users. The real deadline is
  oauth2-proxy's CSRF cookie (`--cookie-csrf-expire`, 15m by default) and the
  IdP's authorization-code lifetime; once those lapse the resumed callback gets a
  `403`, which the gateway turns into `/.auth/reset?rd=/` for a clean restart
  (it's a navigation, so the rewrite applies).
  Hence the `900`s default.
- Anything hand-building a `/.auth/select` link must **URL-encode `rd`**
  (`encodeURIComponent`), or `&state=…` is parsed as a parameter of
  `/.auth/select` and silently dropped from the redirect. The selector page's own
  script does this correctly — and it is gateway-owned, so a custom page inherits
  it rather than re-implementing it (see [Custom selector page](#custom-selector-page)).

## Configuration (env vars)

| Var | Default | Notes |
| --- | --- | --- |
| `BACKEND_PRIMARY` | *(required)* | Full URL, e.g. `http://oauth2-proxy-primary` |
| `BACKEND_SECONDARY` | *(required)* | Full URL, e.g. `http://oauth2-proxy-secondary` |
| `LISTEN_ADDR` | `:8080` | |
| `COOKIE_NAME` | `auth_mode` | |
| `COOKIE_TEMP_MAX_AGE` | `900` | Seconds a freshly selected, not-yet-proven mode lasts. Matches oauth2-proxy's default CSRF cookie expiry. Must be a positive integer; anything else falls back to the default with a log line. |
| `AUTH_PATH_PREFIXES` | `/oauth2/` | Comma-separated path prefixes owned by the auth front door. Used to scope the error rewrite and to keep the front door's own endpoints out of the app's namespace. Each entry matches the path itself and everything below it, so `/oauth2` never matches `/oauth2-app`. A `/` entry is ignored (it would make every path an auth path); if nothing usable is left, the default is used, with a log line. |
| `AUTH_CALLBACK_PATH` | `/oauth2/callback` | Exact path the IdP redirects back to. A `302` here that sets the session cookie is the promotion signal. |
| `AUTH_SESSION_COOKIE` | `_oauth2_proxy` | Name **prefix** of the front door's session cookie (oauth2-proxy splits large sessions into `_oauth2_proxy_0`, `_1`, …). |
| `SELECTOR_HTML_FILE` | *(unset)* | Path to a custom selector **shell**, read **once at startup**. See [Custom selector page](#custom-selector-page). |
| `SELECTOR_HTML` | *(unset)* | The same shell passed inline, for setups without a volume to mount. Mutually exclusive with `SELECTOR_HTML_FILE` — setting both is fatal. |

The three `AUTH_*` vars are what keep the gateway generic: the defaults describe
oauth2-proxy, but any front door that owns a path prefix and sets a session
cookie on its callback works by pointing them elsewhere.

## Custom selector page

The selector page is customizable per deploy — the same image can serve a
differently branded page in every environment — but only *cosmetically*. The
buttons, the modes they select, and the script that preserves where the user was
headed stay gateway-owned.

The mechanism is placeholder injection. What you supply is a **shell**, not a
whole page: one self-contained HTML document containing the token

```
<!--AUTH_GATEWAY_SELECTOR-->
```

exactly once. At startup the gateway replaces that token with the selector
widget it owns, from
[`selector_fragment.html`](selector_fragment.html):

```html
<div class="ag-options">
  <a id="ag-primary" class="ag-btn ag-btn-primary" href="/.auth/select?mode=primary"><span class="ag-logo" aria-hidden="true"></span>Primary</a>
  <a id="ag-secondary" class="ag-btn ag-btn-secondary" href="/.auth/select?mode=secondary"><span class="ag-logo" aria-hidden="true"></span>Secondary</a>
</div>
<script>
  // Preserve where the user was headed so /.auth/select can redirect back.
  …
</script>
```

The `ag-*` class names are the **styling contract** — a stable API you may rely
on: `.ag-options` wraps the buttons, each button is an `ag-btn` anchor with an
`ag-btn-<mode>` variant class, and each contains an empty `.ag-logo` span (it
renders nothing until a shell styles it — see the logo example below). The
fragment ships no styling of its own beyond those hooks, so a shell owns the
whole look. And because the widget is generated rather than authored, a shell
written today keeps working when the selector becomes dynamic (more than two
IdPs): the gateway simply renders more `ag-btn` anchors, each with its own
`.ag-logo`, into the same slot — addressable per mode via `ag-btn-<mode>`.

Pass the shell as either [`SELECTOR_HTML_FILE`](#configuration-env-vars) (a path,
read once at startup) or `SELECTOR_HTML` (the HTML itself). Set neither and the
built-in [`selector.html`](selector.html) is used — it is a shell like any other,
so there is exactly one rendering path. Set **both** and the gateway refuses to
start.

### Rules (all enforced at startup, all fatal)

A misconfigured auth page must not ship, so none of these degrade to the default
page — the process exits and the rollout fails instead:

- both `SELECTOR_HTML_FILE` and `SELECTOR_HTML` set (ambiguous config),
- `SELECTOR_HTML_FILE` unreadable,
- the shell missing the placeholder, or containing it more than once,
- the shell larger than 1 MiB,
- the gateway's own fragment not containing exactly one bare `<script>` tag
  (guards the CSP hash — see below).

Shells must be UTF-8 — the response always declares `charset=utf-8`.

On a successful start the log line carries `selector=<embedded|inline|path>` and
`sha256=<digest of the rendered page>`, so serving an unexpected page is
detectable from the logs alone.

### One self-contained document

The selector response is served with `Cache-Control: no-store`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (selection
puts the original destination in the URL as `rd`, which must not leak via
`Referer`), and a deliberately near-deny-all CSP:

```
default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-<fragment script>';
img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

The `script-src` hash is computed **at startup from the embedded fragment's own
script bytes** (never hardcoded, so it cannot drift). The practical consequences,
stated plainly because they are decisions rather than accidents:

- **Your JavaScript will not run, by design.** Only the gateway's fragment script
  matches the hash, so no script a shell smuggles in can execute or rewrite the
  gateway's own widget. (This is a script boundary, not a markup one — see
  [The trust boundary](#the-trust-boundary) for what it does *not* prevent.)
- **No external scripts, stylesheets, fonts, or remote images.** `<link
  rel=stylesheet>`, webfont URLs and `<img src=https://…>` are all blocked.
  Inline `<style>` is allowed; images, icons and logos travel inside the document
  as `data:` URIs.
- The page cannot be framed, cannot set a `<base>`, and can only submit forms
  same-origin.

A logo goes on a button through the `.ag-logo` element every button carries
(empty and zero-size until styled), targeted per mode via the parent class:

```html
<style>
  .ag-btn { display: flex; align-items: center; gap: .5rem; }
  .ag-btn-primary .ag-logo {
    width: 20px; height: 20px;
    background: url("data:image/svg+xml;base64,PHN2ZyB…") center/contain no-repeat;
  }
</style>
```

If a strict `img-src`/`font-src` ever blocks a legitimate use, that is the knob
to loosen — cosmetic still does not mean arbitrary.

### The trust boundary

The shell is **operator-trusted deployment config**, at exactly the same trust
level as `BACKEND_PRIMARY`: whoever controls the deploy config controls the
page. It never comes from a user, and no request data is ever interpolated into
it (`rd` is handled client-side by the fixed script, and `/.auth/select`
validates `mode` and `rd` server-side regardless). The file is read once at
startup, so after boot there is no runtime file access to abuse: no traversal,
no symlink games, no reload primitive.

The CSP's guarantee behind that is precise, and narrower than "nothing to
spoof": **no script executes except the gateway's own, and nothing can rewrite
the gateway's widget at runtime.** It does not — and cannot — prevent
markup-level spoofing by whoever controls the deploy config: a tampered shell
can still add look-alike anchors pointing elsewhere, a
`<meta http-equiv="refresh">` redirect, or a same-origin form. If your deploy
config is compromised, the selector page is compromised — the same way a
tampered `BACKEND_PRIMARY` would be. Protect the config; the CSP limits blast
radius, it does not substitute for that.

Note also that `SELECTOR_HTML` (the inline variant) is visible via
`kubectl describe pod` and `/proc` like any env var — the shell content is
non-secret by design, so this is fine; just don't put secrets in it.

### Helm

```yaml
config:
  selectorHtml: |
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>Sign in to Acme</title>
      <style>
        body { font-family: system-ui; display: grid; place-items: center; min-height: 100vh; }
        .ag-options { display: grid; gap: .75rem; }
        .ag-btn { padding: .85rem 1.5rem; border-radius: 8px; text-decoration: none; }
        .ag-btn-primary { background: #2b5cff; color: #fff; }
        .ag-btn-secondary { background: #eef1f6; color: #1a1a1a; }
      </style>
    </head>
    <body>
      <main>
        <h1>Sign in to Acme</h1>
        <!--AUTH_GATEWAY_SELECTOR-->
      </main>
    </body>
    </html>
```

The chart renders that into a ConfigMap, mounts it read-only at
`/etc/auth-gateway/selector.html`, sets `SELECTOR_HTML_FILE`, and puts a
`checksum/selector` annotation on the pod template so editing the shell rolls the
pods (the file is only read at startup, so nothing would pick it up otherwise).
Left empty, no ConfigMap or volume is rendered at all and the built-in page is
served.

## Lossless proxying (wss / SSE / long-polling / big headers)

The gateway is tuned so streaming and upgraded connections are piped reliably:

- Uses `httputil.ReverseProxy`, which **natively hijacks `Upgrade` connections**
  (WebSocket/`wss`) and copies bytes bidirectionally — no websocket library.
- `FlushInterval: -1` — every write is flushed immediately (SSE/streaming).
- `ResponseHeaderTimeout: 0` and `DisableCompression: true` — long-polling safe.
- **No** `ReadTimeout`/`WriteTimeout`/`IdleTimeout` on the server — these would
  sever long-lived connections. Only `ReadHeaderTimeout` is set (slow-loris guard).
- `MaxHeaderBytes: 1<<20` — room for large injected auth headers
  (e.g. `X-Forwarded-Access-Token`).
- `Host` header is preserved (oauth2-proxy redirects depend on it), and
  `X-Forwarded-*` is appended to what the upstream ingress sent.

A test (`TestWebSocketUpgradeProxied`) drives a real 101-upgrade + byte-echo
through the gateway to prove the piping path end-to-end.

## Build / run

```sh
go test ./...
go build -o auth-gateway .

BACKEND_PRIMARY=http://localhost:4180 BACKEND_SECONDARY=http://localhost:4181 ./auth-gateway
```

Docker (static binary → distroless):

```sh
docker build -t auth-gateway:latest .
```

CI is GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)): a
single Docker build whose `runtime` stage chains off a `test` stage, so `go test`
runs inside the build. On `main` the tested image is pushed to
`ghcr.io/<owner>/auth-gateway:<sha>`; PRs build + test only (no push).

## Deploy (Helm)

A Helm chart lives in [`charts/auth-gateway/`](charts/auth-gateway/). It is
deliberately small and opinionated — it renders two objects, or three with a
custom selector page:

- a **Deployment** (`replicaCount` 2 by default, tiny resources, `/healthz`
  liveness + readiness probes), and
- a **Service** (`ClusterIP`, `:80 → targetPort http` / container `:8080`), plus
- a **ConfigMap**, only when `config.selectorHtml` is set (see
  [Custom selector page](#custom-selector-page)).

```sh
helm install auth-gateway ./charts/auth-gateway \
  --set image.repository=ghcr.io/<owner>/auth-gateway \
  --set image.tag=<sha> \
  --set config.backendPrimary=http://oauth2-proxy-public \
  --set config.backendSecondary=http://oauth2-proxy-private
```

### How it works

- **Config is passed as env vars.** Everything under `config.*` in
  [`values.yaml`](charts/auth-gateway/values.yaml) is rendered into the
  container's `env` (`BACKEND_PRIMARY`, `BACKEND_SECONDARY`, `LISTEN_ADDR`,
  `COOKIE_NAME`, `COOKIE_TEMP_MAX_AGE`, `AUTH_PATH_PREFIXES`,
  `AUTH_CALLBACK_PATH`, `AUTH_SESSION_COOKIE`). The one exception is
  `config.selectorHtml`, which becomes a mounted ConfigMap plus
  `SELECTOR_HTML_FILE` — see [Custom selector page](#custom-selector-page).
  `backendPrimary` / `backendSecondary` are **required** — the
  chart fails to render (`helm template`/`install` errors) if they're unset, so
  a misconfigured gateway can't reach the cluster. Point them at the two
  oauth2-proxy Services.
- **`extraEnv`** is appended verbatim, so secrets flow in the normal way:

  ```yaml
  extraEnv:
    - name: SOME_TOKEN
      valueFrom:
        secretKeyRef: { name: my-secret, key: token }
  ```

- **Security is baked in, not configurable.** The pod runs as non-root with a
  read-only root filesystem, all Linux capabilities dropped, no privilege
  escalation, and the `RuntimeDefault` seccomp profile — matching the
  *restricted* Pod Security Standard. These are hardcoded in the template rather
  than exposed as values, so they can't be quietly weakened; loosening them
  means forking the chart.
- **No Ingress, by design.** auth-gateway owns the job of wiring ingresses to the
  right frontdoor itself (see below), so the chart never manages one.
- **No `imagePullSecrets`.** The image is public; a private mirror should attach
  a pull secret to the ServiceAccount at the cluster level instead.

### Knobs

See [`values.yaml`](charts/auth-gateway/values.yaml) for the full list. Beyond
`image.*` / `config.*` / `extraEnv`, the tunable ones are `replicaCount`,
`resources`, `livenessProbe` / `readinessProbe`, `service.{type,port}`,
`containerPort`, and scheduling (`nodeSelector`, `tolerations`, `affinity`).

`podAnnotations` / `podLabels` are pass-throughs onto the pod template. The
notable use is **service-mesh sidecar injection** — a mesh's admission webhook
reads e.g. `sidecar.istio.io/inject` / `linkerd.io/inject` off the pod at
creation time, and per-pod sidecar tuning is only expressible there:

```yaml
podAnnotations:
  sidecar.istio.io/inject: "true"
```

### Ingress wiring

In the chart/manifests that own your ingress:

1. Swap the backend service on both ingresses (previously the per-hostname
   oauth2-proxy services) to `auth-gateway`, and update the
   `nginx.ingress.kubernetes.io/websocket-services` annotation likewise.
   Keep both hostnames and ingress classes as-is.
2. Keep a large `proxy-buffer-size` (e.g. `252k`) for the big auth headers.
3. No changes to oauth2-proxy config are required (cookie de-collision between
   the two instances is an accepted risk).
