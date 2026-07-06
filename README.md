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
| No/unknown cookie + `GET` with `Accept: text/html` | `200` embedded selector page (two buttons) |
| No/unknown cookie + anything else | `401` with small JSON body |
| `GET /.auth/select?mode=<primary\|secondary>&rd=<path>` | Set cookie, `302` to `rd` (open-redirect–guarded; defaults to `/`) |
| `GET /healthz` | `200` (liveness/readiness) |

There is **no mode-switch endpoint** by design — a stale oauth2-proxy session
cookie after a manual switch just re-triggers login.

## Configuration (env vars)

| Var | Default | Notes |
| --- | --- | --- |
| `BACKEND_PRIMARY` | *(required)* | Full URL, e.g. `http://oauth2-proxy-primary` |
| `BACKEND_SECONDARY` | *(required)* | Full URL, e.g. `http://oauth2-proxy-secondary` |
| `LISTEN_ADDR` | `:8080` | |
| `COOKIE_NAME` | `auth_mode` | |

The selector button labels live in [`selector.html`](selector.html) — edit them to
match your two providers.

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
deliberately small and opinionated — it renders just two objects:

- a **Deployment** (`replicaCount` 2 by default, tiny resources, `/healthz`
  liveness + readiness probes), and
- a **Service** (`ClusterIP`, `:80 → targetPort http` / container `:8080`).

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
  `COOKIE_NAME`). `backendPrimary` / `backendSecondary` are **required** — the
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
