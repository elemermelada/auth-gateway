# Work done — catch a wrong IdP choice (almost) instantly

Issue: [#13](https://github.com/elemermelada/auth-gateway/issues/13). Branch
`feat/instant-wrong-idp-catch`. Plan followed as written (`plan.md`).

## What shipped

Mechanism 4, two stateless rules over the existing temp cookie. Both fire only on
top-level navigations carrying an unproven (`:tmp`) cookie.

| Piece | Where |
|---|---|
| Cookie value `<mode>:tmp:<starts>` | `cookieMode`, `tempCookieValue`, `handleSelect` |
| Rule 1 — cross-site / `none` return resets | `resetOnReturn`, called from `newHandler` before routing |
| Rule 2 — start counter, rewrite at the limit | `countStart` + `isExternalRedirect` + `authCfg.isStartPath`, in `ModifyResponse` |
| Shared 302-to-reset rewrite | `redirectToReset` (extracted from `rewriteAuthError`) |
| One log line per reset | `logReset`, called from all four reset paths |
| `COOKIE_TEMP_MAX_STARTS`, `AUTH_START_PATH` | `main()`, `.env.example`, chart values + deployment, README env table |
| Chart version | `0.4.0` → `0.5.0` (once, per the branch convention) |
| README | mechanism 4 section, log-line examples, cookie-format paragraph, env table, Helm env list |
| Tests | 15 new tests in `main_test.go` + `TestCookieMode` extended |

## Decisions taken while implementing

1. **Legacy cookie values still parse.** `<mode>:tmp` (no counter) reads as zero
   starts instead of being rejected, so logins in flight survive the rollout. A
   counter that isn't a non-negative integer invalidates the whole cookie —
   otherwise a hand-edited cookie buys unlimited trips to the IdP.
2. **A counted start re-issues the cookie with a fresh `COOKIE_TEMP_MAX_AGE`.**
   The window is meant to cover one login attempt, and a counted start is a new
   attempt beginning. Side effect: repeated starts under a limit > 1 extend the
   temp window.
3. **`isStartPath` excludes the callback** even in the default "any auth path"
   mode, so a callback that happens to 302 off-host can never consume the budget.
4. **`rule=stale` log line.** The plan asked for a log on "expired-tmp selector
   hits". A genuinely expired cookie is invisible to the gateway (the browser
   stops sending it), so the closest observable event is logged instead: a cookie
   present but unroutable (hand-edited value, or a backend dropped from
   `BACKENDS`) reaching `handleNoMode`.
5. **Reset always uses `rd=/`,** per plan decision 4 (plain selector, no
   highlight), matching the existing mechanism-3 rewrite rather than preserving
   the path the user was on.
6. **`AUTH_START_PATH` is rendered by the chart only when non-empty** (`{{- with
   }}`), so the default stays "any auth path" rather than being pinned by an
   empty env var.
7. Ticket text said `AUTH_START_PATH` defaults to `/oauth2/start`; the plan's
   later decision (external-host 302 by default, `AUTH_START_PATH` optional) won,
   as the plan is authoritative.

## Review round (PR #14 review, 2026-09-07)

Fixed:

1. **`countStart` had no navigation guard** — a prefetched auth path burned the
   start budget, so the real click landed as `starts=2` and reset. Now gated on
   `isNavigation`, and `isNavigation` also excludes `Sec-Purpose: prefetch`
   (prefetch/prerender is not a navigation for any of the three rewrites).
2. **`isExternalRedirect` was port-fragile** — raw `u.Host` vs `Request.Host`
   read `https://app.example.com:443/…` as an IdP handoff. Compares hostnames
   now (`hostname()` helper).
3. **`redirectToReset` leaked upstream headers** — drops the upstream
   `Set-Cookie` (oauth2-proxy's CSRF cookie for a cancelled start); it already
   set `Cache-Control: no-store`.
4. **`rule=stale` log flooding** — logged on navigations only.

Documented, not coded: the counter is unauthenticated (README claim softened,
plus the subdomain cookie-tossing angle), rule 1's false positive is remotely
triggerable, and the two-tab counter race.

Left for later: signing the cookie (HMAC) — filed as
[#15](https://github.com/elemermelada/auth-gateway/issues/15).

New tests: non-navigation/prefetch starts, legacy-client start still counted,
table-driven `isExternalRedirect`, blocked start drops upstream cookies.

## Not done

- **No compile / vet / test run.** No Go toolchain on this machine, and you said
  you'd run the checks. `gofmt` was likewise not run — formatting was written to
  match the file's existing style (gofmt-aligned struct fields included), but it
  hasn't been verified by the tool.
- Dev verification of `Sec-Fetch-Site` on back-button history navigations (the
  plan's "verify in dev" item) — needs a browser.
- `plan.md` left untracked, as it was.
