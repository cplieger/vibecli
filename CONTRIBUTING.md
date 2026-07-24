# Contributing to Web Terminal for Kiro

Web Terminal for Kiro is a single Go binary that serves a static web UI and brokers one
`kiro-cli chat` PTY per session (each browser tab is a session with its own
`/ws?session=` connection), via `terminal.NewSessionManager`. There is no chat-history store
and no ACP layer; the browser drives kiro-cli's own TUI through a terminal
stream. This guide covers the things the codebase won't tell you at a glance.

## Architecture at a glance

- `main.go`, `routes.go`: server entry point and route wiring (both at repo
  root, `package main`). `main.go` embeds the web UI with `//go:embed static`
  and assembles the middleware stack in `buildHandler` on top of `webhttp`
  (access logging, panic recovery, security headers, cross-origin protection).
- `static-src/`: TypeScript + CSS sources, compiled into `static/`.
- Tool provisioning is the external
  [`cplieger/toolbelt`](https://github.com/cplieger/toolbelt) library, consumed
  headless: `startTools` (main.go) reconciles `/config/tools.json` in the
  background after the listener binds, session creation waits on that first
  pass (503 "tools installing"), and `/api/tools` is the library's REST
  projection admitted for loopback socket peers only (`loopbackOnly` in
  routes.go). OS packages ride the `APT_PACKAGES` env in `entrypoint.sh`,
  not the manifest.

Web Terminal for Kiro is a thin consumer of the first-party web-terminal libraries: the
terminal engine `web-terminal-engine` (`github.com/cplieger/web-terminal-engine/v3`
server-side, `@cplieger/web-terminal-engine` client-side) and the reference UI
`@cplieger/web-terminal-ui`. Most of "what the terminal does" lives in those
repos, not here. The Go server and TS client share a binary wire protocol, not
code; a wire-format change is a `web-terminal-engine` concern and lands in that
repo, not this one.

Observability is slog-only: webhttp's `Logging` middleware (wired in
`buildHandler` with `WithClientIP()`) emits a structured access-log line per
request (method/path/status/duration_ms/request_id/client_ip), except on the
long-lived streams (`/ws`, `/api/sessions/events`) and the `/api/health`
probe, which are deliberately skipped (the request id is still minted and
echoed there). The session-token-bearing `/api/sessions/{id}` paths ARE
logged, with the recorded path rewritten to the token-free route template
(`/api/sessions/{id}`, `/api/sessions/{id}/title`) via webhttp's
`WithPathFunc`, so their telemetry survives without a live token ever
reaching log-read consumers. There is no
Prometheus `/metrics` endpoint. Log timestamps are UTC (`slogx`'s `UTCTime`
`ReplaceAttr` forces the record time to UTC), so the image needs no `TZ` and
embeds no `time/tzdata`.

## Generated assets (read before building)

`static/*.js` and `static/style.css` are build artifacts and are
git-ignored; the sources of truth are under `static-src/`. Regenerate them
before `go run .` or `go build .`, otherwise `go:embed` captures a stale or
empty tree:

```sh
go generate ./...   # runs: tsc --project static-src/tsconfig.json -> static/app.js
```

`go generate` runs the TypeScript 7 native compiler `tsc` from `static-src`'s
`@typescript/native` devDependency, so run `cd static-src && npm install` first
(the `//go:generate` directive invokes `static-src/node_modules/.bin/tsc`).
Web Terminal for Kiro ships no local CSS: the bundle is assembled from the vendored
`@cplieger/web-terminal-ui` package. At image-build time the Dockerfile
concatenates the files listed in that package's `css/MANIFEST` into
`static/style.css`. For a local `go run .`, install the package first
(`cd static-src && npm install`), then reproduce the bundle from the repo
root with the canonical script (skips blanks + `#`-comments, handles a
missing trailing newline, the same recipe the Dockerfile and
`scripts/dev-build.sh` run):

```sh
sh scripts/css-bundle.sh static-src/node_modules/@cplieger/web-terminal-ui/css static/style.css
```

## Local dev setup

Run the server directly once assets exist:

```sh
go generate ./...
KWEB_WORK_DIR=/path/to/workdir go run .
```

`KWEB_WORK_DIR` must point at an existing directory (the server exits if it is
missing); `KWEB_ADDR` defaults to `:9848` and `KIRO_CLI_PATH` defaults to
`kiro-cli`. The terminal only works if a real `kiro-cli` binary is reachable;
in production `entrypoint.sh` downloads a Renovate-pinned version on first boot.

`/api/health` reports readiness. Under a bare `go run` it reflects only that the
HTTP listener is up: the kiro-cli readiness gate is env-gated on
`KIRO_CLI_READY_MARKER`, which is left unset locally, and the tools engine is
disabled when the config dir is missing (`KWEB_CONFIG_DIR`, default `/config`);
a warn is logged and the `/api/tools` routes are simply absent. In the image the entrypoint
writes that marker only after verifying `kiro-cli --version` matches the pin, so
`/api/health` returns `503 {"reason":"kiro-cli unavailable"}` until kiro-cli is
installed and runnable (the container healthcheck reflects that).

Frontend tooling lives in `static-src/`; run npm commands from there:

```sh
cd static-src
npm install
```

## Running checks

Go (from the repo root):

```sh
go test ./...           # unit + fuzz tests, co-located as *_test.go
golangci-lint run       # lint (config in .golangci.yaml)
golangci-lint fmt       # apply gofumpt + gci formatting
```

`golangci-lint run` reports unformatted files as issues, so the formatters
(`gofumpt` with extra rules, `gci`) are enforced, not just available.

Frontend (from `static-src/`):

```sh
npm run typecheck       # tsc -project tsconfig.json
npm run test            # vitest --run (node + happy-dom; *.test.ts)
npm run lint:eslint     # eslint .
npm run lint:prettier   # prettier --check .
npm run lint:knip       # unused-export / dependency check
```

Vitest defaults to the `node` environment; add `// @vitest-environment
happy-dom` at the top of a test file that needs `window`/`document`. Tests must
assert at least once (`expect.requireAssertions`) and `.only` is forbidden.

## Conventions and gotchas

- **Always use webhttp's response helpers.** Never hand-craft JSON error
  bodies (`http.Error` with a JSON string, `w.Write([]byte(...))`). Every
  app-owned ERROR response (4xx/5xx) is `webhttp.WriteError` with an empty
  code (the standard `{error, request_id}` envelope); the two 403 gates and
  the tools-installing 503 all speak it. `webhttp.WriteJSON` /
  `webhttp.WriteJSONStatus` / `webhttp.Ok` are for non-error documents only
  (`/api/health`'s `{status, reason, tools}` is a health-probe contract, not
  an error envelope). Routes mounted by the pinned engine answer in the
  engine's own plain-text dialect; that is an engine-repo concern, not a
  reason to fork the app-owned shape.
- **Client-local vs library code.** `static-src/app.ts` is the only client
  source Web Terminal for Kiro owns: a
  `createTerminal(root, { features: presetAgentTabbed(), theme })` call plus a
  small bootstrap-failure handler. The theme is Web Terminal for Kiro's purple
  token set, and `presetAgentTabbed` pulls in tabs, the activity monitor,
  touch toolbar, context menu, clipboard, scroll-to-bottom, predictive echo,
  connection banner, and animations. The handler (`showFatal`) surfaces a
  missing `#terminal` root or a `createTerminal` throw on the pre-JS
  `#loading` overlay as a `role="alertdialog"` overlay with a focused Reload
  button. The input model,
  IME/composition, predictive echo, viewport, mobile key toolbar, and status
  banner, plus the render / keyboard / scroll / connection layers, all live in
  `@cplieger/web-terminal-ui` (built on `@cplieger/web-terminal-engine`);
  don't reimplement them here.
- **CI workflows are synced, not editable.** Files under `.github/workflows/`
  carry a "Synced from cplieger/ci — DO NOT EDIT" header; the pipeline is
  centralised in `cplieger/ci`. Change behaviour there, not here.
- **kiro-cli install model.** `entrypoint.sh` pins `KIRO_CLI_VERSION` +
  `KIRO_CLI_SHA256` (Renovate-managed). Don't switch to `latest/` URLs, bake
  the binary into the image, or re-enable in-binary auto-update; each breaks
  the pinned-sha / image-tag reproducibility story.
- **The image runs as root by design.** OpenSSH resolves `~` from the passwd
  entry, not `$HOME`, and the Dockerfile wires that entry for root
  (`/config/home`). Don't add a `user:` line to `compose.yaml` or the README
  run example: a non-root UID has no passwd entry, so `git`/`gh` over SSH
  fail with `No user exists for uid …`. Files under `/config` and `/workspace`
  are root-owned on the host as a result.

## Commits and PRs

Branch from `main`, keep changes focused, and open a PR. Commits follow
[Conventional Commits](https://www.conventionalcommits.org/); git-cliff parses
the type to build release notes and pick the version bump (`feat:`, `fix:`,
`sec:`, `refactor:`/`perf:` ship; `chore`/`ci`/`docs`/`style`/`test` don't). See
`cliff.toml` for the full mapping.

## Conduct & security

By participating you agree to the
[Code of Conduct](https://github.com/cplieger/.github/blob/main/CODE_OF_CONDUCT.md).
Report security issues through the
[security policy](https://github.com/cplieger/.github/blob/main/SECURITY.md),
never in a public issue.
