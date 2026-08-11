# Web Terminal for Kiro

[![Image Size](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/web-terminal-kiro/badges/size.json)](https://github.com/cplieger/web-terminal-kiro/pkgs/container/web-terminal-kiro)
![Platforms](https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-blue)
![base: Debian](https://img.shields.io/badge/base-Debian-A81D33?logo=debian)
[![Test coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/web-terminal-kiro/badges/coverage.json)](https://github.com/cplieger/web-terminal-kiro/actions/workflows/coverage.yml)
[![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/web-terminal-kiro/badges/mutation.json)](https://github.com/cplieger/web-terminal-kiro/issues?q=label%3Agremlins-tracker)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13542/badge)](https://www.bestpractices.dev/projects/13542)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cplieger/web-terminal-kiro/badge)](https://scorecard.dev/viewer/?uri=github.com/cplieger/web-terminal-kiro)
[![SBOM](https://img.shields.io/badge/SBOM-SPDX-1D4ED8)](https://github.com/cplieger/web-terminal-kiro/releases)

A minimal browser terminal for the **Kiro CLI**: run `kiro-cli` in a browser tab, on your desktop or your phone.

![Web Terminal for Kiro running kiro-cli in a browser tab, with more sessions open across tabs](docs/screenshot.png)

Web Terminal for Kiro gives each browser tab its own `kiro-cli` session over a live PTY stream and renders kiro-cli's real terminal UI verbatim, the way an SSH session would, with no chat layer, history store, or translation in between.

Three things set it apart from a typical browser terminal. The screen is **real browser text, not a canvas**, so scrolling and text selection are native. It is **touch-first with multiple tabs**, as usable on a phone as on a laptop. And sessions **survive sleep and network drops**: the screen and scrollback are replayed on reconnect, so you never lose your place.

Published as a multi-arch (amd64 + arm64) container image on **GHCR** (`ghcr.io/cplieger/web-terminal-kiro`) and **Docker Hub** (`cplieger/web-terminal-kiro`).

## ⚠️ It is a remote shell

A browser tab here is an interactive shell with access to your files under `/workspace` and to kiro-cli's stored credentials. Anyone who can reach the port can use it, and Web Terminal for Kiro has **no built-in authentication**. Before exposing it beyond your own machine, do one (ideally both) of:

- put it behind an authenticating reverse proxy (Caddy forward-auth, oauth2-proxy, Authentik, …), and/or
- keep the published port on loopback or a private network.

Neither of those covers DNS rebinding: a malicious page in your own browser can point its own hostname at `127.0.0.1` (or your LAN IP) and drive even a loopback-bound terminal, because the request then arrives from your own machine with a matching `Origin`. Also set [`WT_ALLOWED_HOSTS`](#configuration-reference) to the exact hostnames you reach it by — the `Host` allowlist is the check that rejects a rebound request.

The server logs a warning at startup when it binds a non-loopback address, and another when `WT_ALLOWED_HOSTS` is unset.

### Stored scrollback

Each tab's newest 200 lines are kept in your browser's `localStorage`, so returning to a page your phone discarded does not pull every tab's history back over the wire. Worth knowing, since terminal output is not always something you want on disk:

- It is readable from that browser without reaching this server, and it outlives the tab. An entry is deleted when you close its terminal, and otherwise after seven days.
- Nothing is sent anywhere. The server neither receives nor reads these snapshots.
- Restored output is checked against the running server on the first reconnect and cleared if it came from a previous run, so a container restart never leaves last run's history on screen. If that session is already gone, the restore is discarded outright rather than shown behind a “Session ended” banner.
- On a shared or borrowed device, use a private window, which keeps no storage at all.

No permission prompt is involved — browsers ask nothing for `localStorage` — and a browser that blocks site data simply restores nothing and replays over the wire as before.

The sibling [`web-terminal-server`](https://github.com/cplieger/web-terminal-server) does the same by default but carries a `WT_PERSIST_SCROLLBACK=false` switch, because the command it runs is its operator's choice. Here the command is kiro-cli and the deployment is your own dev box, so there is no knob.

A startup failure produces exactly one `ERROR` line, `web-terminal-kiro exited with error`, carrying the remedy in its `error` field and a `stage` field naming which step failed: `work_dir` (the `/workspace` mount is absent or is not a directory), `static` (the embedded UI is unusable — a build defect), `listen` (the port could not be bound), `serve` (the HTTP server exited), or `unknown`. Key log queries and alert rules on `stage`, not on the message text: the stage values are a stable contract, the prose is not.

## Run

```yaml
# compose.yaml
services:
  web-terminal-kiro:
    image: ghcr.io/cplieger/web-terminal-kiro:latest
    container_name: web-terminal-kiro
    init: true                  # required: reaps orphaned processes, see below
    ports:
      - "9848:9848"
    volumes:
      - ./config:/config        # kiro-cli auth, tools, settings
      - ./workspace:/workspace  # your repos
    restart: unless-stopped
```

Open <http://localhost:9848>. On first launch, kiro-cli walks you through sign-in with a device-code flow: it prints a URL and a one-time code, so you open the URL in any browser (your phone works), enter the code, and you're in. Every browser tab is a fresh session.

`init: true` is required, not cosmetic. An agent session forks language servers, `git` processes and node runtimes whose own parent exits, which re-parents them onto PID 1, and the server waits only for the children it started itself. Without an init the server _is_ PID 1 and those orphans accumulate as zombies for the container's life — measured at 17,323 of them against 88 live processes before this was fixed. Docker's `init: true` runs a tiny reaper as PID 1 instead, which owns no child anyone else is waiting on. The server logs a warning at startup if it finds itself running as PID 1, so a deployment that omits this does not fail silently.

Web Terminal for Kiro runs as root so `git`, `gh`, and SSH work; don't add a `user:` line, and expect files under the mounts to be root-owned on the host.

## Configuration reference

The image ships working defaults; most setups only pick a port and a volume.

| Variable | Description | Default |
| --- | --- | --- |
| `WT_ADDR` | Listen address (`host:port`). Leave the host part empty (or use `0.0.0.0`) so the bind still covers loopback: the image's healthcheck probes `127.0.0.1` on the port taken from this value, so pinning the bind to a single non-loopback interface reports the container `unhealthy` even while it serves normally. Restrict reachability with the published port (`127.0.0.1:9848:9848`) or a reverse proxy instead. | `:9848` |
| `WT_LOG_LEVEL` | Log verbosity: `debug`, `info`, `warn`, or `error` (case-insensitive); `debug` surfaces session-status diagnostics. An unparseable value falls back to `info` with a startup warning. | `info` |
| `WT_LOG_OSC_TEXT` | Log the text of terminal notifications the server does not recognize (needs `WT_LOG_LEVEL=debug` to be visible). Off by default: any program running in the terminal can emit that text, so it may contain a token, a device code, or a tokenised URL, and logs are usually kept longer and searched more widely than terminal scrollback. Off, the log still records a per-wording fingerprint and a length, which is enough to tell that kiro-cli changed its wording and how many distinct ones appeared. Turn it on only for an active diagnostic session; it warns at startup while set. | `false` |
| `WT_WORKDIR` | Directory each terminal session starts in (must exist). | `/workspace` |
| `WT_SCROLLBACK` | Lines of history the server retains per terminal — how far back you can scroll, and what a reconnect replays. Held in memory and grown as history is produced, so a large value costs nothing until a session reaches it: to say "never truncate", set a number no session will hit. `0` keeps nothing beyond the live screen. Values between `1` and `2000` are raised to `2001` with a warning, because at or below the depth a reconnect replays in full there is nothing left to page for, so the browser falls back to holding its whole buffer — asking for less server history would cost your phone more. This is the terminal engine's own variable, shared verbatim with every app built on it. | `100000` |
| `KIRO_CLI_CHAT_ARGS` | Extra launch flags appended to every session's `kiro-cli chat` command, whitespace-separated (for example `--effort high` or `--v3`). Handy for opting into kiro-cli features ahead of the image's defaults. Flag values never reach the logs — the startup line records only a flag count. | _(unset)_ |
| `TOOL_CATALOG_REFRESH` | How often the server refreshes the tool catalog from the published artifact (Go duration). `off` or `0` disables the schedule; a manual refresh stays available via `POST /api/tools/catalog/refresh` on loopback. | `24h` |
| `TOOL_CATALOG_URL` | Where catalog refreshes fetch from. Point it at a fork or mirror to decouple from the default publisher. | the [tool-catalog](https://github.com/cplieger/tool-catalog) latest-release artifact |
| `TOOL_CATALOG_PATH` | Image-baked tool catalog used at first boot and when offline, until a successfully fetched catalog replaces it. | `/app/tool-catalog.json` |
| `APT_PACKAGES` | OS packages `apt-get install`ed at every container start, whitespace-separated (for example `"gcc python3 libc6-dev"`). apt state lives in the ephemeral container layer, not `/config`, so it is re-applied on each start. Plain package names only, checked twice. A token that is not shaped like a bare Debian package name (a `pkg=version` pin, `pkg:arch`, `pkg/release`, or a trailing `-`) is skipped with a warning in the container log. A token that is shaped like one but is not an actual package in the index is skipped too: without that check, `apt-get` retries an unmatched token containing `.`, `?` or `*` as a pattern across every package name, so a typo like `python3.` would install hundreds of packages instead of failing. A pure virtual package (`awk`) is skipped as well and needs a concrete provider (`mawk`). An install failure warns without blocking startup. | _(unset)_ |
| `WT_TRUSTED_PROXIES` | Reverse-proxy CIDRs / bare IPs whose `X-Forwarded-For` the access log trusts to resolve `client_ip`. See [Behind a reverse proxy](#behind-a-reverse-proxy). | _(unset)_ |
| `WT_ALLOWED_HOSTS` | Comma-separated exact hostnames/IPs the server answers for (e.g. `localhost,192.168.1.5,webterm.example.com`); any other `Host` header is rejected. This blocks DNS rebinding, which can reach even a loopback- or LAN-bound terminal through your own browser, so set it for any long-running deployment; unset accepts every `Host` and logs a startup warning. Requests that are loopback on both ends (a loopback client address _and_ a loopback `Host`, e.g. `127.0.0.1:9848` or `localhost:9848`) are always admitted, so the healthcheck and in-container tools clients keep working; addressing the container by any other name still needs that name in the list. | _(unset)_ |
| `WT_TRUSTED_INSTALL_UIDS` | Comma-separated numeric uids that may have write access to the kiro-cli install tree under `/config/tools` without the server treating the install as compromised. Before installing, the server checks who can write each directory on the way to that tree and refuses when another identity can, because what lands there is later run as root. Unset (the default) makes no exception, and that is the right setting for almost every deployment: the full check applies. Set it only when the check refuses a volume you know is safe — a shared mount whose permissions grant an account you control. Each uid you list is an assertion that the account is already at least as privileged as this server, so its write access gains it nothing; listing an unprivileged account hands that account a way in instead, and defeats the check. An entry that is not a whole number above `0` is skipped with a warning that names the variable and how many entries were dropped, never their content. Carries the `WT_` family prefix like the rest of this server's settings because it is not specific to this app: every app that installs kiro-cli the same way answers the same question. | _(unset)_ |

- **Port:** `9848` (HTTP + WebSocket).
- **Volumes:** `/config` persists kiro-cli auth/tokens, installed tools, settings, and `~/.ssh` + git config; `/workspace` is your repositories / working directory.
- **Health:** the image's healthcheck reports healthy only once the server is up **and** kiro-cli is installed and runnable, so a failed first-boot install shows as `unhealthy` in `docker ps` instead of a terminal that silently errors.

kiro-cli itself is pinned and downloaded on first boot (it is not redistributed inside the image); newer versions arrive by pulling a newer image tag. The download runs after the server starts listening, so the web UI and `/api/health` answer immediately while it happens: new terminals report `503 {"reason":"kiro-cli installing"}` until the install finishes, and the reason says which stage it is at if something goes wrong. Each version installs into its own directory under `/config/tools/kiro-cli-versions/`, and the previous one is kept so a bad upgrade has something to fall back to.

If an install fails for good (no network on first boot, a full volume), the container stays up and repairable: fix or clear `/config/tools/kiro-cli-versions` inside the container, then either restart it or run `curl -X POST localhost:9848/api/kiro-cli/rescan` from inside to make the repair take effect without a restart. That endpoint is loopback-only, like the tools API.

### kiro-cli settings and MCP servers

Everything kiro-cli stores lives under `/config` and survives container recreation, so your sign-in, settings, and installed tools stick around. To add [MCP](https://modelcontextprotocol.io) servers, edit kiro-cli's own config on the volume at `/config/home/.kiro/settings/mcp.json`, or run `docker exec -it web-terminal-kiro kiro-cli mcp add --scope global <name> ...`. Use global scope (the per-workspace default only applies under `/workspace`) so the server loads in every session, then open a new tab, since kiro-cli reads its MCP config at session start.

### Behind a reverse proxy

Web Terminal for Kiro has no built-in authentication, so the cleanest way to expose it is to let a reverse proxy terminate TLS and require a login: HTTP Basic auth at minimum, forward auth (Authentik, oauth2-proxy, Caddy forward-auth) for real single sign-on. The proxy needs no special handling beyond passing WebSocket upgrades through, which mainstream proxies do by default. Pair it with a published port bound to loopback (`127.0.0.1:9848:9848`) so the only route in is through the proxy.

Behind a proxy, also set `WT_TRUSTED_PROXIES` to the proxy's address(es), a comma-separated list of CIDRs or bare IPs (e.g. `WT_TRUSTED_PROXIES=10.0.0.0/8,192.0.2.10`); the access log then resolves the real client from a trusted `X-Forwarded-For` instead of logging the proxy as the peer. Unset (the default), the log records the direct socket peer and ignores `X-Forwarded-For`, so the logged IP cannot be spoofed; that is the right choice when the terminal is directly exposed. Only a request whose socket peer is inside the set has its `X-Forwarded-For` trusted, and a malformed entry is logged and skipped rather than aborting startup.

One thing to configure on the proxy: the terminal WebSocket URL carries the session id as a query parameter (`/ws?session=<id>`), and that id is a capability token — anything that can reach the port and replay it attaches to that live session, and sessions have no idle timeout, so it stays valid until the tab is closed or the container restarts. This server never logs it (the access log records the request path only, and the `/api/sessions/` subtree is logged as its route template), but a proxy in front usually logs the full request URI by default (Caddy's `uri` field, nginx's `$request`). Drop or redact the query string for `/ws` in the proxy's access log before shipping it anywhere.

## Features

Everything below works on a phone as well as a desktop.

**A faithful terminal**, powered by [web-terminal-engine](https://github.com/cplieger/web-terminal-engine):

- Full 16 / 256 / 24-bit truecolor and every text attribute (bold, italic, underline, reverse, strikethrough, …), box-drawing, and wide CJK characters.
- Mouse support and clickable **OSC 8 hyperlinks** (bare URLs are auto-linked too).
- Desktop **notifications** and **progress** indicators (OSC 9 / OSC 9;4).
- Full-screen apps (`vim`, `htop`, `less`, `man`) run on the alternate screen, with your scrollback restored on exit.
- Bracketed paste, selectable cursor styles, the Kitty keyboard protocol, and clipboard writes from CLI apps (OSC 52).

**Made for touch**, via the [web-terminal-ui](https://github.com/cplieger/web-terminal-ui) front end:

- **Multiple tabs**: open, close, drag to reorder, plus a swipeable mobile tab switcher.
- An on-screen **key toolbar** (Tab, Esc, arrows, Enter, and a sticky-Ctrl modifier) for keys a phone keyboard lacks.
- Native **text selection**, copy/paste, and a **long-press / right-click context menu**.
- **Predictive echo** so typing feels instant over slow links, tap-to-focus, and a scroll-to-bottom control with auto-follow.
- **Per-tab status dots**: see at a glance which session is working, done, or waiting for input.
- IME/composition support, keyboard accessibility, theming, and reduced-motion support.

**Resilient by default:**

- Auto-reconnect with screen + scrollback replay after laptop sleep, network drops, or proxy timeouts.
- Input sent during an outage is re-delivered on reconnect (no lost or duplicated output), and a restarted server is detected and cleanly resynced.
- **Fast recovery when your phone drops the page.** iOS reclaims a backgrounded tab's memory routinely, which re-runs the page when you come back. The sessions themselves are untouched — they live on the server — but the browser used to return holding nothing and pull every tab's history back over the wire, which you saw as the scrollback filling in line by line. Each tab's recent output is now kept on the device, so returning asks only for what was printed while you were away. See [Stored scrollback](#stored-scrollback) for what that keeps and where.

## Works with the whole kiro-cli TUI

Because Web Terminal for Kiro drives kiro-cli's own terminal UI directly, every kiro-cli feature works with no extra setup, including queue steering (`Ctrl+S`), goal-driven runs (`/goal`), and turn rewind (`/rewind`). On a phone, the shortcuts that need modifier keys are reachable through the on-screen toolbar (sticky-Ctrl, then the letter).

## Tools

Web Terminal for Kiro ships kiro-cli, `git`, and base utilities. Everything else is
declared in `/config/tools/tools.json`, a small manifest the built-in tools engine
(the [`toolbelt`](https://github.com/cplieger/toolbelt) library) reconciles against
on boot: enabled entries are installed into that same `/config/tools/` tree
(persisting across
restarts), disabled entries wait as templates, removed installs are cleaned up.
There is no management UI; you edit the manifest and restart, or drive the
loopback API from inside a session.

**Upgrading a volume from an image that kept the manifest in `/config`?** The
manifest and its state moved into `/config/tools/`, beside the tools they describe,
and the files at the old paths (`/config/tools.json`, `/config/tools-state.json`,
`/config/tool-catalog.cached.json`) are ignored rather than migrated. A fresh
manifest is seeded at the new path, so re-apply your enabled tools there, plus any
tool you had added by name, which the seeded file does not carry at all. Tools from
the old install keep working on `PATH`, but the engine no longer tracks them: to
hand one back to it, declare it in the new manifest and delete its entry from
`/config/tools/bin` so the engine reinstalls and records it. The container logs a
warning at every start while the old files are still there; deleting them stops it.

**Enable a bundled template.** First boot seeds language-server templates plus
the GitHub CLI, all disabled. Flip the ones you want and restart:

```jsonc
{
  "version": 2,
  "tools": {
    "gopls":                      { "disabled": true },   // Go: set false to install (pulls the Go toolchain)
    "typescript-language-server": { "disabled": false },  // TypeScript LSP: enabled, installs on restart (pulls node)
    "pyright":                    { "disabled": true },   // Python LSP
    "rust-analyzer":              { "disabled": true },   // Rust LSP
    "gh":                         { "disabled": true }    // GitHub CLI
  }
}
```

Enabled language servers land on `PATH`, where kiro-cli's [code
intelligence](https://kiro.dev/docs/cli/code-intelligence/) picks them up:
run `/code init` once per workspace inside a session; `/code status` shows
which servers it found.

Install knowledge (download URLs, checksums, dependencies) comes from a
catalog of ~700 tools compiled from the mise and aqua registries by
[tool-catalog](https://github.com/cplieger/tool-catalog); a template carries
no install commands, so it never goes stale. The server refreshes the catalog
at boot and every `TOOL_CATALOG_REFRESH`, keeps the last good catalog on any
failure, and uses an image-baked copy for offline first boots.
`GET localhost:9848/api/tools/catalog` reports what is loaded and where it
came from; `POST .../api/tools/catalog/refresh` forces a refresh (both
loopback-only). Dependencies auto-adopt: enabling `typescript-language-server`
installs `node` and the `typescript` package with it, no extra manifest
entries needed. While tools install, the web UI and health endpoint stay
reachable and only new-session creation waits, so the first session sees the
finished PATH. If provisioning fails, sessions are not blocked: creation is
allowed anyway, the failure is logged, and `/api/health` reports
`"tools": "degraded"`.

That `tools` field is informational (it never affects the container's
healthy/unhealthy verdict) and it is **live**, not just a boot result:
`"syncing"` while the boot pass runs, then `"ok"` or `"degraded"` after each
tool install or reconcile the server runs — including the ones you trigger
through the loopback tools API. So repairing a failed install from inside the
container (`POST localhost:9848/api/tools/...`) flips the field back to
`"ok"` without restarting anything. Two things it deliberately does not
report: a failed **catalog refresh** (the last good catalog keeps serving, so
that failure changes nothing about your installed tools) and a failed
**update**, **uninstall** or **disable** (your installed versions stay on
`PATH`). kiro-cli's own readiness is a separate field — see the `status` and
`reason` keys.

**`tools_missing` is the second, independent tools question.** `tools` tells you
whether the last install or reconcile succeeded (and whether the boot pass is
still running); `tools_missing` tells you whether the tree is actually
_converged_ — how many enabled entries are still not installed. They disagree on
purpose: if a boot reconcile leaves two tools missing and you repair one through
the loopback API, `tools` becomes `"ok"` (that repair genuinely did succeed)
while `tools_missing` stays `1`. Read `tools` for "did the last thing I asked for
work", and `tools_missing` for "is everything the manifest asks for present".
Disabled entries are templates and never counted; an entry still installing does
count, because it is not on `PATH` yet. The key is **absent** when the count is
not known — no tools engine wired, or the first count has not landed — so a `0`
always means converged and never "nobody has looked".

**Add more tools by name.** Any catalog name works as a bare entry; the engine
fills in the rest:

```jsonc
"tools": {
  "ripgrep": {},                            // installed at the latest version, then auto-updated
  "shellcheck": { "pin": true },            // pinned: installed once, never auto-bumped
  "jq-custom": {                            // full manual escape hatch
    "source": "manual",
    "version": "1.8.1",
    "install": "curl -fsSL -o ${BIN}/jq https://github.com/jqlang/jq/releases/download/jq-${VERSION}/jq-linux-${ARCH_AMD64_OR_ARM64} && chmod 755 ${BIN}/jq"
  }
}
```

Sources cover `aqua:owner/repo` binaries (checksum-verified when upstream
publishes checksums), `npm:`, `pip:`, `cargo:`, `go:` modules, and `manual`
shell commands with `${VERSION}`/`${BIN}`/`${ARCH_*}` placeholders.

**From inside a session** (agents included), the same engine answers on
loopback only:

```bash
curl -s localhost:9848/api/tools | jq '.tools[] | {name, installed}'
curl -s -X PATCH localhost:9848/api/tools/gopls -d '{"disabled": false}'   # enable + install
curl -s -X POST  localhost:9848/api/tools -d '{"name": "ripgrep"}'         # add from the catalog
```

OS packages are not manifest entries: set `APT_PACKAGES="gcc python3 ..."` on
the container and the entrypoint installs them at each start.

## Related projects

- [vibekit](https://github.com/cplieger/vibekit): the sister app, a chat-first Kiro web UI (chat history, MCP, agent tools) instead of a raw terminal.
- [web-terminal-engine](https://github.com/cplieger/web-terminal-engine): the terminal engine (Go PTY/VT + TypeScript renderer) behind this app.
- [web-terminal-ui](https://github.com/cplieger/web-terminal-ui): the touch-first browser UI.
- [web-terminal-server](https://github.com/cplieger/web-terminal-server): a generic browser terminal for any command, built on the same engine.
- [pinstall](https://github.com/cplieger/pinstall): the digest-pinned installer this app uses to download, verify and activate kiro-cli at runtime.

## Contributing

Build, test, and layout notes are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

MPL-2.0. See [LICENSE](LICENSE).
