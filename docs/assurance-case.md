# Security assurance case: Web Terminal for Kiro

This extends the shared
[default assurance case](https://github.com/cplieger/.github/blob/main/assurance-case.md)
with the threat model specific to `web-terminal-kiro`. Read that first. Web
Terminal for Kiro is at **v2**; the [roadmap](../ROADMAP.md) lists ongoing
work.

## What this is

A minimal browser terminal: a Go web server that streams a single kiro-cli PTY
over a WebSocket to a browser renderer. As a terminal to an interactive shell/
agent, its **intended capability is full command execution**, so, like vibekit,
the security model is about reaching it, not about sandboxing what it can do.

## Security model

Web Terminal for Kiro is a **trusted-operator tool behind a network/auth boundary**. In a
self-hosted deployment it is reachable only on the internal network (behind the
reverse proxy).
A reachable, authenticated session is, by design, a shell; that is the product.
The control is "only the operator can reach Web Terminal for Kiro."

## Threats and mitigations

| Threat | Mitigation | Evidence |
| --- | --- | --- |
| Unauthorised access to the PTY (i.e. to a shell) | network/auth boundary: keep the port loopback/private and require login at an authenticating reverse proxy (the server ships no auth) | `main.go` bind warning, README security warning |
| WebSocket hijacking / malformed frames | origin and Host checks before the WS upgrade; hardened wire decoding (the shared `web-terminal-engine` wire protocol) | middleware, engine decoder tests |
| Malformed terminal/wire input crashing the server | property + fuzz suite on the PTY/wire surface, maintained in `web-terminal-engine` | engine fuzz targets, weekly fuzz |
| Stale/empty embedded UI shipped | CI image smoke test starts the container and asserts it serves | image smoke test (CI docker job) |

## Residual risks (stated plainly)

- Active work continues on mobile UI and WebSocket robustness (roadmap).
- An authenticated session is a shell by design; network/auth isolation is the
  control and is a deployment responsibility. Do not expose Web Terminal for Kiro to untrusted
  networks.

Report vulnerabilities privately per
[SECURITY.md](https://github.com/cplieger/.github/blob/main/SECURITY.md).
