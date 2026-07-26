# Roadmap

Web Terminal for Kiro is a browser terminal wrapping a single kiro-cli PTY,
now at **v2**. This document supersedes the
[default shared roadmap](https://github.com/cplieger/.github/blob/main/ROADMAP.md)
for this repository.

## Current focus

- **iOS UI / UX.** Continued polish of the iOS browser experience: terminal
  rendering, keyboard handling, and touch interaction on mobile Safari.
- **WebSocket robustness.** Ongoing hardening of the PTY WebSocket stream:
  reconnection, backgrounding/foregrounding on mobile, and overall stream
  stability.

## Ongoing

- Incorporate fixes from the weekly central fuzzing and
  [gremlins](https://gremlins.dev/) mutation-testing runs.
- Track the pinned kiro-cli version via Renovate; dependency and base-image
  currency; security findings (CodeQL / Trivy / Scorecard) addressed as they
  arise.
- Bug and security response per
  [SECURITY.md](https://github.com/cplieger/.github/blob/main/SECURITY.md).
