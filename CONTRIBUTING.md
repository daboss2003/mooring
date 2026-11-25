# Contributing to Mooring

Thanks for your interest in Mooring. Its **paramount requirement is safety** — hosting Mooring
must never become the thing that gets a server hacked — so the contribution process is built around
that. Please read this before opening a PR.

## Ground rules

- **One reconciler, many front-ends.** The dashboard, the CLI, and SSH all produce
  the *same* typed reconcile request and pass the *same* validation chokepoints. A new feature is a
  new front *door*, never a new trust *path* — it must not add a way for bytes to reach
  `docker compose`, the edge, or a secret without going through the existing gates.
- **Fail closed.** Any precondition violation must refuse the operation, never silently degrade.
- **Secrets are by reference.** Never log, serialize, or surface a secret value; never put a value in
  a definition file, an env literal that the lint would catch, a process argv, or an error string.
- **All external input is hostile** — config, compose, app responses, git content, alert identifiers.
  Validate with allowlists, confine paths, output-encode anything rendered.

## Blast-radius modules (extra scrutiny)

Any change touching one of these re-triggers the relevant security gates (see
[docs/security.md](./docs/security.md)) **before merge**, and needs an explicit security review:

- the exec wrapper / `docker compose` invocation
- the SSRF-safe outbound client and the pinned dialer
- the IP-allowlist / XFF / trusted-proxy derivation
- the crypto / secret store
- the setup-script sandbox
- ACME / cert handling
- the edge config renderer
- the git invocation hardening
- `mooring config edit` (the privileged write of the root-of-trust file)

## Required checks

CI enforces the static-assurance gate (see [docs/security.md](./docs/security.md)):

- `govulncheck`, `gosec`, `staticcheck`, `go vet` — clean.
- Custom lint rules (must stay green): no `exec.Command` with request/DB/app-derived args outside the
  compose validator; no `sh -c`; no un-confined path from external input; no `text/template` /
  `template.HTML` on app-controlled content; no secret type whose `String()`/`MarshalJSON` isn't
  redacted; no outbound client that isn't the host-pinned SSRF-safe one.
- `gitleaks` over full history; `trivy`/`grype` with zero Critical/High that has a fix.
- Tests, including the abuse-test suite (allowlist/XFF bypass, SSRF-to-metadata, the edge-editor
  abuse tests, the git checkout-time RCE tests, the setup-sandbox escape test).

## Workflow

1. Open an issue describing the change (especially if it touches a blast-radius module).
2. Branch, implement, add tests (an abuse test for anything security-relevant).
3. Run the static-assurance gate locally.
4. Open a PR; expect a security review for blast-radius changes.

## Reporting a vulnerability

Please **do not** open a public issue for a security vulnerability. Report it privately to the
maintainer at samsonoluwafemi203@gmail.com so a fix can ship before disclosure.
