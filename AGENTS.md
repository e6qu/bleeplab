# Agent Guidelines

> `CLAUDE.md` is a symlink to this file. Edit `AGENTS.md`.

## Complete, real implementations

Do not add stubs, fake responses, mocks of GitLab or cloud behavior, synthetic
state, silent fallbacks, or skip-if-absent tests. Bleeplab implements real
GitLab-compatible and OpenID Connect contracts; tests must exercise those real
paths. If a required dependency is unavailable, fail clearly.

## Boy Scout rule

Never dismiss an observed failure as unrelated, pre-existing, or outside the
current change. Application behavior, protocol fidelity, identity, storage,
containers, CI, documentation, deployment coordinates, and operational hygiene
are one product. Investigate and fix every defect encountered. If a real
external dependency prevents an immediate repair, record the concrete evidence
in the repository's existing tracking mechanism and tell the user. Never hide a
failure by narrowing validation, weakening a guard, or adding a fallback.

## Pull requests

Create at most one open pull request. Rebase its branch on `origin/main` before
pushing. Never merge pull requests; the user handles all merges. Never bypass a
commit or push hook.
