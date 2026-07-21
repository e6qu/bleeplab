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

Every GitHub Actions job must declare a literal `timeout-minutes` value from 1
through 15. `make check-workflow-timeouts` enforces the policy across every
workflow and rejects workflow files in which no jobs were recognized.

## Remote state is authoritative

Before editing, fetch the current `origin/main` and the remote head of the open
pull request being continued. Compare those commits with the local branch and
dirty worktree deliberately. Never assume that a local checkout is current, and
never discard uncommitted work while reconciling it with remote state. Rebase a
task branch onto the freshly fetched `origin/main` before pushing it.

## Announce external dependencies

Tell the user before introducing any new external library, image, service, or
hosted dependency. State what it would do and why the existing project code and
dependencies are insufficient, then wait for direction. Do not hide an external
dependency inside deployment configuration or generated output.
