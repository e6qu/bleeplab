# @sockerless/ui-bleeplab

Dashboard UI for [Bleeplab](../README.md), the GitLab control-plane simulator. A GitLab-style shell with pages in `src/pages/`, routed in `src/App.tsx` (React Router 7). It is read-only: it reads Bleeplab's `/internal/*` projections and public `/api/v4` surface to show projects, pipelines, jobs, and registered runners.

## Pages

- `/ui/` — overview
- `/ui/projects` — projects; `/ui/projects/:id` for detail
- `/ui/pipelines` — pipelines; `/ui/pipelines/:id` for detail
- `/ui/jobs/:id` — job detail (status, trace, artifacts)
- `/ui/runners` — registered runners

## Embedding

`make web-build` at the repository root copies this package's `dist/` to `dist/`, which the binary bundles via `//go:embed all:dist` (`ui_embed.go`) and serves at `/ui/` (default `:8929`). A `-tags noui` build skips it (`ui_noembed.go`).

## Development

- `bun run dev` — Vite dev server (`:5173`), proxying `/internal`, `/health`, and `/api` to a running Bleeplab on `:8929`.
- `bun run build` — production bundle into `dist/`.
- `bun run preview` — serve the built bundle.
- `bun run test` — vitest run (page tests in `src/__tests__/`).
- `bun run typecheck` — `tsc --noEmit`.

The package `Makefile` wraps these as `make build` / `run` / `preview` / `test` / `lint` / `clean`.

## See also

- [Bleeplab README](../README.md) — the server this UI dashboards.
- [`@bleeplab/ui-core`](core/README.md) — shared components, hooks, and tokens.
