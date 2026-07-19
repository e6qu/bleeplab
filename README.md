# bleeplab

bleeplab is a self-contained Go reimplementation of the slice of GitLab's server-side surface that a real `gitlab-runner` (docker executor) and a CI orchestrator exercise — enough for the official runner binary to register, poll for jobs, stream build logs, and upload/download artifacts against a local process exactly as it would against `gitlab.com` or a self-managed GitLab instance.

It is the **GitLab analog of [Bleephub](https://github.com/e6qu/bleephub)**, the GitHub control-plane simulator. The two are structural siblings: same object-store-backed git, same embedded SPA pattern, same "fidelity, not fakery" contract. Where Bleephub speaks GHES `/_apis/` + `/api/v3/`, Bleeplab speaks the GitLab runner API + `/api/v4/`.

**Fidelity, not fakery.** The runner authenticates and polls exactly as it does against real GitLab; Bleeplab differs only in **coordinates** — the base URL and tokens. It implements the real wire shapes the runner consumes and never special-cases [Sockerless](https://github.com/e6qu/sockerless). This follows the [Sockerless engineering guidelines](https://github.com/e6qu/sockerless/blob/main/AGENTS.md).

## Reference adaptor

bleeplab is paired with the external GitLab-compatible tool that drives it. Anything that tool does against `gitlab.com` must work against bleeplab.

| Adaptor | Version | What it proves |
|---|---|---|
| [`gitlab-runner`](https://docs.gitlab.com/runner/) (official binary, docker executor) | v18.11.3 (pinned in the [`Dockerfile`](Dockerfile)) | The runner API end-to-end — register/verify, `POST /api/v4/jobs/request` long-poll, `PATCH .../trace` log streaming, `PUT .../jobs/:id` completion, artifact upload/download. |
| [Smart-HTTP git](https://git-scm.com/docs/http-protocol) (`go-git`) | git 2.40+ | `git clone` / `git fetch` of a project repo over `http://<host>/{namespace}/{project}.git` — what the runner's git step does before a job. |
| [GitLab runner API](https://docs.gitlab.com/ee/api/runners.html) / [CI/CD YAML](https://docs.gitlab.com/ee/ci/yaml/) | current | The authoritative reference for the runner wire shapes and the `.gitlab-ci.yml` subset bleeplab models (stages, `image`, `script`/`before_script`/`after_script`, `services`, `variables`, `artifacts`, `dependencies`). |

## How it works

bleeplab is the **control plane**; the sockerless backend + cloud simulator are the **data plane**. A real `gitlab-runner` sits between them:

1. The runner registers against bleeplab (`/api/v4/runners`) and long-polls `POST /api/v4/jobs/request`.
2. A pipeline is created for a project (from its committed `.gitlab-ci.yml`); bleeplab parses the CI config ([`ciyaml.go`](ciyaml.go)) into ordered stages and per-stage jobs, and enqueues the first stage.
3. bleeplab hands a queued job to the polling runner as a GitLab-shaped `jobResponse` (image, script steps, services, variables, git info, artifact/dependency specs).
4. The runner's **docker executor** dispatches the job + helper containers through a `--docker-host` that points at a [Sockerless](https://github.com/e6qu/sockerless) backend — so the containers actually run on the cloud (Amazon Elastic Container Service (ECS), Google Cloud Run, Azure Container Apps, …) via the simulator, exactly as they would with a cloud `DOCKER_HOST` against real GitLab. This is the *runner-as-cloud-task* data plane; its [per-cloud mapping](https://github.com/e6qu/sockerless/blob/main/specs/CLOUD_RESOURCE_MAPPING.md) lives in Sockerless.
5. The job clones its repo over smart-HTTP from bleeplab's git storage, runs, streams its trace back via `PATCH .../trace`, uploads artifacts, and reports completion via `PUT .../jobs/:id`. bleeplab advances the pipeline to the next stage.

The `externalURL` coordinate (`BLEEPLAB_EXTERNAL_URL`) matters here: the `git_info.repo_url` handed to a job must be reachable **from the job/helper container**, which is a different network vantage point than the runner process — so it is a distinct coordinate from the control-plane API URL. The [Sockerless runner guide](https://github.com/e6qu/sockerless/blob/main/docs/RUNNERS.md) covers the transport and cloud-runtime constraints.

## Shauth browser sign-in

The GitLab-compatible runner API, project API, and Git smart-HTTP transports
continue to use their GitLab tokens and remain wire-compatible. For the human
dashboard and its `/internal/` operator projections, Bleeplab can additionally
use Shauth OpenID Connect. Configure the four required identity values together;
set the portal coordinate so local logout returns to the shared app catalog:

```text
BLEEPLAB_SHAUTH_ISSUER=https://auth.dev.e6qu.dev
BLEEPLAB_SHAUTH_CLIENT_ID=...
BLEEPLAB_SHAUTH_CLIENT_SECRET=...
BLEEPLAB_PUBLIC_URL=https://bleeplab.dev.e6qu.dev
BLEEPLAB_SHAUTH_POST_LOGOUT_URL=https://auth.dev.e6qu.dev/apps
```

Register `https://bleeplab.dev.e6qu.dev/auth/shauth/callback` as the Shauth
client redirect URI. Bleeplab uses discovery, authorization code + PKCE, nonce
and state checks, signed short-lived transaction/session cookies, and accepts
only Shauth `developer` or `admin` roles. The dashboard displays the signed-in
user's name, email, and avatar and exposes a local logout control. An omitted
configuration preserves the standalone simulator mode; a partial or non-HTTPS
configuration fails startup.

## What it implements

All under one binary on one port (`:8929` by default).

**Runner-facing API** (`gitlab-runner` polls these):
- `POST /api/v4/runners/verify`, `POST /api/v4/runners`, `DELETE /api/v4/runners` — register / verify / unregister.
- `POST /api/v4/jobs/request` — long-poll job claim (201 with a job, or 204 when the queue is empty).
- `PUT /api/v4/jobs/{id}` — job completion (success/failed).
- `PATCH /api/v4/jobs/{id}/trace` — incremental build-log streaming.
- `POST /api/v4/jobs/{id}/artifacts`, `GET /api/v4/jobs/{id}/artifacts` — artifact upload / dependency download.

**Control-plane API** (the orchestrator / test harness drives these):
- `POST /api/v4/user/runners` — mint a runner registration token.
- `POST /api/v4/projects`, `POST /api/v4/projects/{id}/repository/commits` — create a project and commit its `.gitlab-ci.yml` + files.
- `POST /api/v4/projects/{id}/pipeline`, `GET .../pipelines`, `GET .../pipelines/{pid}`, `GET .../pipelines/{pid}/jobs`, `GET .../jobs/{jid}/trace` — trigger a pipeline and read pipeline/job/trace status.

**Git smart-HTTP** — `clone` / `fetch` / `push` on dynamic `/{namespace}/{project}.git/...` paths ([`git.go`](git.go)).

**Internal read-only surface** (`/internal/*`) — projections the embedded SPA consumes for its dashboard (status, projects, pipelines, jobs, runners, storage). Resource detail still comes from the public `/api/v4` surface; the internal routes exist only where there is no clean public-API equivalent.

**Health** — `GET /health`.

## Storage backend

Bleeplab stores git repositories and CI artifacts in an **object store first**, exactly like Bleephub — the backend is selected by environment, with the same precedence (S3-compatible object store → filesystem directory → in-memory). Git repos are `go-git` `Storer`s ([`git_storage.go`](git_storage.go)); artifacts go through an `artifactStore` ([`artifacts.go`](artifacts.go)); both share the S3 client ([`s3fs.go`](s3fs.go)). Bleephub's [Persistence section](https://github.com/e6qu/bleephub#persistence) describes the common object-store model.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `BLEEPLAB_EXTERNAL_URL` | Base URL for `git_info.repo_url` handed to jobs — must be reachable from the job container. | request `Host` |
| `BLEEPLAB_S3_ENDPOINT` / `BLEEPLAB_S3_BUCKET` / `BLEEPLAB_S3_PREFIX` / `BLEEPLAB_S3_REGION` | S3-compatible object store for git + artifacts. `BUCKET` set ⇒ object-store mode. The region must come from `BLEEPLAB_S3_REGION` or the standard AWS SDK configuration chain. | — (in-memory) |
| `BLEEPLAB_GIT_DIR` | Filesystem directory for git repos when not using S3. | — (in-memory) |
| `BLEEPLAB_ARTIFACTS_DIR` | Filesystem directory for artifacts when not using S3. | — (in-memory) |
| `BLEEPLAB_BACKEND` | Selects the backend + cloud sim in the integration harness (`ecs` → AWS sim, `cloudrun` → GCP sim, …). | — |

## Quick start

Bleeplab has a repository-local Makefile for builds, tests, and the real Sockerless runner harness.

```bash
# Build the server with its embedded dashboard.
make build                   # → ./bleeplab-server
./bleeplab-server -addr :8929 -log-level debug
```

Nothing is required in the environment for the in-memory default — a runner can register and run jobs immediately. Point `BLEEPLAB_S3_*` or `BLEEPLAB_GIT_DIR` at durable storage to keep repos and artifacts across restarts.

## Container images

Every merge to `main` publishes immutable twelve-character commit-SHA tags to GitHub Container Registry. Each generic tag is a multi-architecture manifest; its direct native manifests are suffixed with `-amd64` and `-arm64`. Select the generic manifest for an architecture-aware orchestrator such as Kubernetes, or select a suffixed manifest when a service requires an explicit platform image.

| Image | Multi-architecture manifest | Direct native manifests |
|---|---|---|
| Server | `ghcr.io/e6qu/bleeplab:<tag>` | `ghcr.io/e6qu/bleeplab:<tag>-amd64`, `ghcr.io/e6qu/bleeplab:<tag>-arm64` |
| GitLab Runner | `ghcr.io/e6qu/bleeplab-runner:<tag>` | `ghcr.io/e6qu/bleeplab-runner:<tag>-amd64`, `ghcr.io/e6qu/bleeplab-runner:<tag>-arm64` |

The runner image packages the official GitLab Runner. Mount an existing `config.toml`, or have it register itself from a real Bleeplab runner URL and token:

```bash
docker run --rm \
  -e RUNNER_URL=https://bleeplab.example \
  -e RUNNER_TOKEN=<runner-token> \
  -e RUNNER_EXECUTOR=docker \
  -e RUNNER_DOCKER_IMAGE=alpine:3.20 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/e6qu/bleeplab-runner:<tag>
```

`RUNNER_NAME` and `RUNNER_DOCKER_HOST` optionally refine registration. The newest 20 releases of each package are retained; no mutable `latest` or `main` tag is published.

### bleeplab UI

The dashboard is a Vite SPA embedded via Go `embed` (`ui_embed.go`; `-tags noui` drops it, `ui_noembed.go`). For live UI development, run the Go server headless and the Vite dev server against it:

```bash
go run -tags noui ./cmd -addr :8929 -log-level debug
cd web && bun install --frozen-lockfile && bun run dev
```

## Integration tests

```bash
# Go unit tests (in-process, in-memory storage — no Docker needed).
make test

# Full docker-executor harness: a real gitlab-runner registers against
# Bleeplab and dispatches jobs through a Sockerless backend + cloud simulator.
# The source checkout is a build context: no Bleeplab source dependency exists.
SOCKERLESS_ROOT=/path/to/sockerless make runner-sockerless-test
```

The harness ([`test/runner/sockerless/run-integration.sh`](test/runner/sockerless/run-integration.sh)) exercises the whole runner-as-cloud-task data plane end to end: clone + compile, artifacts across stages, and `services:` sidecars over the network pod. Set `BLEEPLAB_HOLD=1` to hold the stack (Bleeplab `:8929`, backend `:3375`) for inspection on failure. It uses `docker buildx build --load` because the runner image must be available to the local Docker API.

## Source layout

| File | Responsibility |
|---|---|
| [`server.go`](server.go) | HTTP mux, route table, middleware, lifecycle. |
| [`store.go`](store.go) | In-memory control-plane state (runners, projects, pipelines, jobs) + the runner-API wire shapes. |
| [`runner_api.go`](runner_api.go) | The runner-facing handlers (`/api/v4/runners`, `/api/v4/jobs/*`). |
| [`projects_api.go`](projects_api.go) | Control-plane handlers (projects, commits, pipeline trigger + status). |
| [`ciyaml.go`](ciyaml.go) | `.gitlab-ci.yml` parsing → stages + per-job execution spec. |
| [`pipeline.go`](pipeline.go) | Pipeline/stage advancement + job enqueueing. |
| [`artifacts.go`](artifacts.go) | CI artifact upload/download over the object-store-backed `artifactStore`. |
| [`git.go`](git.go), [`git_storage.go`](git_storage.go), [`s3fs.go`](s3fs.go) | Smart-HTTP git + the object-store / filesystem / in-memory storage backend. |
| [`internal_api.go`](internal_api.go) | Read-only `/internal/*` projections for the embedded UI. |
| [`cmd/main.go`](cmd/main.go) | Binary entrypoint (`-addr`, `-log-level`). |

## See also

- [Bleephub](https://github.com/e6qu/bleephub) — the GitHub control-plane sibling.
- [Sockerless runner guide](https://github.com/e6qu/sockerless/blob/main/docs/RUNNERS.md) — runner transport and runtime constraints.
- [Sockerless cloud resource mapping](https://github.com/e6qu/sockerless/blob/main/specs/CLOUD_RESOURCE_MAPPING.md) — how it maps Docker/CI primitives onto clouds.
- [Sockerless architecture](https://github.com/e6qu/sockerless/blob/main/ARCHITECTURE.md) — backend architecture used by the external runner harness.
