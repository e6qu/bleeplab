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

The GitLab-compatible runner, job, artifact, and Git smart-HTTP transports use
their native registration, runner, and job tokens. The human project,
pipeline, and runner-management API, dashboard, and `/internal/` operator
projections use Shauth OpenID Connect when Shauth is configured. Configure all
five identity coordinates together. Every process also requires an immutable
deployment revision:

```text
BLEEPLAB_SHAUTH_ISSUER=https://auth.dev.e6qu.dev
BLEEPLAB_SHAUTH_CLIENT_ID=...
BLEEPLAB_SHAUTH_CLIENT_SECRET=...
BLEEPLAB_PUBLIC_URL=https://bleeplab.dev.e6qu.dev
BLEEPLAB_SHAUTH_STATE_DIR=/var/lib/bleeplab/shauth
APPLICATION_RELEASE_REVISION=0123456789abcdef0123456789abcdef01234567
```

The optional legacy `POST /api/v4/runners` registration flow is enabled only
when `BLEEPLAB_RUNNER_REGISTRATION_TOKEN` is set; the request's GitLab
`token` field must match it. Modern runners use a runner authentication token
created through the Shauth-protected `POST /api/v4/user/runners` flow.

Register these exact Shauth client coordinates:

```text
redirect_uri:                    https://bleeplab.dev.e6qu.dev/auth/shauth/callback
post_logout_redirect_uri:        https://bleeplab.dev.e6qu.dev/auth/shauth/logout/complete
frontchannel_logout_uri:         https://bleeplab.dev.e6qu.dev/auth/shauth/frontchannel-logout
backchannel_logout_uri:          https://bleeplab.dev.e6qu.dev/auth/shauth/backchannel-logout
frontchannel_logout_session_required: true
backchannel_logout_session_required: true
validation_url:                 https://bleeplab.dev.e6qu.dev/auth/validation
signed_out_url:                 https://bleeplab.dev.e6qu.dev/auth/signed-out
release_revision:               <same immutable APPLICATION_RELEASE_REVISION>
```

Bleeplab treats `BLEEPLAB_SHAUTH_ISSUER` as an exact OpenID Connect issuer
identifier, including a trailing slash when the provider publishes one. It uses
discovery, authorization code + PKCE, `client_secret_post`, nonce and state
checks, and accepts only Shauth `developer` or `admin` roles backed by a
non-empty, verified email address. Every non-runner `/api/v4/` route defaults
to Shauth protection, so newly added control-plane routes fail closed until
their authentication contract is chosen deliberately. An unauthenticated API
request receives GitLab-shaped `401` JSON; browser pages enter the OpenID
Connect flow. The browser receives an opaque,
HttpOnly session identifier; verified issuer, subject, `sid`, identity claims,
expiry, and the ID token remain server-side in `BLEEPLAB_SHAUTH_STATE_DIR`.
Every replica must mount that coordinate from the same durable filesystem (for
example, a shared POSIX-compatible volume); startup fails when Shauth is
configured without it. Session reads and signed logout-token replay
claims are shared across replicas and survive process replacement. The dashboard
displays the user's name, email, avatar, and logout control. Logout uses the
provider's discovered RP-Initiated Logout endpoint with an ID-token hint and the
exact same-origin `/auth/shauth/logout/complete` protocol bridge. The bridge
ignores every query parameter, emits no-store and no-referrer protections, and
redirects only to Shauth's issuer-derived fixed `/oauth/logout/complete`
endpoint. Shauth then completes its one-time server-side logout correlation and
returns the browser to Bleeplab's distinct `/auth/signed-out` page. Local
session state is revoked before any provider discovery or logout network work,
so an unavailable provider cannot leave Bleeplab authenticated. OpenID Connect Front-Channel
Logout revokes the exact issuer and `sid`, and signed Back-Channel Logout
atomically revokes matching local sessions by `sid` (or all sessions for `sub`
when no `sid` is supplied). The signed-out page clears local identity state,
remains local across reloads, and never starts a new sign-in unless the user
chooses its exact `Sign in with Shauth` control. That control enters the
same-origin `/auth/shauth` starter and returns to `/ui/`. The accessible,
responsive page uses saturated light and dark palettes, keyboard focus cues,
and reduced-motion preferences without loading a runtime dependency. The
post-logout bridge URI is derived from `BLEEPLAB_PUBLIC_URL`, so it cannot drift
to another client origin, and the bridge never accepts a caller-selected target.
`GET /auth/validation` is the deployment-neutral,
application-owned acceptance surface. Anonymous callers receive an exact `303`
to the persistent app-local signed-out page. A real Bleeplab session exposes
the verified username, email, normalized `developer` or `admin` role, ordinary
global sign-out control, and immutable deployed release through the stable
`validation-username`, `validation-email`, `validation-role`, and
`validation-release` markers. Authorization headers, API keys, query values,
and Shauth validator credentials are not authentication mechanisms for that
route. An omitted Shauth configuration preserves standalone mode; a partial or
non-HTTPS Shauth configuration fails startup.

`APPLICATION_RELEASE_REVISION` is mandatory and accepts a 12–64 character
lowercase hexadecimal source revision or `sha256:` plus a 64-character
lowercase hexadecimal digest. Release containers bake the full source revision
into the binary; deployment configuration may replace it with the exact image
manifest digest. Startup fails when neither coordinate identifies an immutable
artifact.

`BLEEPLAB_ALLOW_INSECURE_OIDC=true` permits HTTP only for loopback hostnames.
It exists solely for repository-local integration tests; non-loopback issuer
and application coordinates remain HTTPS-only.

## What it implements

All under one binary on one port (`:8929` by default).

**Runner-facing API** (`gitlab-runner` polls these):
- `POST /api/v4/runners/verify`, `POST /api/v4/runners`, `DELETE /api/v4/runners` — verify, legacy registration-token registration, and authenticated unregister.
- `POST /api/v4/jobs/request` — long-poll job claim (201 with a job, or 204 when the queue is empty).
- `PUT /api/v4/jobs/{id}` — job completion (success/failed).
- `PATCH /api/v4/jobs/{id}/trace` — incremental build-log streaming.
- `POST /api/v4/jobs/{id}/artifacts`, `GET /api/v4/jobs/{id}/artifacts` — artifact upload / dependency download.

**Shauth-protected control-plane API** (the UI / operator drives these in a
configured deployment; repository-local harnesses use standalone mode):
- `POST /api/v4/user/runners` — mint a runner registration token.
- `POST /api/v4/projects`, `POST /api/v4/projects/{id}/repository/commits` — create a project and commit its `.gitlab-ci.yml` + files.
- `POST /api/v4/projects/{id}/pipeline`, `GET .../pipelines`, `GET .../pipelines/{pid}`, `GET .../pipelines/{pid}/jobs`, `GET .../jobs/{jid}/trace` — trigger a pipeline and read pipeline/job/trace status.

**Git smart-HTTP** — `clone` / `fetch` / `push` on dynamic
`/{namespace}/{project}.git/...` paths ([`git.go`](git.go)), authenticated as
`gitlab-ci-token` with a job token belonging to that project.

**Internal read-only surface** (`/internal/*`) — projections the embedded SPA consumes for its dashboard (status, projects, pipelines, jobs, runners, storage). Resource detail still comes from the public `/api/v4` surface; the internal routes exist only where there is no clean public-API equivalent.

**Health** — `GET /health`.

## Storage backend

Bleeplab stores git repositories and CI artifacts in an **object store first**, exactly like Bleephub — the backend is selected by environment, with the same precedence (S3-compatible object store → filesystem directory → in-memory). Git repos are `go-git` `Storer`s ([`git_storage.go`](git_storage.go)); artifacts go through an `artifactStore` ([`artifacts.go`](artifacts.go)); both share the S3 client ([`s3fs.go`](s3fs.go)). Bleephub's [Persistence section](https://github.com/e6qu/bleephub#persistence) describes the common object-store model.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `BLEEPLAB_EXTERNAL_URL` | Base URL for `git_info.repo_url` handed to jobs — must be reachable from the job container. | request `Host` |
| `BLEEPLAB_RUNNER_REGISTRATION_TOKEN` | Instance token for the legacy GitLab runner registration endpoint. An unset value disables legacy registration. | — |
| `BLEEPLAB_S3_ENDPOINT` / `BLEEPLAB_S3_BUCKET` / `BLEEPLAB_S3_PREFIX` / `BLEEPLAB_S3_REGION` | S3-compatible object store for git + artifacts. `BUCKET` set ⇒ object-store mode. The region must come from `BLEEPLAB_S3_REGION` or the standard AWS SDK configuration chain. | — (in-memory) |
| `BLEEPLAB_GIT_DIR` | Filesystem directory for git repos when not using S3. | — (in-memory) |
| `BLEEPLAB_ARTIFACTS_DIR` | Filesystem directory for artifacts when not using S3. | — (in-memory) |
| `BLEEPLAB_BACKEND` | Selects the backend + cloud sim in the integration harness (`ecs` → AWS sim, `cloudrun` → GCP sim, …). | — |
| `APPLICATION_RELEASE_REVISION` | Immutable source revision or image digest exposed by app-owned post-deploy validation. Release images bake the source revision as their default. | required |

## Quick start

Bleeplab has a repository-local Makefile for builds, tests, and the real Sockerless runner harness.

```bash
# Build the server with its embedded dashboard.
make build                   # → ./bleeplab-server
APPLICATION_RELEASE_REVISION=0123456789ab ./bleeplab-server -addr :8929 -log-level debug
```

Apart from the required immutable release coordinate, nothing is required in
the environment for the in-memory standalone default — the control-plane API
can create a runner authentication token and run jobs immediately. Point
`BLEEPLAB_S3_*` or `BLEEPLAB_GIT_DIR` at durable storage to keep repos and
artifacts across restarts.

## Container images

Every merge to `main` publishes immutable twelve-character commit-SHA tags to GitHub Container Registry. Each generic tag is a multi-architecture manifest; its direct native manifests are suffixed with `-amd64` and `-arm64`. Select the generic manifest for an architecture-aware orchestrator such as Kubernetes, or select a suffixed manifest when a service requires an explicit platform image.

The server image build requires
`--build-arg APPLICATION_RELEASE_REVISION=<immutable-revision>` and bakes that
coordinate into the binary. The publication workflow supplies the full source
commit; arbitrary local builds must provide their own exact immutable
coordinate.

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

# Real Shauth SSO acceptance: PostgreSQL, Ory Hydra, the pinned Shauth source,
# two Bleeplab relying parties, and Chromium.
SHAUTH_SOURCE_DIR=/path/to/shauth make shauth-sso-test

# Full docker-executor harness: a real gitlab-runner registers against
# Bleeplab and dispatches jobs through a Sockerless backend + cloud simulator.
# The source checkout is a build context: no Bleeplab source dependency exists.
SOCKERLESS_ROOT=/path/to/sockerless make runner-sockerless-test
```

The harness ([`test/runner/sockerless/run-integration.sh`](test/runner/sockerless/run-integration.sh)) exercises the whole runner-as-cloud-task data plane end to end: clone + compile, artifacts across stages, and `services:` sidecars over the network pod. Set `BLEEPLAB_HOLD=1` to hold the stack (Bleeplab `:8929`, backend `:3375`) for inspection on failure. It uses `docker buildx build --load` because the runner image must be available to the local Docker API.

The Shauth acceptance harness is owned by this repository and pins the reviewed
Shauth commit. It runs the same deployment-neutral browser contract used after
deployment, once from Bleeplab's public origin and once from Shauth's application
catalog. Each lifecycle receives exactly two short-lived, single-use,
passwordless Shauth browser bootstraps. It proves exact verified identity and
release markers, single-login SSO across two relying parties, app-initiated
global logout returning to Bleeplab, provider-initiated global logout,
Front-Channel and signed Back-Channel Logout, persistent app-local signed-out
reload, explicit recovery through the same-origin starter, and fail-closed
access after the shared session ends. The reusable Shauth validator token is
accepted only by Shauth and is never inherited by either Bleeplab process or
the browser process. The browser additionally proves that credential-shaped
headers, query values, cookies, and form fields cannot authenticate Bleeplab.
The harness reuses the test-only Playwright installation locked by that Shauth
checkout; Bleeplab has no oauth2-proxy or other authentication proxy dependency.

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
