FROM oven/bun:1.2.19-alpine AS ui-builder
WORKDIR /src/web
COPY web/package.json web/bun.lock web/tsconfig.base.json web/tsconfig.json web/vite.config.ts web/vitest.config.ts web/index.html ./
COPY web/core ./core
COPY web/src ./src
RUN bun install --frozen-lockfile && bun run build

FROM golang:1.25-alpine AS builder
ARG APPLICATION_RELEASE_REVISION
WORKDIR /src
COPY . .
COPY --from=ui-builder /src/web/dist/ ./dist/
RUN printf '%s' "$APPLICATION_RELEASE_REVISION" | grep -Eq '^([0-9a-f]{12,64}|sha256:[0-9a-f]{64})$' && \
    CGO_ENABLED=0 go build -ldflags "-X github.com/e6qu/bleeplab.builtReleaseRevision=$APPLICATION_RELEASE_REVISION" -o /out/bleeplab ./cmd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/bleeplab /usr/local/bin/bleeplab
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/bleeplab"]
