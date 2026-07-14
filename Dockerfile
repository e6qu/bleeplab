FROM oven/bun:1.2.19-alpine AS ui-builder
WORKDIR /src/web
COPY web/package.json web/tsconfig.base.json web/tsconfig.json web/vite.config.ts web/vitest.config.ts web/index.html ./
COPY web/core ./core
COPY web/src ./src
RUN bun install && bun run build

FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
COPY --from=ui-builder /src/web/dist/ ./dist/
RUN CGO_ENABLED=0 go build -o /out/bleeplab ./cmd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/bleeplab /usr/local/bin/bleeplab
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/bleeplab"]
