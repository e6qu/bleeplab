FROM golang:1.25 AS builder

WORKDIR /src

# The product repository supplies Bleeplab; the named sockerless BuildKit
# context supplies the real simulator and backend implementations under test.
COPY --from=sockerless simulators/realexec/ /realexec/
COPY --from=sockerless simulators/aws/ /sim-aws/
RUN cd /sim-aws && GOWORK=off go build -tags noui -o /out/simulator-aws .
COPY --from=sockerless simulators/gcp/ /sim-gcp/
RUN cd /sim-gcp && GOWORK=off go build -tags noui -o /out/simulator-gcp .
COPY --from=sockerless simulators/azure/ /sim-azure/
RUN cd /sim-azure && GOWORK=off go build -tags noui -o /out/simulator-azure .

COPY --from=sockerless api/ api/
COPY --from=sockerless agent/ agent/
COPY --from=sockerless backends/core/ backends/core/
COPY --from=sockerless backends/aws-common/ backends/aws-common/
COPY --from=sockerless backends/ecs/ backends/ecs/
RUN cd backends/ecs && GOWORK=off go mod download && \
    GOWORK=off go build -tags noui -o /out/sockerless-backend-ecs ./cmd/sockerless-backend-ecs
COPY --from=sockerless backends/gcp-common/ backends/gcp-common/
COPY --from=sockerless backends/cloudrun/ backends/cloudrun/
RUN cd backends/cloudrun && GOWORK=off go mod download && \
    GOWORK=off go build -tags noui -o /out/sockerless-backend-cloudrun ./cmd/sockerless-backend-cloudrun
COPY --from=sockerless backends/cloudrun-functions/ backends/cloudrun-functions/
RUN cd backends/cloudrun-functions && GOWORK=off go mod download && \
    GOWORK=off go build -tags noui -o /out/sockerless-backend-gcf ./cmd/sockerless-backend-gcf
COPY --from=sockerless backends/azure-common/ backends/azure-common/
COPY --from=sockerless backends/aca/ backends/aca/
RUN cd backends/aca && GOWORK=off go mod download && \
    GOWORK=off go build -tags noui -o /out/sockerless-backend-aca ./cmd/sockerless-backend-aca
COPY --from=sockerless backends/azure-functions/ backends/azure-functions/
RUN cd backends/azure-functions && GOWORK=off go mod download && \
    GOWORK=off go build -tags noui -o /out/sockerless-backend-azf ./cmd/sockerless-backend-azf
RUN cd agent && GOWORK=off go mod download && \
    CGO_ENABLED=0 GOWORK=off go build -o /out/sockerless-agent ./cmd/sockerless-agent && \
    CGO_ENABLED=0 GOWORK=off go build -o /out/sockerless-cloudrun-bootstrap ./cmd/sockerless-cloudrun-bootstrap && \
    CGO_ENABLED=0 GOWORK=off go build -o /out/sockerless-gcf-bootstrap ./cmd/sockerless-gcf-bootstrap && \
    CGO_ENABLED=0 GOWORK=off go build -o /out/sockerless-azf-bootstrap ./cmd/sockerless-azf-bootstrap

COPY . /bleeplab/
RUN cd /bleeplab && GOWORK=off go build -tags noui -o /out/bleeplab ./cmd

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates jq git docker.io openssl && \
    rm -rf /var/lib/apt/lists/*

ARG GITLAB_RUNNER_VERSION=v18.11.3
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64) RUNNER_ARCH=amd64 ;; \
        arm64) RUNNER_ARCH=arm64 ;; \
        *) echo "Unsupported arch: $ARCH"; exit 1 ;; \
    esac && \
    curl -fsSL "https://gitlab-runner-downloads.s3.amazonaws.com/${GITLAB_RUNNER_VERSION}/binaries/gitlab-runner-linux-${RUNNER_ARCH}" \
        -o /usr/local/bin/gitlab-runner && \
    chmod +x /usr/local/bin/gitlab-runner

COPY --from=builder /out/ /usr/local/bin/
COPY test/run-integration.sh /test/run-integration.sh
RUN chmod +x /test/run-integration.sh

WORKDIR /test
ENTRYPOINT ["/bin/bash", "/test/run-integration.sh"]
