.PHONY: build check-workflow-timeouts test web-build shauth-sso-test runner-sockerless-test runner-image

build: web-build
	CGO_ENABLED=0 go build -o bleeplab-server ./cmd

web-build:
	cd web && bun install --frozen-lockfile && bun run build
	rm -rf dist
	mkdir -p dist
	cp -R web/dist/. dist/

test:
	go test -tags noui -count=1 -timeout 5m ./...

check-workflow-timeouts:
	bash test/test-workflow-timeouts.sh

shauth-sso-test: build
	@test -n "$(SHAUTH_SOURCE_DIR)" || { echo "SHAUTH_SOURCE_DIR must point to the pinned Shauth checkout"; exit 1; }
	bash test/run-shauth-sso.sh

runner-sockerless-test:
	@test -n "$(SOCKERLESS_ROOT)" || { echo "SOCKERLESS_ROOT must point to a Sockerless checkout"; exit 1; }
	@test -f "$(SOCKERLESS_ROOT)/go.work" || { echo "SOCKERLESS_ROOT is not a Sockerless checkout"; exit 1; }
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine:3.20 true >/dev/null 2>&1 || { echo "runner harness requires a bind-mountable Linux Docker API socket at /var/run/docker.sock"; exit 1; }
	docker buildx build --load --build-context sockerless="$(SOCKERLESS_ROOT)" -f test/runner/sockerless/Dockerfile -t bleeplab-runner-sockerless:local .
	rm -rf /tmp/bleeplab-runner-sockerless-data
	mkdir -p /tmp/bleeplab-runner-sockerless-data
	docker run --rm --security-opt label=disable -v /var/run/docker.sock:/var/run/docker.sock -v /tmp/bleeplab-runner-sockerless-data:/tmp/bleeplab-runner-sockerless-data -e SOCKERLESS_HARNESS_DATA_DIR=/tmp/bleeplab-runner-sockerless-data -e BLEEPLAB_BACKEND=ecs -p 8929:8929 -p 3375:3375 -p 5000:4566 bleeplab-runner-sockerless:local

runner-image:
	docker buildx build --load -f Dockerfile.runner -t bleeplab-runner:local .
