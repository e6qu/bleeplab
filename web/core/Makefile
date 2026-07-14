.PHONY: install build test lint clean

install:
	cd .. && bun install --frozen-lockfile

build: install
	bun run build

test: install
	bun run test

lint: install
	bun run typecheck

clean:
	rm -rf dist tsconfig.build.tsbuildinfo
