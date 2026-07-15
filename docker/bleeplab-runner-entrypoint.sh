#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${RUNNER_TOKEN:-}" ]]; then
  : "${RUNNER_URL:?RUNNER_URL must be the Bleeplab server URL when RUNNER_TOKEN is set}"
  : "${RUNNER_EXECUTOR:?RUNNER_EXECUTOR must be set when RUNNER_TOKEN is set}"

  register_args=(
    register
    --non-interactive
    --url "$RUNNER_URL"
    --token "$RUNNER_TOKEN"
    --executor "$RUNNER_EXECUTOR"
    --name "${RUNNER_NAME:-$(hostname)}"
  )
  if [[ "$RUNNER_EXECUTOR" == docker ]]; then
    : "${RUNNER_DOCKER_IMAGE:?RUNNER_DOCKER_IMAGE must be set for the docker executor}"
    register_args+=(--docker-image "$RUNNER_DOCKER_IMAGE")
    if [[ -n "${RUNNER_DOCKER_HOST:-}" ]]; then
      register_args+=(--docker-host "$RUNNER_DOCKER_HOST")
    fi
  fi
  gitlab-runner "${register_args[@]}"
fi

exec gitlab-runner run --user=gitlab-runner --working-directory=/home/gitlab-runner
