#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

: "${SHAUTH_SOURCE_DIR:?SHAUTH_SOURCE_DIR must point to the pinned Shauth checkout}"

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
expected_shauth_commit="74735a1710fa69d472e7eb27ae95ce317c7c1a3d"
actual_shauth_commit="$(git -C "$SHAUTH_SOURCE_DIR" rev-parse HEAD)"
if [[ "$actual_shauth_commit" != "$expected_shauth_commit" ]]; then
  printf 'Shauth checkout is %s; expected reviewed commit %s\n' "$actual_shauth_commit" "$expected_shauth_commit" >&2
  exit 1
fi
if [[ -n "$(git -C "$SHAUTH_SOURCE_DIR" status --porcelain)" ]]; then
  printf 'Shauth checkout must be clean at reviewed commit %s\n' "$expected_shauth_commit" >&2
  exit 1
fi

compose=(docker compose --project-directory "$SHAUTH_SOURCE_DIR" -f "$SHAUTH_SOURCE_DIR/compose.yaml" -f "$root/test/shauth-compose.override.yaml" -p bleeplab-shauth-sso)
temporary="$(mktemp -d)"
primary_pid=""
secondary_pid=""

docker_arch="$(docker version --format '{{.Server.Arch}}')"
case "$docker_arch" in
  amd64 | x86_64) docker_arch="amd64" ;;
  arm64 | aarch64) docker_arch="arm64" ;;
  *) printf 'unsupported Docker server architecture %s\n' "$docker_arch" >&2; exit 1 ;;
esac
export BLEEPLAB_BACKCHANNEL_FORWARDER="$temporary/backchannel-forwarder"
CGO_ENABLED=0 GOOS=linux GOARCH="$docker_arch" go build -o "$BLEEPLAB_BACKCHANNEL_FORWARDER" ./test/backchannel-forwarder

random_secret() {
  openssl rand -base64 48 | tr -d '\n'
}

cleanup() {
  status=$?
  if [[ "$status" -ne 0 ]]; then
    "${compose[@]}" logs --no-color --tail=180 shauth hydra postgres >&2 || true
    for log in "$temporary"/*.log; do
      [[ -f "$log" ]] || continue
      printf '\n===== %s =====\n' "$log" >&2
      tail -180 "$log" >&2 || true
    done
  fi
  for pid in "$primary_pid" "$secondary_pid"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$temporary"
  return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

POSTGRES_PASSWORD="$(openssl rand -hex 32)"
export POSTGRES_PASSWORD
HYDRA_SYSTEM_SECRET="$(random_secret)"
export HYDRA_SYSTEM_SECRET
export HYDRA_DSN="postgres://shauth:${POSTGRES_PASSWORD}@postgres:5432/hydra?sslmode=disable"
export HYDRA_PUBLIC_URL="http://localhost:48080"
export SHAUTH_PUBLIC_URL="http://localhost:48080"
export SHAUTH_DATABASE_URL="postgres://shauth:${POSTGRES_PASSWORD}@postgres:5432/shauth?sslmode=disable"
export GITHUB_CLIENT_ID="local-integration-client"
export GITHUB_CLIENT_SECRET="local-integration-secret"
SHAUTH_BOOTSTRAP_ADMIN_PASSWORD="$(random_secret)"
export SHAUTH_BOOTSTRAP_ADMIN_PASSWORD
SHAUTH_VALIDATOR_TOKEN="$(random_secret)"
export SHAUTH_VALIDATOR_TOKEN
SHAUTH_VALIDATION_STATUS_TOKEN="$(random_secret)"
export SHAUTH_VALIDATION_STATUS_TOKEN
export SHAUTH_VALIDATION_USERNAME="shauth-validator"
export SHAUTH_VALIDATION_EMAIL="shauth-validator@localhost.test"
export APPLICATION_RELEASE_REVISION="0123456789abcdef0123456789abcdef01234567"
primary_secret="$(random_secret)"
secondary_secret="$(random_secret)"
export SHAUTH_BOOTSTRAP_APPS_JSON
SHAUTH_BOOTSTRAP_APPS_JSON="$(printf '[{"slug":"bleeplab-primary","name":"Bleeplab primary","description":"Primary Bleeplab SSO acceptance application.","launch_url":"http://127.0.0.1:18929/ui/","oidc_client_id":"bleeplab-primary","oidc_client_secret":"%s","redirect_uris":["http://127.0.0.1:18929/auth/shauth/callback"],"post_logout_redirect_uris":["http://127.0.0.1:18929/auth/shauth/logout/complete"],"frontchannel_logout_uri":"http://127.0.0.1:18929/auth/shauth/frontchannel-logout","backchannel_logout_uri":"http://127.0.0.1:18929/auth/shauth/backchannel-logout","health_url":"http://127.0.0.1:18929/health","monitoring_url":"","validation_url":"http://127.0.0.1:18929/auth/validation","signed_out_url":"http://127.0.0.1:18929/auth/signed-out","release_revision":"%s"},{"slug":"bleeplab-secondary","name":"Bleeplab secondary","description":"Secondary Bleeplab SSO acceptance application.","launch_url":"http://localhost:18930/ui/","oidc_client_id":"bleeplab-secondary","oidc_client_secret":"%s","redirect_uris":["http://localhost:18930/auth/shauth/callback"],"post_logout_redirect_uris":["http://localhost:18930/auth/shauth/logout/complete"],"frontchannel_logout_uri":"http://localhost:18930/auth/shauth/frontchannel-logout","backchannel_logout_uri":"http://localhost:18930/auth/shauth/backchannel-logout","health_url":"http://localhost:18930/health","monitoring_url":"","validation_url":"http://localhost:18930/auth/validation","signed_out_url":"http://localhost:18930/auth/signed-out","release_revision":"%s"}]' "$primary_secret" "$APPLICATION_RELEASE_REVISION" "$secondary_secret" "$APPLICATION_RELEASE_REVISION")"

"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker build --load --tag shauth-local "$SHAUTH_SOURCE_DIR"
"${compose[@]}" up --no-build --detach

for ((attempt = 0; attempt < 180; attempt++)); do
  if curl --fail --silent http://localhost:48080/healthz >/dev/null 2>&1 && curl --fail --silent http://localhost:49444/health/ready >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl --fail --silent --show-error http://localhost:48080/healthz >/dev/null
curl --fail --silent --show-error http://localhost:49444/health/ready >/dev/null

start_bleeplab() {
  port="$1"
  host="$2"
  client_id="$3"
  client_secret="$4"
  state_dir="$5"
  mkdir -p "$state_dir"
  env -i \
    APPLICATION_RELEASE_REVISION="$APPLICATION_RELEASE_REVISION" \
    BLEEPLAB_ALLOW_INSECURE_OIDC=true \
    BLEEPLAB_SHAUTH_ISSUER=http://localhost:48080 \
    BLEEPLAB_SHAUTH_CLIENT_ID="$client_id" \
    BLEEPLAB_SHAUTH_CLIENT_SECRET="$client_secret" \
    BLEEPLAB_PUBLIC_URL="http://${host}:${port}" \
    BLEEPLAB_SHAUTH_STATE_DIR="$state_dir" \
    BLEEPLAB_INSECURE_COOKIES=true \
    "$root/bleeplab-server" -addr "0.0.0.0:${port}" >"$temporary/${client_id}.log" 2>&1 &
  started_pid=$!
}

export BLEEPLAB_PRIMARY_STATE_DIR="$temporary/primary-state"
export BLEEPLAB_SECONDARY_STATE_DIR="$temporary/secondary-state"
start_bleeplab 18929 127.0.0.1 bleeplab-primary "$primary_secret" "$BLEEPLAB_PRIMARY_STATE_DIR"
primary_pid="$started_pid"
start_bleeplab 18930 localhost bleeplab-secondary "$secondary_secret" "$BLEEPLAB_SECONDARY_STATE_DIR"
secondary_pid="$started_pid"

for endpoint in http://127.0.0.1:18929/health http://localhost:18930/health; do
  for ((attempt = 0; attempt < 100; attempt++)); do
    if curl --fail --silent "$endpoint" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  curl --fail --silent --show-error "$endpoint" >/dev/null
done

for pid in "$primary_pid" "$secondary_pid"; do
  if ps eww -p "$pid" -o command= | grep -Eq 'SHAUTH_(VALIDATOR_TOKEN|VALIDATION_STATUS_TOKEN|BOOTSTRAP_ADMIN_PASSWORD)='; then
    printf 'Bleeplab process %s inherited a Shauth-only credential\n' "$pid" >&2
    exit 1
  fi
done

env -i \
  PATH="$PATH" \
  HOME="${HOME:-$temporary}" \
  SHAUTH_SOURCE_DIR="$SHAUTH_SOURCE_DIR" \
  SHAUTH_URL="http://localhost:48080" \
  SHAUTH_VALIDATOR_TOKEN="$SHAUTH_VALIDATOR_TOKEN" \
  SHAUTH_VALIDATION_USERNAME="$SHAUTH_VALIDATION_USERNAME" \
  SHAUTH_VALIDATION_EMAIL="$SHAUTH_VALIDATION_EMAIL" \
  APPLICATION_RELEASE_REVISION="$APPLICATION_RELEASE_REVISION" \
  node "$root/test/run-shauth-validation.mjs"
