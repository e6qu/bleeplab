#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
checker="$root/test/check-workflow-timeouts.sh"
fixtures="$root/test/workflow-timeouts"

expect_failure() {
  local fixture="$1"
  local expected="$2"
  local output
  if output="$($checker "$fixtures/$fixture" 2>&1)"; then
    printf 'expected %s to fail\n' "$fixture" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    printf 'unexpected diagnostic for %s:\n%s\n' "$fixture" "$output" >&2
    exit 1
  fi
}

$checker "$fixtures/valid.yml"
expect_failure missing.yml 'is missing timeout-minutes'
expect_failure too-large.yml 'from 1 through 15'
expect_failure expression.yml 'from 1 through 15'
expect_failure duplicate.yml 'more than once'
expect_failure no-jobs.yml 'contains no recognized jobs'
$checker
printf '%s\n' 'workflow timeout contracts passed'
