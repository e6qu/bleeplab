#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
awk_program="$script_dir/check_workflow_timeouts.awk"

if [[ "$#" -eq 0 ]]; then
  for workflow in .github/workflows/*.yml .github/workflows/*.yaml; do
    [[ -f "$workflow" ]] || continue
    set -- "$@" "$workflow"
  done
fi

if [[ "$#" -eq 0 ]]; then
  printf '%s\n' 'no workflow files were found' >&2
  exit 1
fi

status=0
for workflow in "$@"; do
  if [[ ! -f "$workflow" ]]; then
    printf 'workflow file does not exist: %s\n' "$workflow" >&2
    status=1
    continue
  fi
  if ! awk -f "$awk_program" "$workflow"; then
    status=1
  fi
done
exit "$status"
