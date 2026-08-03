#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "usage: checkout_pinned.sh REPOSITORY_URL COMMIT DESTINATION [SPARSE_PATH]" >&2
  exit 2
fi

repository_url=$1
commit=$2
destination=$3
sparse_path=${4:-}

if [[ -e "$destination" && ! -d "$destination/.git" ]]; then
  echo "destination exists but is not a git checkout: $destination" >&2
  exit 1
fi

if [[ ! -d "$destination/.git" ]]; then
  mkdir -p "$(dirname "$destination")"
  git init --quiet "$destination"
  git -C "$destination" remote add origin "$repository_url"
else
  git -C "$destination" remote set-url origin "$repository_url"
fi

if [[ -n "$sparse_path" ]]; then
  git -C "$destination" sparse-checkout set --no-cone "$sparse_path"
fi

git -C "$destination" fetch --quiet --depth=1 --filter=blob:none origin "$commit"
git -C "$destination" checkout --quiet --detach FETCH_HEAD
git -C "$destination" clean -dffx

actual_commit=$(git -C "$destination" rev-parse HEAD)
if [[ "$actual_commit" != "$commit" ]]; then
  echo "checkout mismatch: expected $commit, got $actual_commit" >&2
  exit 1
fi
