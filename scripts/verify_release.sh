#!/usr/bin/env bash
# Consumer-side verification of a published Epimetheus Red release.
#
# Usage:
#   scripts/verify_release.sh v0.1.0 [repo]
#
# Downloads the release artifacts from GitHub, verifies the cosign keyless
# signature (Fulcio certificate pinned to this repository's release
# workflow), and checks the checksums file.

set -euo pipefail

tag="${1:?usage: verify_release.sh TAG [owner/repo]}"
repo="${2:-paarthbhatt/epimetheus-core}"

command -v cosign >/dev/null || { echo "cosign not installed: https://docs.sigstore.dev"; exit 1; }
command -v gh >/dev/null || { echo "gh (GitHub CLI) not installed"; exit 1; }

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

echo "Downloading release $tag from $repo ..."
gh release download "$tag" --repo "$repo" --dir "$workdir" --clobber \
  -p '*.bundle' -p 'checksums.txt' -p '*.whl' -p '*.tar.gz'

status=0
for artifact in "$workdir"/*.whl "$workdir"/*.tar.gz "$workdir"/checksums.txt; do
  [ -e "$artifact" ] || continue
  cosign verify-blob \
    --bundle "${artifact}.bundle" \
    --certificate-identity-regexp "^https://github.com/${repo}/.github/workflows/release.yml@refs/tags/${tag}$" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$artifact" || { echo "FAILED: $artifact"; status=1; }
done

(cd "$workdir" && sha256sum --check --quiet checksums.txt) || status=1

if [ "$status" -eq 0 ]; then
  echo "OK: release $tag of $repo verified (cosign + checksums)."
else
  echo "VERIFICATION FAILED for release $tag of $repo" >&2
  exit 1
fi
