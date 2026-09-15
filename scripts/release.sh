#!/usr/bin/env bash
# Local release build + cosign signing + verification gate.
#
# Usage:
#   scripts/release.sh build              # build sdist + wheel, write checksums
#   scripts/release.sh sign COSIGN_KEY    # sign every artifact with a cosign key pair
#   scripts/release.sh verify COSIGN_PUB  # verify every artifact against the public key
#
# Key pair (one-time, keep the private key secret):
#   COSIGN_PASSWORD="" cosign generate-key-pair
#
# The release is only valid if `verify` exits 0 — the same gate the CI
# release workflow enforces with keyless signing.

set -euo pipefail

dist_dir="dist"

die() { echo "release.sh: $*" >&2; exit 1; }

cmd="${1:-}"; shift || true

case "$cmd" in
  build)
    rm -rf "$dist_dir"
    python3 -m pip install --quiet --upgrade pip build
    python3 -m build
    (cd "$dist_dir" && sha256sum -- * > checksums.txt)
    echo "Built:"
    ls -l "$dist_dir"
    ;;

  sign)
    key="${1:?usage: release.sh sign COSIGN_KEY}"
    [ -d "$dist_dir" ] || die "no dist/ — run 'release.sh build' first"
    for artifact in "$dist_dir"/*; do
      case "$artifact" in *.bundle) continue ;; esac
      cosign sign-blob --yes \
        --key "$key" \
        --bundle "${artifact}.bundle" \
        "$artifact"
      echo "signed: ${artifact}"
    done
    ;;

  verify)
    pub="${1:?usage: release.sh verify COSIGN_PUB}"
    [ -d "$dist_dir" ] || die "no dist/ — run 'release.sh build' first"
    for artifact in "$dist_dir"/*; do
      case "$artifact" in *.bundle) continue ;; esac
      bundle="${artifact}.bundle"
      [ -f "$bundle" ] || die "missing signature bundle for $artifact"
      cosign verify-blob \
        --key "$pub" \
        --bundle "$bundle" \
        "$artifact" || die "cosign verify FAILED for $artifact"
      echo "verified: $artifact"
    done
    ( cd "$dist_dir" && sha256sum --check --quiet checksums.txt ) \
      || die "checksums mismatch"
    echo "All release artifacts passed cosign verify + checksums."
    ;;

  *)
    die "unknown command: $cmd (use build | sign | verify)"
    ;;
esac
