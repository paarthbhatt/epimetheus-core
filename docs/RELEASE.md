# Release Integrity — cosign verification

Every release artifact of `epimetheus-core` (sdist, wheel, checksums) is
signed with [Sigstore cosign](https://docs.sigstore.dev). The release
workflow **refuses to publish** if any artifact fails `cosign verify` —
signature verification is a gate, not best-effort.

## Verify a release (consumers)

One command — downloads the release and verifies signature + checksums:

```bash
scripts/verify_release.sh v0.1.0
```

Manual equivalent (cosign >= v3):

```bash
gh release download v0.1.0 --dir release/ -p '*.whl' -p '*.tar.gz' -p '*.bundle' -p 'checksums.txt'

cosign verify-blob \
  --bundle release/epimetheus_core-0.1.0-py3-none-any.whl.bundle \
  --certificate-identity-regexp '^https://github.com/paarthbhatt/epimetheus-core/.github/workflows/release.yml@refs/tags/v0.1.0$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  release/epimetheus_core-0.1.0-py3-none-any.whl

(cd release/ && sha256sum --check checksums.txt)
```

The certificate identity is pinned to this repository's release workflow and
the exact tag, so a signature cannot be replayed from another repo or tag.

## Local signing (maintainers, offline)

For pre-release or air-gapped signing with a cosign key pair:

```bash
# one-time key pair (keep cosign.key secret; publish cosign.pub)
COSIGN_PASSWORD="" cosign generate-key-pair

scripts/release.sh build            # dist/ + checksums.txt
scripts/release.sh sign cosign.key  # dist/*.bundle
scripts/release.sh verify cosign.pub
```

`verify` exits non-zero if any artifact fails `cosign verify-blob` or the
checksums mismatch.

## What is signed

| Artifact | Signature |
| :--- | :--- |
| `epimetheus_core-<ver>.tar.gz` | `.bundle` (cosign v3 bundle; keyless: Fulcio cert via GitHub OIDC) |
| `epimetheus_core-<ver>-py3-none-any.whl` | `.bundle` |
| `checksums.txt` | `.bundle` |

SBOM (SPDX-JSON) is generated per release by
[anchore/sbom-action](https://github.com/anchore/sbom-action) and attached to
the release.
