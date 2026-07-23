# Releasing finpass

Releases are built locally and published with `scripts/release.sh`. A release
ships one binary — the Cosmopolitan APE build, which runs on Linux, macOS and
Windows on amd64 and arm64 — plus arch-independent deb/rpm packages, a
`SHA256SUMS` file, and an SSH signature over it made with a YubiKey-resident
key. The Homebrew tap (`hermo/homebrew-finpass`) is updated as part of the
release.

## Trust model

The trust root is the `finpass-allowed-signers` file in the repository root,
not any single key. Each YubiKey holds its own non-extractable FIDO2
(`ed25519-sk`) keypair; the file lists every currently-valid public key under
the identity `release@mirko.fi`. A release signature verifies if it was made
by *any* listed key, so any enrolled YubiKey can sign a release, and keys can
be added or revoked independently.

## One-time setup

### Enroll a YubiKey

Requires firmware ≥ 5.2.3 for `ed25519-sk` (check with `ykman info`; older
keys can use `ecdsa-sk` instead). For each YubiKey:

```bash
ssh-keygen -t ed25519-sk -O resident -O verify-required \
    -O application=ssh:finpass-release \
    -C "yk-$(ykman info | awk '/Serial/{print $3}')" \
    -f ~/.ssh/id_ed25519_sk_rk_finpass-release
```

- `-O resident` stores the key handle on the YubiKey itself, so on any new
  machine `ssh-keygen -K` (run in `~/.ssh`) regenerates the local stub files.
  The stub is useless without the physical YubiKey, so it needs no special
  protection.
- `-O verify-required` requires the FIDO2 PIN in addition to a touch, so a
  stolen YubiKey alone can't sign.
- An empty file passphrase is fine here: the stub holds no key material, and
  the token itself already demands PIN + touch.

**YubiKey 4** (no FIDO2, only U2F): enroll with `ecdsa-sk` and without the
resident/PIN options, which CTAP1 devices don't support:

```bash
ssh-keygen -t ecdsa-sk -O application=ssh:finpass-release \
    -C "yk-$(ykman info | awk '/Serial/{print $3}')" \
    -f ~/.ssh/id_ecdsa_sk_finpass-release
```

Two caveats versus the FIDO2 enrollment: the key handle lives only in the
stub file (back it up — e.g. in Bitwarden; without it the key is unusable
and must be revoked and re-enrolled), and signing requires only a touch, no
PIN. **Set a file passphrase on this stub** — it stands in for the PIN the
YubiKey 4 can't enforce, so a stolen laptop with the YubiKey still attached
can't sign.

Append each public key to `finpass-allowed-signers`:

```bash
printf 'release@mirko.fi namespaces="file" %s\n' \
    "$(cat ~/.ssh/id_ed25519_sk_rk_finpass-release.pub)" >> finpass-allowed-signers
```

Commit the file. Enroll at least two YubiKeys so losing one never blocks a
release.

### Transition from minisign (one time)

So existing users can verify the handover from the old minisign key, sign the
allowed-signers file once with it and attach the signature to the first
SSH-signed release:

```bash
minisign -s /mnt/st/finpass.sec -Sm finpass-allowed-signers
gh release upload vX.Y.Z finpass-allowed-signers.minisig
```

### Tools

- `nfpm` (deb/rpm packaging): `brew install nfpm`
- `gh`, authenticated: `gh auth login`
- Podman or Docker (set `CONTAINER_ENGINE=docker` if using Docker)

## Cutting a release

```bash
scripts/release.sh vX.Y.Z
```

To rehearse the ceremony — including the real YubiKey signing and signature
verification — without tagging or publishing anything:

```bash
scripts/release.sh --dry-run v0.0.0
```

A dry run tolerates a dirty tree, any branch, and an existing tag (they
become warnings), doesn't need `gh`, and leaves the signed artifacts in
`dist/` for inspection.

The script refuses to run on a dirty tree or off `main`. It builds the binary
in the container with the version stamped in, smoke-tests it, packages
deb/rpm, writes `SHA256SUMS`, and then asks for the YubiKey — **PIN + touch
is the manual gate**; nothing is published before it. After an explicit
confirmation prompt it tags, pushes, creates the GitHub release, and updates
the brew tap.

Environment overrides: `FINPASS_SIGNING_KEY` (key stub path),
`FINPASS_SIGNER_ID`, `FINPASS_TAP_REPO`, `CONTAINER_ENGINE`.

## Key rotation

- **Add a YubiKey**: enroll as above, append to `finpass-allowed-signers`,
  commit. Sign that release with an *existing* key so the addition is
  authenticated by the previous trust root.
- **Revoke a YubiKey** (lost/retired): delete its line, commit. Optionally
  keep the line with a `valid-before="YYYYMMDD"` option instead of deleting,
  so old releases still verify while new signatures from it are rejected.

## How users verify

Documented in the README; the short form:

```bash
ssh-keygen -Y verify -f finpass-allowed-signers -I release@mirko.fi \
    -n file -s SHA256SUMS.sig < SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```
