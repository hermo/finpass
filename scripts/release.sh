#!/usr/bin/env bash
# Release ceremony for finpass. See RELEASING.md for setup and details.
#
# Usage: scripts/release.sh [-n|--dry-run] vX.Y.Z
#
# Builds the APE binary in a container, packages deb/rpm, signs the checksum
# file with a YubiKey-backed SSH key (touch required), publishes the GitHub
# release, and updates the Homebrew tap.
#
# With --dry-run, runs the full ceremony including signing and signature
# verification, but publishes nothing (no tag, push, release, or tap update).
set -euo pipefail

usage() { echo "usage: $0 [-n|--dry-run] vX.Y.Z" >&2; exit 1; }

DRY_RUN=0
VERSION_TAG=""
while [[ $# -gt 0 ]]; do
	case "$1" in
		-n|--dry-run) DRY_RUN=1 ;;
		-*) usage ;;
		*) [[ -z "$VERSION_TAG" ]] || usage; VERSION_TAG="$1" ;;
	esac
	shift
done
[[ "$VERSION_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage
VERSION="${VERSION_TAG#v}"

cd "$(git rev-parse --show-toplevel)"

CONTAINER_ENGINE="${CONTAINER_ENGINE:-podman}"
# Signing key: FINPASS_SIGNING_KEY wins; otherwise look for known stubs and,
# if several exist, ask which YubiKey is plugged in right now.
SIGNING_KEY="${FINPASS_SIGNING_KEY:-}"
if [[ -z "$SIGNING_KEY" ]]; then
	candidates=()
	for c in "$HOME/.ssh/id_ed25519_sk_rk_finpass-release" \
			"$HOME/.ssh/id_ecdsa_sk_finpass-release"; do
		[[ -f "$c" ]] && candidates+=("$c")
	done
	if (( ${#candidates[@]} == 1 )); then
		SIGNING_KEY="${candidates[0]}"
	elif (( ${#candidates[@]} > 1 )); then
		echo "Multiple signing keys found — pick the one whose YubiKey is plugged in:"
		select SIGNING_KEY in "${candidates[@]}"; do
			[[ -n "$SIGNING_KEY" ]] && break
		done
	else
		SIGNING_KEY="$HOME/.ssh/id_ed25519_sk_rk_finpass-release"
	fi
fi
SIGNER_ID="${FINPASS_SIGNER_ID:-release@mirko.fi}"
ALLOWED_SIGNERS="finpass-allowed-signers"
TAP_REPO="${FINPASS_TAP_REPO:-git@github.com:hermo/homebrew-tap.git}"
# Releases are published on GitHub, which is a secondary remote; origin is the
# private Forgejo. The tag must be pushed to both.
GITHUB_REMOTE="${FINPASS_GITHUB_REMOTE:-github}"
DIST=dist

# --- Preflight ---------------------------------------------------------------
fail() { echo "error: $*" >&2; exit 1; }
# Publish-blocking conditions are only warnings in a dry run
check() { if (( DRY_RUN )); then echo "warning (dry-run): $*" >&2; else fail "$*"; fi }

git diff-index --quiet HEAD -- || check "working tree is not clean"
[[ "$(git branch --show-current)" == "main" ]] || check "not on main"
git rev-parse -q --verify "refs/tags/$VERSION_TAG" >/dev/null \
	&& check "tag $VERSION_TAG already exists"
[[ -f "$SIGNING_KEY" ]] \
	|| fail "signing key $SIGNING_KEY not found (plug in a YubiKey and run: ssh-keygen -K; or set FINPASS_SIGNING_KEY)"
[[ -f "$ALLOWED_SIGNERS" ]] || fail "$ALLOWED_SIGNERS not found (see RELEASING.md)"
for cmd in "$CONTAINER_ENGINE" nfpm sha256sum ssh-keygen; do
	command -v "$cmd" >/dev/null || fail "$cmd not installed"
done
if (( ! DRY_RUN )); then
	command -v gh >/dev/null || fail "gh not installed"
	gh auth status >/dev/null || fail "gh not authenticated"
	git remote get-url "$GITHUB_REMOTE" >/dev/null 2>&1 \
		|| fail "remote $GITHUB_REMOTE not configured (set FINPASS_GITHUB_REMOTE)"
fi

# --- Build -------------------------------------------------------------------
rm -rf "$DIST"
mkdir -p "$DIST"

echo "==> Building $VERSION_TAG in container"
"$CONTAINER_ENGINE" build --build-arg FINPASS_VERSION="$VERSION_TAG" \
	-t finpass-builder .
cid=$("$CONTAINER_ENGINE" create finpass-builder)
"$CONTAINER_ENGINE" cp "$cid:/app/finpass.ape" "$DIST/finpass.ape"
"$CONTAINER_ENGINE" rm -f "$cid" >/dev/null
chmod +x "$DIST/finpass.ape"

echo "==> Smoke test"
"$DIST/finpass.ape" --version | grep -qF "$VERSION_TAG" \
	|| fail "built binary does not report $VERSION_TAG"
"$DIST/finpass.ape" >/dev/null || fail "built binary failed to generate a passphrase"

echo "==> Packaging deb/rpm"
export FINPASS_VERSION="$VERSION"
nfpm package -f nfpm.yaml -p deb -t "$DIST/"
nfpm package -f nfpm.yaml -p rpm -t "$DIST/"

# --- Sign (manual gate: requires YubiKey touch) ------------------------------
echo "==> Checksums"
(cd "$DIST" && sha256sum finpass.ape ./*.deb ./*.rpm > SHA256SUMS)

echo "==> Signing SHA256SUMS — touch your YubiKey when it blinks"
ssh-keygen -Y sign -f "$SIGNING_KEY" -n file "$DIST/SHA256SUMS"

echo "==> Verifying signature against $ALLOWED_SIGNERS"
ssh-keygen -Y verify -f "$ALLOWED_SIGNERS" -I "$SIGNER_ID" -n file \
	-s "$DIST/SHA256SUMS.sig" < "$DIST/SHA256SUMS" \
	|| fail "signature does not verify against $ALLOWED_SIGNERS"

# --- Publish -----------------------------------------------------------------
if (( DRY_RUN )); then
	echo
	echo "Dry run complete — signed artifacts left in $DIST/, nothing published:"
	(cd "$DIST" && ls -l)
	exit 0
fi

echo
echo "About to publish:"
(cd "$DIST" && ls -l)
echo
read -r -p "Tag $VERSION_TAG, push, create GitHub release and update brew tap? [y/N] " answer
[[ "$answer" == "y" || "$answer" == "Y" ]] || fail "aborted"

git tag -a "$VERSION_TAG" -m "finpass $VERSION_TAG"
git push origin "$VERSION_TAG"
git push "$GITHUB_REMOTE" "$VERSION_TAG"

gh release create "$VERSION_TAG" \
	"$DIST/finpass.ape" "$DIST"/*.deb "$DIST"/*.rpm \
	"$DIST/SHA256SUMS" "$DIST/SHA256SUMS.sig" \
	--title "finpass $VERSION_TAG" --generate-notes

# --- Homebrew tap ------------------------------------------------------------
echo "==> Updating Homebrew tap"
APE_SHA256=$(awk '$2 == "finpass.ape" { print $1 }' "$DIST/SHA256SUMS")
tapdir=$(mktemp -d)
trap 'rm -rf "$tapdir"' EXIT
git clone --depth 1 "$TAP_REPO" "$tapdir"
mkdir -p "$tapdir/Formula"
cat > "$tapdir/Formula/finpass.rb" <<EOF
class Finpass < Formula
  desc "Generate passphrases using Finnish language words"
  homepage "https://github.com/hermo/finpass"
  version "$VERSION"
  url "https://github.com/hermo/finpass/releases/download/$VERSION_TAG/finpass.ape"
  sha256 "$APE_SHA256"
  license "MIT"

  # The APE binary is not ELF, so Homebrew's Linux cleaner would strip its
  # exec bit (it only recognizes shebang scripts and ELF as executables).
  skip_clean "bin/finpass"

  def install
    bin.install "finpass.ape" => "finpass"
    chmod 0755, bin/"finpass"
  end

  test do
    assert_match "$VERSION_TAG", shell_output("#{bin}/finpass --version")
  end
end
EOF
git -C "$tapdir" add Formula/finpass.rb
git -C "$tapdir" commit -m "finpass $VERSION_TAG"
git -C "$tapdir" push

echo
echo "Released finpass $VERSION_TAG"
