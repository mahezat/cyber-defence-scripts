#!/usr/bin/env bash
# Generate/verify a SHA256 manifest of the toolkit so you can detect tampering
# after cloning onto a compromised box.
#   ./gen-manifest.sh            # write MANIFEST.sha256
#   ./gen-manifest.sh --check    # verify against it
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
MANIFEST="MANIFEST.sha256"

# Pick whichever sha256 tool exists (Linux: sha256sum, macOS: shasum -a 256)
if command -v sha256sum >/dev/null 2>&1; then
  SHA="sha256sum"; SHACHECK="sha256sum -c"
elif command -v shasum >/dev/null 2>&1; then
  SHA="shasum -a 256"; SHACHECK="shasum -a 256 -c"
else
  echo "No sha256sum or shasum found" >&2; exit 1
fi

if [[ "${1:-}" == "--check" ]]; then
  [[ -f "$MANIFEST" ]] || { echo "No $MANIFEST to check against"; exit 1; }
  if $SHACHECK "$MANIFEST"; then
    echo "OK: all files match the manifest."
  else
    echo "MISMATCH: one or more files differ. Do NOT trust this clone." >&2
    exit 1
  fi
  exit 0
fi

# Generate: hash every file except the manifest and .git.
find . -type f \
  -not -path './.git/*' \
  -not -name "$MANIFEST" \
  -print0 \
| sort -z \
| xargs -0 $SHA > "$MANIFEST"

echo "Wrote $MANIFEST ($(wc -l < "$MANIFEST") files)."
echo "Keep a copy of this file on your OWN machine. After cloning on the box, run:"
echo "  ./gen-manifest.sh --check"
