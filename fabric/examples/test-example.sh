#!/usr/bin/env bash
set -eo pipefail
#
# Test an example by replacing placeholder values with real ones.
#
# Usage:
#   HANDLE=@buffrr SECRET_KEY=abc... ./test-example.sh rust
#
# Required env vars:
#   HANDLE      — handle to resolve/publish (e.g. @buffrr)
#   SECRET_KEY  — 64-char hex secret key for signing
#
# Optional:
#   HANDLES     — comma-separated batch (default: HANDLE repeated)
#   BTC_ADDR    — Bitcoin address to use
#   NPUB        — Nostr npub to use
#   NUM_ID      — Numeric ID for resolve_by_id
#

LANG="${1:?Usage: test-example.sh <rust|js|go|python|kotlin|swift>}"

HANDLE="${HANDLE:?Set HANDLE env var}"
SECRET_KEY="${SECRET_KEY:?Set SECRET_KEY env var}"
HANDLES="${HANDLES:-$HANDLE}"
BTC_ADDR="${BTC_ADDR:-bc1qtest$(date +%s)}"
NPUB="${NPUB:-npub1placeholder}"
NUM_ID="${NUM_ID:-num1placeholder}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "==> Copying $LANG example to $TMPDIR"
cp -r "$SCRIPT_DIR/$LANG" "$TMPDIR/$LANG"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> Replacing placeholders"
find "$TMPDIR/$LANG" -type f \( -name "*.rs" -o -name "*.ts" -o -name "*.js" -o -name "*.go" -o -name "*.py" -o -name "*.kt" -o -name "*.swift" -o -name "*.toml" \) | while read f; do
    sed -i.bak \
        -e "s|alice@bitcoin|$HANDLE|g" \
        -e "s|bob@bitcoin|$HANDLES|g" \
        -e "s|@bitcoin|$(echo $HANDLE | grep -o '[@#].*')|g" \
        -e "s|bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4|$BTC_ADDR|g" \
        -e "s|npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6|$NPUB|g" \
        -e "s|num1qx8dtlzq\.\.\.|$NUM_ID|g" \
        -e "s|0000000000000000000000000000000000000000000000000000000000000001|$SECRET_KEY|g" \
        -e "s|path = \"../../../fabric/rust\"|path = \"$REPO_ROOT/fabric/rust\"|g" \
        "$f"
    rm -f "$f.bak"
done

echo "==> Building and running"
case "$LANG" in
    rust)
        cd "$TMPDIR/$LANG"
        cargo run 2>&1
        ;;
    *)
        echo "Language '$LANG' not yet supported"
        exit 1
        ;;
esac