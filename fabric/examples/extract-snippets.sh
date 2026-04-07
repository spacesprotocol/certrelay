#!/usr/bin/env bash
set -eo pipefail
#
# Extract code snippets from example files.
#
# Snippets are delimited by <doc:name> and </doc:name> tags.
# Output: one file per snippet in the output directory.
#
# Usage:
#   ./extract-snippets.sh rust/src/main.rs snippets/rust
#   ./extract-snippets.sh js/index.mjs snippets/js
#

INPUT="${1:?Usage: extract-snippets.sh <input-file> <output-dir>}"
OUTDIR="${2:?Usage: extract-snippets.sh <input-file> <output-dir>}"

mkdir -p "$OUTDIR"

# Detect language from file extension
EXT="txt"

# Extract each <doc:name> ... </doc:name> block
current_tag=""
current_file=""

while IFS= read -r line; do
    # Check for opening tag
    if [[ "$line" =~ \<doc:([a-zA-Z0-9_-]+)\> ]]; then
        current_tag="${BASH_REMATCH[1]}"
        current_file="$OUTDIR/${current_tag}.${EXT}"
        > "$current_file"  # truncate
        continue
    fi

    # Check for closing tag
    if [[ "$line" =~ \</doc: ]]; then
        if [ -n "$current_file" ]; then
            echo "  extracted: $current_tag -> $current_file"
        fi
        current_tag=""
        current_file=""
        continue
    fi

    # Write line to current snippet (strip common leading whitespace)
    if [ -n "$current_file" ]; then
        echo "$line" >> "$current_file"
    fi
done < "$INPUT"

# Clean up: strip common leading whitespace from each snippet
for f in "$OUTDIR"/*."$EXT"; do
    [ -f "$f" ] || continue
    # Find minimum indentation (ignoring blank lines)
    min_indent=$(sed -n '/[^ ]/{ s/^\( *\).*/\1/; p; }' "$f" | awk '{ print length }' | sort -n | head -1)
    if [ -n "$min_indent" ] && [ "$min_indent" -gt 0 ]; then
        if sed -i '' "s/^ \{1,$min_indent\}//" "$f" 2>/dev/null; then
            : # macOS sed
        else
            sed -i "s/^ \{1,$min_indent\}//" "$f"  # Linux sed
        fi
    fi
done

echo "Done: $(ls "$OUTDIR"/*."$EXT" 2>/dev/null | wc -l | tr -d ' ') snippets extracted"