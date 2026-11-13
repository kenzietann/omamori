#!/bin/bash
# Reads the logs of each lab app with omamori and prints what was read and which rules fired.
cd "$(dirname "$0")"
for app in "$@"; do
  for file in out/$app/*; do
    rm -rf score-tmp; mkdir score-tmp
    line=$("$OM" detect "$file" --year 2026 --timezone UTC --output score-tmp 2>&1 | head -1)
    rules=$(python3 -c "
import json,glob,collections
files=glob.glob('score-tmp/*/alerts.json')
if not files: print('-'); raise SystemExit
a=json.load(open(files[0])); al=a['alerts'] if isinstance(a,dict) else a
print(', '.join(sorted(set(x['rule'] for x in al))))" 2>/dev/null)
    stats=$(grep -E "^\| $(basename $file) " score-tmp/*/report.md 2>/dev/null | head -1)
    printf '%-10s %-24s %s\n    rules: %s\n    file: %s\n' "$app" "$(basename $file)" "$line" "$rules" "$stats"
  done
done
