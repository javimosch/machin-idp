#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
MACHIN="${MACHIN:-machin}"
python3 - <<'PY' > src/landing_gen.src
import json
print('func landing_html() (h) { h = ' + json.dumps(open('ui/landing.html').read(), ensure_ascii=False) + ' }')
PY
"$MACHIN" encode framework/machweb.src src/*.src > app.mfl
"$MACHIN" build app.mfl -o machin-idp
echo "built ./machin-idp"
