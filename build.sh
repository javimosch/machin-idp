#!/usr/bin/env bash
# Build the IdP.
#
#   ./build.sh            dev build  (~160 KB, links libssl/libcrypto from the host)
#   ./build.sh --static   release build (~7.3 MB, bundles OpenSSL + CA roots)
#
# Anything that leaves this machine — a GitHub release asset, a deploy to a box
# whose OpenSSL you do not control — MUST be the static one. v0.2.0 shipped a
# dynamic binary under release notes promising a static one; the assertion at
# the bottom is there so that cannot happen silently again.
set -euo pipefail
cd "$(dirname "$0")"
MACHIN="${MACHIN:-machin}"

STATIC=0
[ "${1:-}" = "--static" ] && STATIC=1

python3 - <<'PY' > src/landing_gen.src
import json
print('func landing_html() (h) { h = ' + json.dumps(open('ui/landing.html').read(), ensure_ascii=False) + ' }')
PY
"$MACHIN" encode framework/machweb.src src/*.src > app.mfl

if [ "$STATIC" = 1 ]; then
  "$MACHIN" build app.mfl --static -o machin-idp
  # Assert the claim rather than trusting the flag.
  if ! file machin-idp | grep -q 'statically linked'; then
    echo "build.sh: --static did not produce a static binary — refusing to call it a release" >&2
    exit 1
  fi
  echo "built ./machin-idp (static, $(stat -c %s machin-idp) bytes) — release-shippable"
else
  "$MACHIN" build app.mfl -o machin-idp
  echo "built ./machin-idp (dynamic) — dev only, use --static to release"
fi
