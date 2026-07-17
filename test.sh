#!/usr/bin/env bash
# End-to-end OIDC: discovery, jwks, register account+client, headless agent login,
# human form login, token exchange, EdDSA id_token verified against jwks, userinfo.
set -euo pipefail
cd "$(dirname "$0")"

PORT=18798
DB=$(mktemp -d)/test.db
export IDP_DB="$DB" IDP_PUBLIC_URL="http://127.0.0.1:$PORT"
export IDP_ED25519_SEED="1111111111111111111111111111111111111111111111111111111111111111"

./machin-idp serve -port $PORT 2>/dev/null &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
sleep 0.6
B="http://127.0.0.1:$PORT"
J(){ python3 -c "import json,sys;d=json.load(sys.stdin);print(d$1)"; }
fail(){ echo "FAIL: $1"; exit 1; }
P=0; ok(){ P=$((P+1)); echo "ok $P - $1"; }

curl -sf "$B/_health" | grep -q '"ok":1' || fail health; ok health
curl -sf "$B/llms.txt" | grep -q "Login with intrane" || fail llms; ok llms.txt
# discovery + jwks
D=$(curl -sf "$B/.well-known/openid-configuration")
[ "$(echo "$D" | J "['id_token_signing_alg_values_supported'][0]")" = "EdDSA" ] || fail disc; ok "discovery advertises EdDSA"
[ "$(echo "$D" | J "['issuer']")" = "$B" ] || fail iss; ok "discovery issuer"
JW=$(curl -sf "$B/jwks")
[ "$(echo "$JW" | J "['keys'][0]['crv']")" = "Ed25519" ] || fail jwks; ok "jwks exposes Ed25519 OKP key"

# register a principal (agent) + a client
A=$(curl -sf -X POST "$B/v1/accounts" -d '{"handle":"agent7@example.com","password":"correct-horse-battery","name":"Agent 7","kind":"agent"}')
SUB=$(echo "$A" | J "['sub']")
[ -n "$SUB" ] || fail acct; ok "account registered ($SUB)"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/v1/accounts" -d '{"handle":"agent7@example.com","password":"another-one"}')" = "409" ] || fail dup; ok "duplicate handle -> 409"
C=$(curl -sf -X POST "$B/v1/clients" -d '{"name":"testapp","redirect_uris":"http://127.0.0.1:9999/cb"}')
CID=$(echo "$C" | J "['client_id']"); CSEC=$(echo "$C" | J "['client_secret']")
[ -n "$CSEC" ] || fail client; ok "client registered ($CID)"

AUTHQ="response_type=code&client_id=$CID&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&scope=openid%20email&state=xyz&nonce=n1"

# --- headless agent login: HTTP Basic on /authorize -> 302 with code ---
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' -u 'agent7@example.com:correct-horse-battery' "$B/authorize?$AUTHQ")
echo "$LOC" | grep -q "127.0.0.1:9999/cb?code=ac_" || fail headless; ok "headless agent login -> code"
echo "$LOC" | grep -q "state=xyz" || fail hstate; ok "state preserved"
CODE=$(echo "$LOC" | sed -n 's/.*code=\(ac_[a-f0-9]*\).*/\1/p')
# wrong password -> 401
[ "$(curl -s -o /dev/null -w '%{http_code}' -u 'agent7@example.com:wrong' "$B/authorize?$AUTHQ")" = "401" ] || fail badpw; ok "wrong password -> 401"

# --- token exchange (client Basic auth) ---
TOK=$(curl -sf -X POST "$B/token" -u "$CID:$CSEC" -d "grant_type=authorization_code&code=$CODE&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb")
AT=$(echo "$TOK" | J "['access_token']")
IDT=$(echo "$TOK" | J "['id_token']")
[ -n "$AT" ] || fail token; ok "token exchange returns access_token"
[ -n "$IDT" ] || fail idt; ok "id_token issued"
# code is one-time
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/token" -u "$CID:$CSEC" -d "grant_type=authorization_code&code=$CODE&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb")" = "400" ] || fail onetime; ok "auth code is one-time"
# wrong client secret -> 401
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/token" -u "$CID:wrong" -d "grant_type=authorization_code&code=x&redirect_uri=y")" = "401" ] || fail clisec; ok "bad client secret -> 401"

# --- verify the EdDSA id_token against the jwks (independent Python check) ---
python3 - "$IDT" "$JW" "$B" "$CID" "$SUB" <<'PY'
import sys, json, base64, hashlib
idt, jwks, iss, cid, sub = sys.argv[1:6]
def b64u(s): return base64.urlsafe_b64decode(s + '='*(-len(s)%4))
h,p,s = idt.split('.')
hdr=json.loads(b64u(h)); pay=json.loads(b64u(p)); sig=b64u(s)
assert hdr['alg']=='EdDSA', hdr
assert pay['iss']==iss and pay['aud']==cid and pay['sub']==sub, pay
assert pay['email']=='agent7@example.com', pay
x=b64u(json.loads(jwks)['keys'][0]['x'])
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(x).verify(sig, (h+'.'+p).encode())
    print("SIGOK")
except ImportError:
    print("SIGSKIP(no cryptography lib)")
PY
SIGRES=$(python3 - "$IDT" "$JW" "$B" "$CID" "$SUB" <<'PY'
import sys, json, base64
idt, jwks = sys.argv[1], sys.argv[2]
def b64u(s): return base64.urlsafe_b64decode(s + '='*(-len(s)%4))
h,p,s = idt.split('.'); sig=b64u(s)
x=b64u(json.loads(jwks)['keys'][0]['x'])
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(x).verify(sig, (h+'.'+p).encode()); print("SIGOK")
except ImportError: print("SIGSKIP")
except Exception as e: print("SIGBAD")
PY
)
[ "$SIGRES" != "SIGBAD" ] || fail sigverify; ok "id_token EdDSA signature verifies against jwks ($SIGRES)"

# --- userinfo ---
UI=$(curl -sf "$B/userinfo" -H "Authorization: Bearer $AT")
[ "$(echo "$UI" | J "['email']")" = "agent7@example.com" ] || fail userinfo; ok "userinfo returns the identity"
[ "$(echo "$UI" | J "['sub']")" = "$SUB" ] || fail uisub; ok "userinfo sub matches"
# bad token -> 401
[ "$(curl -s -o /dev/null -w '%{http_code}' "$B/userinfo" -H "Authorization: Bearer at_nope")" = "401" ] || fail uitoken; ok "bad access_token -> 401"

# --- human form login path ---
FLOC=$(curl -s -o /dev/null -w '%{redirect_url}' -X POST "$B/authorize/login" --data-urlencode "handle=agent7@example.com" --data-urlencode "password=correct-horse-battery" --data-urlencode "client_id=$CID" --data-urlencode "redirect_uri=http://127.0.0.1:9999/cb" --data-urlencode "scope=openid email" --data-urlencode "state=formstate" --data-urlencode "nonce=n2")
echo "$FLOC" | grep -q "code=ac_" || fail form; ok "human form login -> code"
# /authorize without creds serves the sign-in form
curl -sf "$B/authorize?$AUTHQ" | grep -q "Sign in with intrane" || fail formhtml; ok "/authorize serves a sign-in form for browsers"

# open-redirect guard: unregistered redirect_uri -> error
curl -s "$B/authorize?response_type=code&client_id=$CID&redirect_uri=http%3A%2F%2Fevil.com&scope=openid&state=x" -u 'agent7@example.com:correct-horse-battery' | grep -qi "not registered" || fail openredir; ok "unregistered redirect_uri blocked"

# operator CLI
./machin-idp account-new -handle ops@x -password opspassword -kind human | grep -q '"ok":true' || fail cli-acct; ok "cli account-new"
./machin-idp stats | grep -q '"agents"' || fail cli-stats; ok "cli stats"

echo "ALL $P TESTS PASSED"
