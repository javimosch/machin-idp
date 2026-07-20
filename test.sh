#!/usr/bin/env bash
# End-to-end OIDC: discovery, jwks, register account+client, headless agent login,
# human form login, token exchange, EdDSA id_token verified against jwks, userinfo,
# redirect_uri enforcement, nonce/kid claims, signup, security guards.
set -euo pipefail
cd "$(dirname "$0")"

[ -x ./machin-idp ] || ./build.sh

PORT=18798
DB=$(mktemp -d)/test.db
export IDP_DB="$DB" IDP_PUBLIC_URL="http://127.0.0.1:$PORT"
export IDP_ED25519_SEED="1111111111111111111111111111111111111111111111111111111111111111"

./machin-idp serve -port $PORT 2>/dev/null &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
B="http://127.0.0.1:$PORT"
for _ in $(seq 1 50); do curl -sf "$B/_health" >/dev/null 2>&1 && break; sleep 0.1; done
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
[ "$(curl -sf "$B/.well-known/jwks.json" | J "['keys'][0]['kty']")" = "OKP" ] || fail jwksalt; ok "alternate jwks path /.well-known/jwks.json"

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
# wrong password -> 401 + WWW-Authenticate
BADPW=$(curl -s -D - -o /dev/null -u 'agent7@example.com:wrong' "$B/authorize?$AUTHQ")
echo "$BADPW" | grep -qi '401' || fail badpw; ok "wrong password -> 401"
echo "$BADPW" | grep -qi 'WWW-Authenticate: Basic realm="intrane"' || fail wwwauth; ok "401 includes WWW-Authenticate realm"
# malformed Basic -> 401
[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Basic !!!' "$B/authorize?$AUTHQ")" = "401" ] || fail badbasic; ok "malformed Basic -> 401"
# empty Basic scheme (no credentials) -> 401, not the browser form
[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Basic' "$B/authorize?$AUTHQ")" = "401" ] || fail emptybasic; ok "empty Basic scheme -> 401"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Basic ' "$B/authorize?$AUTHQ")" = "401" ] || fail emptybasicsp; ok "Basic with empty payload -> 401"
# unknown handle -> 401 (same shape as wrong password — no user enumeration)
UNK=$(curl -s -D - -o /tmp/idp_unk_body -u 'nobody@example.com:whatever' "$B/authorize?$AUTHQ")
echo "$UNK" | grep -qi '401' || fail unkhandle; ok "unknown handle Basic -> 401"
echo "$UNK" | grep -qi 'WWW-Authenticate: Basic realm="intrane"' || fail unkwww; ok "unknown handle includes WWW-Authenticate"
grep -qi 'invalid credentials' /tmp/idp_unk_body || fail unkbody; ok "unknown handle body matches wrong-password shape"
! grep -qi 'unknown\|not found\|no such' /tmp/idp_unk_body || fail unk leak; ok "unknown handle does not leak existence"

# --- rate limit: 61 failed Basic attempts -> 429 on the 61st ---
for i in $(seq 1 60); do curl -s -o /dev/null -u 'agent7@example.com:wrong' "$B/authorize?$AUTHQ&state=rl$i"; done
RL=$(curl -s -o /dev/null -w '%{http_code}' -u 'agent7@example.com:wrong' "$B/authorize?$AUTHQ&state=rl61")
[ "$RL" = "429" ] || fail ratelimit; ok "61st failed Basic auth -> 429"
# valid creds still work after rate limit (success path skips rate counter)
LOC_RL=$(curl -s -o /dev/null -w '%{redirect_url}' -u 'agent7@example.com:correct-horse-battery' "$B/authorize?$AUTHQ&state=rlok")
echo "$LOC_RL" | grep -q "code=ac_" || fail ratelimit_ok; ok "valid Basic auth succeeds after rate limit window"

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
# malformed Basic on /token -> 401 invalid_client (no crash)
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/token" -H 'Authorization: Basic !!!' -d 'grant_type=authorization_code&code=x&redirect_uri=y')" = "401" ] || fail badtokbasic; ok "malformed Basic on /token -> 401"
# missing / wrong grant_type -> 400 unsupported_grant_type
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/token" -u "$CID:$CSEC" -d "grant_type=client_credentials&code=x&redirect_uri=y")" = "400" ] || fail badgrant; ok "wrong grant_type -> 400"
curl -s -X POST "$B/token" -u "$CID:$CSEC" -d "code=x&redirect_uri=y" | grep -q unsupported_grant_type || fail nogrant; ok "missing grant_type -> unsupported_grant_type"

# --- verify the EdDSA id_token against the jwks (independent Python check) ---
python3 - "$IDT" "$JW" "$B" "$CID" "$SUB" <<'PY'
import sys, json, base64, hashlib
idt, jwks, iss, cid, sub = sys.argv[1:6]
def b64u(s): return base64.urlsafe_b64decode(s + '='*(-len(s)%4))
h,p,s = idt.split('.')
hdr=json.loads(b64u(h)); pay=json.loads(b64u(p)); sig=b64u(s)
assert hdr['alg']=='EdDSA', hdr
assert hdr.get('typ')=='JWT', hdr
jkid=json.loads(jwks)['keys'][0]['kid']
assert hdr.get('kid')==jkid, (hdr, jkid)
assert pay['iss']==iss and pay['aud']==cid and pay['sub']==sub, pay
assert pay['email']=='agent7@example.com', pay
assert pay.get('nonce')=='n1', pay
import time
now=int(time.time())
assert abs(pay['iat']-now)<=60, pay['iat']
assert abs(pay['exp']-(now+3600))<=60, pay['exp']
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
# tampered signature must not verify
TAMP=$(python3 - "$IDT" "$JW" <<'PY'
import sys, json, base64
idt, jwks = sys.argv[1], sys.argv[2]
def b64u(s): return base64.urlsafe_b64decode(s + '='*(-len(s)%4))
h,p,s = idt.split('.')
sig = bytearray(b64u(s)); sig[0] ^= 0xff
bad = h + '.' + p + '.' + base64.urlsafe_b64encode(bytes(sig)).decode().rstrip('=')
x = b64u(json.loads(jwks)['keys'][0]['x'])
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(x).verify(b64u(bad.split('.')[2]), (h+'.'+p).encode())
    print('SIGBAD')
except ImportError: print('SIGSKIP')
except Exception: print('SIGOK')
PY
)
[ "$TAMP" = "SIGOK" ] || fail tamper; ok "tampered id_token signature rejected ($TAMP)"
# id_token omits nonce when authorize had none
AUTHQ_NONONCE="response_type=code&client_id=$CID&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&scope=openid&state=nononce"
LOC_NN=$(curl -s -o /dev/null -w '%{redirect_url}' -u 'agent7@example.com:correct-horse-battery' "$B/authorize?$AUTHQ_NONONCE")
CODE_NN=$(echo "$LOC_NN" | sed -n 's/.*code=\(ac_[a-f0-9]*\).*/\1/p')
TOK_NN=$(curl -sf -X POST "$B/token" -u "$CID:$CSEC" -d "grant_type=authorization_code&code=$CODE_NN&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb")
IDT_NN=$(echo "$TOK_NN" | J "['id_token']")
python3 - "$IDT_NN" <<'PY' || fail nononce
import sys, json, base64
def b64u(s): return base64.urlsafe_b64decode(s + '='*(-len(s)%4))
pay = json.loads(b64u(sys.argv[1].split('.')[1]))
assert 'nonce' not in pay, pay
PY
ok "id_token omits nonce when authorize had none"
python3 - "$IDT" <<'PY' || fail iatexp
import sys, json, base64, time
def b64u(s): return base64.urlsafe_b64decode(s + '='*(-len(s)%4))
pay=json.loads(b64u(sys.argv[1].split('.')[1]))
now=int(time.time())
assert abs(pay['iat']-now)<=60, pay
assert abs(pay['exp']-(now+3600))<=60, pay
PY
ok "id_token iat/exp within ±60s"

# redirect_uri mismatch at token exchange -> invalid_grant
LOC2=$(curl -s -o /dev/null -w '%{redirect_url}' -u 'agent7@example.com:correct-horse-battery' "$B/authorize?$AUTHQ&state=mismatch")
CODE2=$(echo "$LOC2" | sed -n 's/.*code=\(ac_[a-f0-9]*\).*/\1/p')
[ -n "$CODE2" ] || fail code2
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/token" -u "$CID:$CSEC" -d "grant_type=authorization_code&code=$CODE2&redirect_uri=http%3A%2F%2Fevil.com%2Fcb")" = "400" ] || fail redirmismatch; ok "redirect_uri mismatch -> invalid_grant"
# omit redirect_uri at token exchange -> invalid_grant (OAuth exact-match)
LOC2B=$(curl -s -o /dev/null -w '%{redirect_url}' -u 'agent7@example.com:correct-horse-battery' "$B/authorize?$AUTHQ&state=missredir")
CODE2B=$(echo "$LOC2B" | sed -n 's/.*code=\(ac_[a-f0-9]*\).*/\1/p')
[ -n "$CODE2B" ] || fail code2b
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/token" -u "$CID:$CSEC" -d "grant_type=authorization_code&code=$CODE2B")" = "400" ] || fail missredir; ok "missing redirect_uri at token -> invalid_grant"
# empty / unknown code -> invalid_grant
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/token" -u "$CID:$CSEC" -d "grant_type=authorization_code&code=&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb")" = "400" ] || fail emptycode; ok "empty auth code -> invalid_grant"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/token" -u "$CID:$CSEC" -d "grant_type=authorization_code&code=ac_nope&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb")" = "400" ] || fail unkcode; ok "unknown auth code -> invalid_grant"

# client_secret_post (no Basic) on /token
LOC3=$(curl -s -o /dev/null -w '%{redirect_url}' -u 'agent7@example.com:correct-horse-battery' "$B/authorize?$AUTHQ&state=postauth")
CODE3=$(echo "$LOC3" | sed -n 's/.*code=\(ac_[a-f0-9]*\).*/\1/p')
TOK3=$(curl -sf -X POST "$B/token" -d "grant_type=authorization_code&code=$CODE3&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&client_id=$CID&client_secret=$CSEC")
[ -n "$(echo "$TOK3" | J "['access_token']")" ] || fail secretpost; ok "token exchange via client_secret_post"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/token" -d "grant_type=authorization_code&code=$CODE3&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&client_id=$CID&client_secret=wrong")" = "401" ] || fail secretpostbad; ok "client_secret_post wrong secret -> 401"

# code issued to client A, exchange with client B -> invalid_grant
C_B=$(curl -sf -X POST "$B/v1/clients" -d '{"name":"otherapp","redirect_uris":"http://127.0.0.1:9999/cb"}')
CID_B=$(echo "$C_B" | J "['client_id']"); CSEC_B=$(echo "$C_B" | J "['client_secret']")
LOC_X=$(curl -s -o /dev/null -w '%{redirect_url}' -u 'agent7@example.com:correct-horse-battery' "$B/authorize?$AUTHQ&state=crossclient")
CODE_X=$(echo "$LOC_X" | sed -n 's/.*code=\(ac_[a-f0-9]*\).*/\1/p')
[ -n "$CODE_X" ] || fail crosscode
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/token" -u "$CID_B:$CSEC_B" -d "grant_type=authorization_code&code=$CODE_X&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb")" = "400" ] || fail crossclient; ok "code from client A exchanged by client B -> invalid_grant"

# expired auth code -> invalid_grant
LOC4=$(curl -s -o /dev/null -w '%{redirect_url}' -u 'agent7@example.com:correct-horse-battery' "$B/authorize?$AUTHQ&state=expired")
CODE4=$(echo "$LOC4" | sed -n 's/.*code=\(ac_[a-f0-9]*\).*/\1/p')
sqlite3 "$DB" "UPDATE codes SET expires_at=1 WHERE code='$CODE4'"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/token" -u "$CID:$CSEC" -d "grant_type=authorization_code&code=$CODE4&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb")" = "400" ] || fail codexp; ok "expired auth code -> invalid_grant"

# unknown client_id / bad response_type
curl -s "$B/authorize?response_type=code&client_id=cid_nope&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&scope=openid" | grep -qi "unknown client" || fail unkclient; ok "unknown client_id -> error"
curl -s "$B/authorize?response_type=token&client_id=$CID&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&scope=openid" | grep -qi "response_type must be code" || fail badrt; ok "response_type != code -> error"

# --- userinfo ---
UI=$(curl -sf "$B/userinfo" -H "Authorization: Bearer $AT")
[ "$(echo "$UI" | J "['email']")" = "agent7@example.com" ] || fail userinfo; ok "userinfo returns the identity"
[ "$(echo "$UI" | J "['sub']")" = "$SUB" ] || fail uisub; ok "userinfo sub matches"
# bad token -> 401
[ "$(curl -s -o /dev/null -w '%{http_code}' "$B/userinfo" -H "Authorization: Bearer at_nope")" = "401" ] || fail uitoken; ok "bad access_token -> 401"
# missing Authorization -> 401
[ "$(curl -s -o /dev/null -w '%{http_code}' "$B/userinfo")" = "401" ] || fail uinoauth; ok "userinfo without Authorization -> 401"
# expired access_token -> 401
sqlite3 "$DB" "UPDATE tokens SET expires_at=1 WHERE access_token='$AT'"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$B/userinfo" -H "Authorization: Bearer $AT")" = "401" ] || fail atexp; ok "expired access_token -> 401"

# --- human form login path ---
FLOC=$(curl -s -o /dev/null -w '%{redirect_url}' -X POST "$B/authorize/login" --data-urlencode "handle=agent7@example.com" --data-urlencode "password=correct-horse-battery" --data-urlencode "client_id=$CID" --data-urlencode "redirect_uri=http://127.0.0.1:9999/cb" --data-urlencode "scope=openid email" --data-urlencode "state=formstate" --data-urlencode "nonce=n2")
echo "$FLOC" | grep -q "code=ac_" || fail form; ok "human form login -> code"
# wrong password on form -> error page, no auth code
FORM_BAD=$(curl -s -o /tmp/form_bad_body -w '%{http_code}' -X POST "$B/authorize/login" --data-urlencode "handle=agent7@example.com" --data-urlencode "password=wrong-password" --data-urlencode "client_id=$CID" --data-urlencode "redirect_uri=http://127.0.0.1:9999/cb" --data-urlencode "scope=openid email" --data-urlencode "state=formbad" --data-urlencode "nonce=n2b")
[ "$FORM_BAD" = "200" ] || fail formbadcode
grep -qi 'invalid credentials' /tmp/form_bad_body || fail formbadmsg; ok "form login wrong password -> error form, no code"
! grep -q 'code=ac_' /tmp/form_bad_body || fail formbadleak; ok "form login wrong password does not leak code"
# form login unknown handle -> same error shape (no enumeration)
FORM_UNK=$(curl -s -o /tmp/form_unk_body -w '%{http_code}' -X POST "$B/authorize/login" --data-urlencode "handle=nobody@example.com" --data-urlencode "password=whatever" --data-urlencode "client_id=$CID" --data-urlencode "redirect_uri=http://127.0.0.1:9999/cb" --data-urlencode "scope=openid email" --data-urlencode "state=formunk" --data-urlencode "nonce=n2u")
[ "$FORM_UNK" = "200" ] || fail formunkcode
grep -qi 'invalid credentials' /tmp/form_unk_body || fail formunkmsg; ok "form login unknown handle -> error form, no code"
! grep -qi 'unknown\|not found\|no such' /tmp/form_unk_body || fail formunkleak; ok "form login unknown handle does not leak existence"
# form login rate limit: 61 failed attempts -> 429
for i in $(seq 1 60); do curl -s -o /dev/null -X POST "$B/authorize/login" --data-urlencode "handle=agent7@example.com" --data-urlencode "password=wrong-$i" --data-urlencode "client_id=$CID" --data-urlencode "redirect_uri=http://127.0.0.1:9999/cb" --data-urlencode "scope=openid email" --data-urlencode "state=formrl$i"; done
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/authorize/login" --data-urlencode "handle=agent7@example.com" --data-urlencode "password=wrong-61" --data-urlencode "client_id=$CID" --data-urlencode "redirect_uri=http://127.0.0.1:9999/cb" --data-urlencode "scope=openid email" --data-urlencode "state=formrl61")" = "429" ] || fail formratelimit; ok "61st failed form login -> 429"
# /authorize without creds serves the sign-in form
curl -sf "$B/authorize?$AUTHQ" | grep -q "Sign in with intrane" || fail formhtml; ok "/authorize serves a sign-in form for browsers"

# open-redirect guard: unregistered redirect_uri -> error
curl -s "$B/authorize?response_type=code&client_id=$CID&redirect_uri=http%3A%2F%2Fevil.com&scope=openid&state=x" -u 'agent7@example.com:correct-horse-battery' | grep -qi "not registered" || fail openredir; ok "unregistered redirect_uri blocked"

# inline signup on /authorize/signup -> auth code
SLOC=$(curl -s -o /dev/null -w '%{redirect_url}' -X POST "$B/authorize/signup" \
  --data-urlencode "handle=newbie@example.com" --data-urlencode "password=correct-horse-battery" \
  --data-urlencode "name=Newbie" --data-urlencode "client_id=$CID" \
  --data-urlencode "redirect_uri=http://127.0.0.1:9999/cb" --data-urlencode "scope=openid email" \
  --data-urlencode "state=signupstate" --data-urlencode "nonce=n3")
echo "$SLOC" | grep -q "code=ac_" || fail signup; ok "authorize/signup creates account + code"
echo "$SLOC" | grep -q "state=signupstate" || fail signupstate; ok "signup preserves state"

# operator CLI
./machin-idp account-new -handle ops@x -password opspassword -kind human | grep -q '"ok":true' || fail cli-acct; ok "cli account-new"
./machin-idp stats | grep -q '"agents"' || fail cli-stats; ok "cli stats"

# --- custom IDP_KID: JWT header kid + JWKS kid must match ---
PORT2=18799
DB2=$(mktemp -d)/kid.db
export IDP_DB="$DB2" IDP_PUBLIC_URL="http://127.0.0.1:$PORT2" IDP_KID="custom-kid-42"
./machin-idp serve -port $PORT2 2>/dev/null &
SRV2=$!
trap 'kill $SRV2 2>/dev/null || true; kill $SRV 2>/dev/null || true' EXIT
B2="http://127.0.0.1:$PORT2"
for _ in $(seq 1 50); do curl -sf "$B2/_health" >/dev/null 2>&1 && break; sleep 0.1; done
JW2=$(curl -sf "$B2/jwks")
[ "$(echo "$JW2" | J "['keys'][0]['kid']")" = "custom-kid-42" ] || fail kidjwks; ok "custom IDP_KID in JWKS"
C2=$(curl -sf -X POST "$B2/v1/clients" -d '{"name":"kidtest","redirect_uris":"http://127.0.0.1:9998/cb"}')
CID2=$(echo "$C2" | J "['client_id']"); CSEC2=$(echo "$C2" | J "['client_secret']")
curl -sf -X POST "$B2/v1/accounts" -d '{"handle":"kid@example.com","password":"correct-horse-battery","kind":"agent"}' >/dev/null
AUTHQ2="response_type=code&client_id=$CID2&redirect_uri=http%3A%2F%2F127.0.0.1%3A9998%2Fcb&scope=openid&state=kid&nonce=kidn"
LOC_K=$(curl -s -o /dev/null -w '%{redirect_url}' -u 'kid@example.com:correct-horse-battery' "$B2/authorize?$AUTHQ2")
CODE_K=$(echo "$LOC_K" | sed -n 's/.*code=\(ac_[a-f0-9]*\).*/\1/p')
TOK_K=$(curl -sf -X POST "$B2/token" -u "$CID2:$CSEC2" -d "grant_type=authorization_code&code=$CODE_K&redirect_uri=http%3A%2F%2F127.0.0.1%3A9998%2Fcb")
IDT_K=$(echo "$TOK_K" | J "['id_token']")
KID_HDR=$(python3 -c "import json,base64,sys; h=sys.argv[1].split('.')[0]; print(json.loads(base64.urlsafe_b64decode(h+'='*(-len(h)%4)))['kid'])" "$IDT_K")
[ "$KID_HDR" = "custom-kid-42" ] || fail kidjwt; ok "custom IDP_KID in id_token header"
curl -sf "$B2/llms.txt" | grep -qi portier || fail llmsportier; ok "llms.txt mentions portier"
curl -sf "$B2/guide" | grep -q '"portier"' || fail guideportier; ok "guide_json includes portier"

# invalid IDP_ED25519_SEED aborts serve at boot
DB_BOOT=$(mktemp -d)/boot.db
set +e
BOOT_OUT=$(IDP_DB="$DB_BOOT" IDP_PUBLIC_URL="http://127.0.0.1:18888" IDP_ED25519_SEED="not-valid" ./machin-idp serve -port 18888 2>&1)
BOOT_EC=$?
set -e
[ "$BOOT_EC" -eq 1 ] || fail badseedec; ok "invalid IDP_ED25519_SEED exits non-zero at boot"
echo "$BOOT_OUT" | grep -q 'IDP_ED25519_SEED must be exactly 64 hex' || fail badseedmsg; ok "invalid IDP_ED25519_SEED logs fatal reason"

kill $SRV2 2>/dev/null || true
unset IDP_KID
export IDP_DB="$DB" IDP_PUBLIC_URL="http://127.0.0.1:$PORT"

echo "ALL $P TESTS PASSED"
