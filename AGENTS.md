# machin-idp — agent notes

OIDC identity provider in machin. Principals = humans OR agents; headless login
(HTTP Basic on /authorize) + a form. EdDSA (Ed25519) id_tokens + JWKS. The identity
behind portier's "Login with intrane".

- Build: `./build.sh`. Test: `./test.sh` (88 assertions incl. EdDSA-verify-against-jwks, headless+form login, redirect_uri token check, nonce/kid/name claims). Keep green.
- JWT: EdDSA via ed25519_sign(seed,msg); JWKS = OKP/Ed25519 pubkey (ed25519_pub(seed)). base64url = base64_encode_bytes + translate +/->-_ strip =. Passwords = pbkdf2_sha256(bytes,bytes,60000,32).
- MFL gotcha hit: one type per var name per scope — a `range` loop var `r` (string) collided with `r := issue_code_redirect(...)` (struct) in handle_authorize_login → "string vs struct". Renamed.
- MFL gotcha: `&&` / `||` evaluate both operands — never `aok == 1 && verify_password(...)` on a maybe-empty AccountRow; nest the `if` instead (segfault on unknown handle).
- Stored JSON columns: emit via struct parse, not json_get (double-encodes) — same as relais/portier.
- Security: auth codes one-time + 10min TTL; access tokens 1h; redirect_uri exact-match per client (open-redirect guard); client_secret + account password stored HASHED (sha256 for client secret, pbkdf2 for passwords).
- **IDP_ED25519_SEED is IRREPLACEABLE** (losing it invalidates all tokens + breaks JWKS trust) — back up with the DB. env /etc/machin-idp/idp.env 640.
- NOT peage-metered (it's Javier's own free IdP infra; portier does the per-auth metering). Deploy: dk1 /opt/machin-idp, systemd :8798, hotify idp.intrane.fr.
- Dogfood proven: portier client cid_06149ff79342cab4; provider kind=oidc name=intrane; full Login-with-intrane chain live (agent headless).
