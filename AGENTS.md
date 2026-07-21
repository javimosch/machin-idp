# machin-idp — agent notes

OIDC identity provider in machin. Principals = humans OR agents; headless login
(HTTP Basic on /authorize) + a form. EdDSA (Ed25519) id_tokens + JWKS.

**Product story (OSS):** self-host under any brand. Docs on GitHub Pages
(`docs/` → https://javimosch.github.io/machin-idp/). Do **not** market any
`*.intrane.fr` host as a free/public IdP for this project.

- Build: `./build.sh`. Test: `./test.sh` (keep green; count drifts with coverage PRs).
- JWT: EdDSA via ed25519_sign(seed,msg); JWKS = OKP/Ed25519 pubkey (ed25519_pub(seed)). base64url = base64_encode_bytes + translate +/->-_ strip =. Passwords = pbkdf2_sha256(bytes,bytes,60000,32).
- MFL gotcha hit: one type per var name per scope — a `range` loop var `r` (string) collided with `r := issue_code_redirect(...)` (struct) in handle_authorize_login → "string vs struct". Renamed.
- MFL gotcha: `&&` / `||` evaluate both operands — never `aok == 1 && verify_password(...)` on a maybe-empty AccountRow; nest the `if` instead (segfault on unknown handle).
- Stored JSON columns: emit via struct parse, not json_get (double-encodes) — same as relais/portier.
- Security: auth codes one-time + 10min TTL; access tokens 1h; redirect_uri exact-match per client (open-redirect guard); client_secret + account password stored HASHED (sha256 for client secret, pbkdf2 for passwords).
- **IDP_ED25519_SEED is IRREPLACEABLE** (losing it invalidates all tokens + breaks JWKS trust) — back up with the DB.
- **Private operator deploy (not public product):** dk1 `/opt/machin-idp`, env `/etc/machin-idp/idp.env` 640, systemd `:8798`, hotify host for operator use via portier (or direct). NOT peage-metered; portier meters when used as a broker. Dogfood: portier client `cid_06149ff79342cab4`; provider name `intrane`.
