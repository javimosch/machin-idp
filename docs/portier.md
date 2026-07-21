# machin-idp × portier — Login with intrane

[machin-idp](https://github.com/javimosch/machin-idp) is the OIDC identity provider behind
portier's **Login with intrane**. [portier](https://github.com/javimosch/portier) is the
authentication broker in the intrane stack (alongside [péage](https://peage.intrane.fr) and
[relais](https://github.com/javimosch/relais)).

## Architecture

```
App  →  portier (OIDC client)  →  machin-idp (OIDC provider)
         ↑ callback URL              ↑ discovery + JWKS (EdDSA)
```

portier registers machin-idp as a generic OIDC provider (`kind=oidc`). Humans get the
sign-in form; agents authenticate **headlessly** with HTTP Basic on `/authorize`.

## 1. Register an OIDC client for portier

Each portier deployment needs a client on machin-idp whose `redirect_uris` includes
portier's OAuth callback URL.

```sh
curl -s -X POST https://idp.intrane.fr/v1/clients \
  -d '{"name":"portier","redirect_uris":"https://portier.example/cb"}'
# → {"client_id":"cid_…","client_secret":"csec_…"}   # save the secret — shown once
```

**Dogfood (production intrane):** portier uses client `cid_06149ff79342cab4` against
`https://idp.intrane.fr`. Do not commit live secrets; configure them in portier's env.

## 2. Configure portier

Point portier at machin-idp's discovery document:

| Setting | Value |
|---------|-------|
| Provider kind | `oidc` |
| Provider name | `intrane` (display: "Login with intrane") |
| Issuer / discovery | `https://idp.intrane.fr/.well-known/openid-configuration` |
| Client ID | `cid_…` from step 1 |
| Client secret | `csec_…` from step 1 |
| Redirect URI | must match exactly what you registered on machin-idp |

portier reads `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, and
`jwks_uri` from discovery. id_tokens are **EdDSA (Ed25519)** — verify against
`https://idp.intrane.fr/jwks` (OKP key, not RSA).

## 3. Register principals (humans and agents)

Before anyone can log in, create an account on machin-idp:

```sh
curl -s -X POST https://idp.intrane.fr/v1/accounts \
  -d '{"handle":"agent@example.com","password":"correct-horse-battery","kind":"agent"}'
```

- **`kind=human`** — browser users; portier redirects them to machin-idp's sign-in form.
- **`kind=agent`** — headless automation; authenticate with HTTP Basic on `/authorize`.

Users can also self-register during "Login with intrane" via the signup form on
`/authorize` (no separate registration step).

## 4. Flows

### Human (via portier UI)

1. User clicks "Login with intrane" in your app (brokered by portier).
2. portier redirects to `https://idp.intrane.fr/authorize?…` (standard OIDC code flow).
3. User signs in on the machin-idp form → redirect back to portier's callback with `code`.
4. portier exchanges the code at `/token` (client-authenticated) → `{access_token, token_type: Bearer, expires_in: 3600, scope, id_token}`.
5. portier validates the `id_token` against `/jwks` and establishes the session.

### Agent (headless)

Agents skip the browser form. Send HTTP Basic credentials directly to machin-idp's
`/authorize` (portier may proxy this, or the agent talks to the IdP upstream):

```sh
curl -si "https://idp.intrane.fr/authorize?response_type=code&client_id=cid_…&redirect_uri=…&scope=openid%20email&state=x" \
  -u 'agent@example.com:correct-horse-battery'
# → 302 Location: redirect_uri?code=ac_…&state=x
```

Then exchange the code (same as any OIDC client):

```sh
curl -s -X POST https://idp.intrane.fr/token \
  -u 'cid_…:csec_…' \
  -d 'grant_type=authorization_code&code=ac_…&redirect_uri=…'
```

The `redirect_uri` in the token request **must match** the one used in `/authorize`
(OAuth security requirement, enforced by machin-idp).

## 5. id_token claims

EdDSA JWT with header `{alg:"EdDSA", typ:"JWT", kid:"idp-ed25519-1"}` and payload:

| Claim | Description |
|-------|-------------|
| `iss` | Issuer (`IDP_PUBLIC_URL`, e.g. `https://idp.intrane.fr`) |
| `sub` | Principal ID (`u_…`) |
| `aud` | Client ID (`cid_…`) |
| `iat` / `exp` | Issued / expiry (1 h) |
| `email` | Handle (email-like) |
| `name` | Display name |
| `nonce` | Present when supplied in the authorize request |

Verify signature with the Ed25519 public key from `/jwks` (`kty: OKP`, `crv: Ed25519`).

`/userinfo` also returns `kind` (`human` or `agent`) so portier or downstream apps can
distinguish browser users from headless agents.

## 6. Security notes

- Auth codes: one-time, 10 min TTL.
- Access tokens: 1 h TTL; call `/userinfo` with `Authorization: Bearer …`.
- Redirect URIs: exact match per client (open-redirect guard).
- Headless Basic failures: rate-limited per IP (60/min); `401` with `WWW-Authenticate: Basic realm="intrane"`, then `429` when exceeded.
- Form login failures: same rate limit per IP (60/min); `429` with an error form when exceeded. Successful form login is not rate-limited.
- Token endpoint client auth failures: rate-limited per IP (60/min); `401 invalid_client`, then `429 too_many_requests`.
- Self-service signup (`POST /authorize/signup`): rate-limited per IP (30/h); `429` with an error page when exceeded.
- API registration: `POST /v1/accounts` rate-limited per IP (30/h); `POST /v1/clients` rate-limited per IP (20/h).
- **`IDP_ED25519_SEED`**: 64 hex chars, irreplaceable — back up with the DB (see [deploy.md](deploy.md)).
- **`IDP_KID`**: optional JWT/JWKS key id (default `idp-ed25519-1`); must be alphanumeric plus `.`, `_`, `-` — quotes or JSON metacharacters abort boot.

## 7. Local smoke test

```sh
./build.sh && ./test.sh   # 102 assertions incl. portier-relevant OIDC checks
```

## 8. Troubleshooting (portier + machin-idp)

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| id_token verification fails | Expecting RSA/RS256 | machin-idp signs **EdDSA (Ed25519)** only — fetch `/jwks` (OKP key, not RSA) |
| `invalid_grant` at `/token` | `redirect_uri` mismatch or omitted | The `redirect_uri` in the token request must **exact match** the one used in `/authorize`; omitting it also returns `invalid_grant` |
| Headless agent gets `401` | Wrong Basic credentials or unknown handle | Use `Authorization: Basic` with `handle:password`; failures return `401` + `WWW-Authenticate: Basic realm="intrane"` (same shape for unknown handles — no enumeration). An empty `Authorization: Basic` header (no credentials) also returns `401`, not the browser form. |
| Headless agent gets `429` | Rate limit (60 failed Basic attempts/min per IP) | Wait one minute or use correct credentials (success path is not rate-limited) |
| `/token` returns `429 too_many_requests` | Rate limit (60 failed client auth attempts/min per IP) | Wait one minute; valid client credentials still work after the window |
| Form login loops with "invalid credentials" | Wrong password or rate limit (60/min per IP) | Same rate-limit window as headless Basic; check password and wait if throttled |
| `429 too many registrations` on `POST /v1/accounts` | API registration rate limit (30/h per IP) | Wait one hour or register via operator CLI (`machin-idp account-new`) |
| `429 too many clients` on `POST /v1/clients` | Client registration rate limit (20/h per IP) | Wait one hour or use operator CLI (`machin-idp client-new`) |
| Signup form shows "too many sign-ups" | Self-service signup rate limit (30/h per IP) | Wait one hour or create the account via `POST /v1/accounts` / operator CLI |
| `unknown client_id` | Client not registered on machin-idp | `POST /v1/clients` with the exact callback URL portier uses |
| Discovery/JWKS 404 | Wrong base URL | Use `IDP_PUBLIC_URL` / issuer exactly (e.g. `https://idp.intrane.fr`) |

## 9. Example portier provider config

Minimal OIDC provider block for portier (env or config — adjust URLs/secrets):

```json
{
  "kind": "oidc",
  "name": "intrane",
  "display_name": "Login with intrane",
  "discovery_url": "https://idp.intrane.fr/.well-known/openid-configuration",
  "client_id": "cid_…",
  "client_secret": "csec_…",
  "redirect_uri": "https://portier.example/cb"
}
```

portier fetches discovery, validates EdDSA `id_token` signatures against `/jwks`, and
proxies human users to the machin-idp sign-in form. Agents authenticate headlessly with
HTTP Basic on `/authorize` upstream (or via portier if configured to forward credentials).

See also [README.md](../README.md) and live discovery at
[https://idp.intrane.fr/.well-known/openid-configuration](https://idp.intrane.fr/.well-known/openid-configuration).
