# machin-idp × portier — OIDC broker integration

[machin-idp](https://github.com/javimosch/machin-idp) is an open-source OIDC identity
provider. [portier](https://github.com/javimosch/portier) is an authentication broker that
can front it (same pattern as GitHub/Google OIDC).

## Architecture

```
App  →  portier (OIDC client)  →  machin-idp (OIDC provider)
         ↑ callback URL              ↑ discovery + JWKS (EdDSA)
```

Register machin-idp as a generic OIDC provider (`kind=oidc`). Humans get the sign-in form;
agents authenticate **headlessly** with HTTP Basic on `/authorize`.

## 1. Register an OIDC client for your broker

Each portier deployment needs a client on machin-idp whose `redirect_uris` includes
portier's OAuth callback URL (e.g. `https://your-portier.example/cb/my-idp`).

```sh
export IDP=http://127.0.0.1:8798   # your machin-idp base URL
curl -s -X POST "$IDP/v1/clients" \
  -d '{"name":"portier","redirect_uris":"https://your-portier.example/cb/my-idp"}'
# → {"client_id":"cid_…","client_secret":"csec_…"}   # save the secret — shown once
```

## 2. Configure portier

| Setting | Value |
|---------|-------|
| Provider kind | `oidc` |
| Provider name | e.g. `my-idp` (display label in your app) |
| Issuer / discovery | `$IDP/.well-known/openid-configuration` |
| Client ID | `cid_…` from step 1 |
| Client secret | `csec_…` from step 1 |
| Redirect URI | must match exactly what you registered on machin-idp |

portier reads `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, and
`jwks_uri` from discovery. id_tokens are **EdDSA (Ed25519)** — verify against
`$IDP/jwks` (OKP key, not RSA).

## 3. Register principals (humans and agents)

```sh
curl -s -X POST "$IDP/v1/accounts" \
  -d '{"handle":"agent@example.com","password":"correct-horse-battery","kind":"agent"}'
```

- **`kind=human`** — browser users; portier redirects them to machin-idp's sign-in form.
- **`kind=agent`** — headless automation; authenticate with HTTP Basic on `/authorize`.

Users can also self-register via the signup form on `/authorize` if you leave that open.

## 3.1 Scope

Request `openid` in the `scope` parameter to receive an `id_token`. `email` and `profile` are optional and control which claims are returned. A token exchange for a scope without `openid` (for example `email` only) returns an `access_token` but no `id_token`.

## 3.2 `redirect_uri` exact-match

machin-idp rejects any `redirect_uri` that is not an exact match with one of the comma-separated values registered for the client. Protocol, host, port, path, and trailing slashes all matter — keep the callback URL in portier identical to the value registered in `/v1/clients`.

## 3.3 PKCE

machin-idp supports PKCE (`code_challenge` / `code_verifier`) for the authorization-code flow. Send `code_challenge_method=S256` on `/authorize` and include the matching `code_verifier` at `/token`. `plain` is also accepted, but `S256` is recommended. Portier can use this to harden the code exchange.

## 4. Flows

### Human (via portier)

1. User starts login in your app (brokered by portier).
2. portier redirects to `$IDP/authorize?…` (standard OIDC code flow).
3. User signs in on the machin-idp form → redirect back to portier's callback with `code`.
4. portier exchanges the code at `/token` → `{access_token, id_token, …}`.
5. portier validates the `id_token` against `/jwks` and establishes the session.

### Agent (headless)

```sh
curl -si "$IDP/authorize?response_type=code&client_id=cid_…&redirect_uri=…&scope=openid%20email&state=x" \
  -u 'agent@example.com:correct-horse-battery'
# → 302 Location: …?code=ac_…
```

```sh
curl -s -X POST "$IDP/token" -u 'cid_…:csec_…' \
  -d 'grant_type=authorization_code&code=ac_…&redirect_uri=…'
```

## Claims / JWKS

| Claim | Notes |
|-------|-------|
| `iss` | Issuer (`IDP_PUBLIC_URL`) |
| `sub` | Stable account id |
| `aud` | Client id |
| alg | `EdDSA` (Ed25519 OKP in JWKS) |

`state` and `nonce` are optional but recommended. `state` is echoed back to the `redirect_uri` unchanged; `nonce` is included in the `id_token` payload when `openid` is requested.

## 5. Validating EdDSA id_tokens

portier should verify the `id_token` against the Ed25519 public key in `$IDP/jwks` (`kty=OKP`, `crv=Ed25519`, `alg=EdDSA`). The signature covers the `header.payload` bytes.

```python
import json, base64, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def b64u(s): return base64.urlsafe_b64decode(s + '='*(-len(s)%4))

IDP = "http://127.0.0.1:8798"
idt = "..."  # id_token from /token
jwks = json.loads(urllib.request.urlopen(f"{IDP}/jwks").read())
kid = json.loads(b64u(idt.split('.')[0]))["kid"]
key = next(k for k in jwks["keys"] if k["kid"] == kid)
h, p, s = idt.split('.')
Ed25519PublicKey.from_public_bytes(b64u(key["x"])).verify(b64u(s), (h + '.' + p).encode())
```

| Scope requested | Claims in `id_token` |
|-----------------|----------------------|
| `openid` | `iss`, `sub`, `aud`, `iat`, `exp` |
| `openid email` | + `email` (the principal's handle) |
| `openid profile` | + `name` |
| `openid email profile` | + `email` and `name` |
| `email`, `profile` (no `openid`) | no `id_token`; only `access_token` |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Discovery/JWKS 404 | Wrong base URL | Match `IDP_PUBLIC_URL` / issuer exactly |
| redirect_uri mismatch | Callback not registered | Exact string match on client `redirect_uris` |
| id_token verify fails | Wrong JWKS / seed rotated | Keep `IDP_ED25519_SEED` backed up with the DB |

## Example portier provider payload

```json
{
  "kind": "oidc",
  "name": "my-idp",
  "display_name": "Login with my IdP",
  "discovery_url": "http://127.0.0.1:8798/.well-known/openid-configuration",
  "client_id": "cid_…",
  "client_secret": "csec_…"
}
```

See also: [GitHub Pages docs](https://javimosch.github.io/machin-idp/) · [README](../README.md).
