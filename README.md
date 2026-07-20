# machin-idp — Login with intrane, for humans and agents

An **OIDC identity provider for the agent era**. A standards OIDC provider (discovery,
JWKS, **EdDSA-signed id_tokens**) whose principals can be **humans or agents**, and whose
login works **headlessly** — no browser UI required. Your apps offer "Login with intrane"
instead of "Login with Google". One static [machin (MFL)](https://github.com/javimosch/machin) binary — EdDSA JWTs, PBKDF2 passwords, no RSA, no runtime.

Live: **https://idp.intrane.fr** · [`/.well-known/openid-configuration`](https://idp.intrane.fr/.well-known/openid-configuration) · [`/llms.txt`](https://idp.intrane.fr/llms.txt)

## Register a principal + a client

```sh
# a principal — human or agent
curl -s -X POST https://idp.intrane.fr/v1/accounts \
  -d '{"handle":"agent7@example.com","password":"correct-horse-battery","kind":"agent"}'

# an OIDC client (your app; or point portier at it)
curl -s -X POST https://idp.intrane.fr/v1/clients \
  -d '{"name":"my app","redirect_uris":"https://myapp/cb"}'
# -> {client_id, client_secret}
```

## Login — headless for agents, a form for humans

```sh
# agent: HTTP Basic on /authorize returns the auth code, no browser
curl -si "https://idp.intrane.fr/authorize?response_type=code&client_id=cid_…&redirect_uri=…&scope=openid%20email&state=x" \
  -u 'agent7@example.com:correct-horse-battery'
# -> 302 Location: …?code=ac_…

# exchange it (client-authenticated) for an EdDSA id_token + access_token
curl -s -X POST https://idp.intrane.fr/token -u 'cid_…:csec_…' \
  -d 'grant_type=authorization_code&code=ac_…&redirect_uri=…'
```

A human hitting `/authorize` without credentials gets a minimal sign-in form instead.
Verify the `id_token` against [`/jwks`](https://idp.intrane.fr/jwks) (Ed25519 OKP), or
call `/userinfo` with the access token.

## Plugs into portier

Register machin-idp as a generic OIDC provider in [portier](https://github.com/javimosch/portier)
and your apps get "Login with intrane" through the same broker they use for Google/GitHub.
**Step-by-step integration:** [docs/portier.md](docs/portier.md) (client registration, discovery,
EdDSA JWKS, human vs agent flows, dogfood client `cid_06149ff79342cab4`).
The intrane agent-web stack: **[péage](https://peage.intrane.fr)** (pay) ·
**[relais](https://github.com/javimosch/relais)** (receive) · **[portier](https://github.com/javimosch/portier)** (authenticate) · **machin-idp** (the identity behind it).

## Why EdDSA

A real IdP signs id_tokens asymmetrically so any client verifies against the JWKS
without a shared secret. machin has no RSA — but it has **Ed25519** (`ed25519_sign` /
`ed25519_pub`), and JWT's `EdDSA` alg is exactly that. Modern, 32-byte keys, pure MFL.
Independently verified: the id_tokens pass Python `cryptography`'s Ed25519 check.

## Build & run

```sh
./build.sh    # -> ./machin-idp
./test.sh     # 59 assertion OIDC e2e incl. EdDSA-verify-against-jwks, headless + form login
```

Env: `IDP_DB` · `IDP_PUBLIC_URL` · `IDP_ED25519_SEED` (64 hex — the signing key; set in
prod, back it up) · `IDP_KID`.

## Scope

v1 is an OIDC provider (authorization-code flow). Passwords are PBKDF2-HMAC-SHA256.
SAML federation and RS256 are out of scope (machin has no RSA — see [machin#484](https://github.com/javimosch/machin/issues/484)); EdDSA covers OIDC fully.

## Feedback

```sh
machin-idp feedback "headless login returned 401 with a valid password" -kind bug -context "agent principal, Basic auth on /authorize"
```

Dual-writes: to machin-idp's own `POST /v1/feedback` (stored locally) **and**, best-effort, to
a central relay so one inbox spans every intrane CLI. Open intake — no token, 16 KB cap,
idempotent on a client-supplied id. `FEEDBACK_RELAY` retargets the relay (`off` disables);
`IDP_URL`/`IDP_PUBLIC_URL` retarget the app endpoint. Follows the [cli-feedback-spec](https://github.com/javimosch/cli-feedback-spec) convention
(reference relay: [machin-feedback](https://github.com/javimosch/machin-feedback)).
