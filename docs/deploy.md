# Deploy

Self-host: build the binary, set `IDP_PUBLIC_URL` / `IDP_ED25519_SEED`, put a reverse
proxy in front. Public product docs: https://javimosch.github.io/machin-idp/

## Update (generic)

```sh
./build.sh && ./test.sh
# install the binary wherever you run it, then restart the service
```

Env: `IDP_DB`, `IDP_PUBLIC_URL`, **`IDP_ED25519_SEED`** (signing key — IRREPLACEABLE:
losing it invalidates every issued token and breaks JWKS trust; back it up alongside the
DB), `IDP_KID`.

## Operator note (private)

A private operator instance may run on dk1 (`/opt/machin-idp`, systemd `:8798`). That host
is **not** a public Intrane IdP product — keep it out of OSS marketing. Details for agents
working that host live in `AGENTS.md`.
