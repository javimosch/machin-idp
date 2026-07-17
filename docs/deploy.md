# Deploy — dk1

Live at **https://idp.intrane.fr** -> 127.0.0.1:8798 (hotify/Traefik TLS).
- `/opt/machin-idp/machin-idp` (dir owned dk1), `/opt/machin-idp/data.db` (WAL)
- `/etc/machin-idp/idp.env` (640): IDP_DB, IDP_PUBLIC_URL, **IDP_ED25519_SEED** (the signing
  key — IRREPLACEABLE: losing it invalidates every issued token and breaks JWKS trust;
  back it up alongside the DB), IDP_KID
- systemd `machin-idp.service` :8798

## Update
```sh
./build.sh && ./test.sh
scp machin-idp dk1:/tmp/machin-idp
ssh dk1 'sudo install -m0755 /tmp/machin-idp /opt/machin-idp/machin-idp && sudo systemctl restart machin-idp && sleep 1 && curl -sf 127.0.0.1:8798/_health'
```
