# Docker Registry CA Certificate

Place **ONLY** the public CA certificate (`registry-ca.crt`) in this directory so the v2.3 installer scripts can install it into `/etc/docker/certs.d/103.19.110.148:5000/ca.crt` without using `insecure-registries`.

## What belongs here
- `registry-ca.crt` — Public CA certificate (`-----BEGIN CERTIFICATE-----`), safe to publish in this repository.

## What MUST NEVER be placed here
- `ca.key` (CA private key)
- `server.key` (Registry TLS private key)
- `server.crt`, `*.csr`, `*.srl` (Registry server cert and signing artifacts)

## Optional SHA-256 Pinning
After generating and publishing `certs/registry-ca.crt`, compute its SHA-256 digest:

```bash
sha256sum certs/registry-ca.crt
```

and set `REGISTRY_CA_SHA256` to that 64-character hex string in both `installation-script-2.3.sh` and `id_installation-script-2.3.sh`.
