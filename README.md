<p align="center">
  <img src="./docs/logo-light.svg#gh-light-mode-only" alt="Reel Logo" width="80" height="80">
  <img src="./docs/logo.svg#gh-dark-mode-only" alt="Reel Logo" width="80" height="80">
</p>

<h1 align="center"><samp>reel</samp> vex</h1>

<p align="center">
  <strong>Free, open source VEX resolution service.</strong>
  <br>
  Aggregates vendor VEX statements from CSAF 2.0 and OVAL feeds, translates across identifier schemes (PURL ↔ CPE), and serves the result via HTTP API.
  <br><br>
  <a href="https://getreel.dev/vex">Web UI</a> · API <code>vex.getreel.dev</code> · <a href="./docs/api.md">API reference</a>
</p>

## Why

Vulnerability scanners produce long lists of CVEs. Many of those CVEs don't actually affect you — the vendor already confirmed the vulnerable code isn't present, a fix is available, or it's still under investigation. This information is published as VEX (Vulnerability Exploitability eXchange) statements. Red Hat and SUSE publish it as CSAF 2.0 JSON; Red Hat, Ubuntu, and Debian publish it as OVAL XML. Red Hat publishes both formats with intentionally different coverage between them.

reel-vex pulls from both formats, normalizes the statements into one database, and bridges identifier schemes so a scanner querying with a package PURL matches statements vendors published against a platform CPE. One query, unified answer.

## How it works

```
     config.yaml
         │
         ▼
┌──────────────────────────────────────────────────────────┐
│                  Ingest Pipeline                          │
│                                                           │
│   Adapters                           Alias fetchers       │
│   ────────                           ──────────────       │
│   ┌─────────────┐                    ┌──────────────┐     │
│   │ CSAF adapter│                    │ repo → CPE   │     │
│   │ (RH, SUSE)  │                    │ (Red Hat)    │     │
│   └──────┬──────┘                    └──────┬───────┘     │
│          │                                  │             │
│   ┌──────┴──────┐                           │             │
│   │ OVAL        │                           │             │
│   │ adapters    │                           │             │
│   └──────┬──────┘                           │             │
│          │                                  │             │
│          ▼                                  ▼             │
│   statements + adapter_state         product_aliases      │
└──────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────┐
│                    SQLite  vex.db                         │
│  statements  │ vendors │ product_aliases │ adapter_state  │
└──────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────┐
│                        HTTP API                           │
│                                                           │
│  GET  /v1/cve/{id}                                        │
│  POST /v1/resolve        (with optional source_formats)   │
│  POST /v1/sbom           (annotates CycloneDX with VEX)   │
│  GET  /v1/stats                                           │
│  GET  /v1/ingest         (status) ·  POST /v1/ingest      │
│  GET  /healthz                                            │
│                                                           │
│      Resolver: PURL ↔ CPE translation + CPE prefix match  │
└──────────────────────────────────────────────────────────┘
```

Single Go binary. Single SQLite file. No external dependencies at runtime.

For deeper reading: the ingest pipeline and project layout live in [`docs/architecture.md`](./docs/architecture.md), the database schema in [`docs/data-model.md`](./docs/data-model.md), and the field-level API reference (every endpoint, every enum value, OpenVEX 0.2.0 output) in [`docs/api.md`](./docs/api.md).

## Data sources

| Vendor | Format | Feed | Documents | Identifiers |
|--------|--------|------|-----------|-------------|
| Red Hat | CSAF VEX | [security.access.redhat.com/data/csaf/v2/vex/](https://security.access.redhat.com/data/csaf/v2/vex/) | ~313K | PURL + CPE |
| Red Hat | OVAL | [security.access.redhat.com/data/oval/v2/](https://security.access.redhat.com/data/oval/v2/) | 1 per stream (EUS/AUS/E4S/…) | CPE (incl. stream variants) |
| SUSE | CSAF VEX | [ftp.suse.com/pub/projects/security/csaf-vex/](https://ftp.suse.com/pub/projects/security/csaf-vex/) | ~54K | CPE |
| Ubuntu | OVAL | [security-metadata.canonical.com/oval/](https://security-metadata.canonical.com/oval/) | 1 per LTS release (focal / jammy / noble) | PURL (`pkg:deb/ubuntu/<name>?distro=ubuntu-<v>`) |
| Debian | OVAL | [www.debian.org/security/oval/](https://www.debian.org/security/oval/) | 1 per release (bullseye / bookworm / trixie) | PURL (`pkg:deb/debian/<name>?distro=debian-<n>`) |

Alias sources:

| Vendor | File | Purpose |
|--------|------|---------|
| Red Hat | [repository-to-cpe.json](https://security.access.redhat.com/data/metrics/repository-to-cpe.json) | Maps RPM `repository_id` qualifiers → platform CPEs |

## Adding adapters

`config.yaml` has two top-level lists, `adapters:` and `aliases:`:

```yaml
adapters:
  - type: csaf
    id: redhat
    name: Red Hat
    url: https://security.access.redhat.com/data/csaf/v2/provider-metadata.json
  - type: csaf
    id: suse
    name: SUSE
    url: https://www.suse.com/.well-known/csaf/provider-metadata.json
  - type: redhat-oval
    id: redhat-oval-rhel-9.6-eus
    url: https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.6-eus.oval.xml.bz2
  - type: ubuntu-oval
    id: ubuntu-oval-noble
    name: Ubuntu 24.04 LTS
    url: https://security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2
  - type: debian-oval
    id: debian-oval-bookworm
    name: Debian 12 (bookworm)
    url: https://www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2

aliases:
  - type: redhat-repository-to-cpe
    id: redhat
    # url: defaults to security.access.redhat.com/data/metrics/repository-to-cpe.json
```

**Adapter types currently registered:**
- `csaf` — any CSAF 2.0 provider (generic)
- `redhat-oval` — Red Hat OVAL (one URL per adapter entry)
- `ubuntu-oval` — Canonical USN OVAL (one URL per LTS release)
- `debian-oval` — Debian Security Tracker OVAL (one URL per release)

**Alias fetcher types currently registered:**
- `redhat-repository-to-cpe` — Red Hat's repository → CPE mapping

Each adapter `id` must be unique across the config (used as the watermark key in `adapter_state`); the `vendor` written onto statements comes from `Adapter.Vendor()`. For CSAF adapters, `Vendor()` returns the same value as `id`. For OVAL adapters, `Vendor()` returns the canonical vendor name (`redhat`, `ubuntu`, `debian`) regardless of which OVAL file the adapter targets, so all statements from one vendor live under one vendor string and are distinguished by `source_format` and (for deb-shaped products) the `?distro=` qualifier on `product_id`.

## Resolver

At query time, user-supplied product identifiers get expanded into candidate base IDs that are matched against `statements.base_id`. Three expansion rules apply:

1. **Direct**: the base form of the input (PURL stripped of `@version` + qualifiers; CPE as-is).
2. **via_alias**: for PURLs carrying a `repository_id=` qualifier, the CPEs stored in `product_aliases` for that repository.
3. **via_cpe_prefix**: for CPE inputs, the first 5 CPE 2.2 URI parts (`part:vendor:product:version:update`) with trailing variants dropped. Implements Red Hat's [SECDATA-1220](https://redhat.atlassian.net/browse/SECDATA-1220) matching contract.

Each returned statement carries a `match_reason` field (`direct`, `via_alias`, `via_cpe_prefix`) so consumers can see which rule fired. Stronger reasons win when the same candidate is produced by multiple rules.

## API

Base URL: `https://vex.getreel.dev`. Full field-level reference — every endpoint, every enum value, the opt-in OpenVEX 0.2.0 format — lives in [`docs/api.md`](./docs/api.md).

Quick batch resolve:

```bash
curl -X POST https://vex.getreel.dev/v1/resolve \
  -H "Content-Type: application/json" \
  -d '{
    "cves": ["CVE-2021-44228"],
    "products": ["pkg:rpm/redhat/log4j@2.14.0?repository_id=rhel-8-for-x86_64-appstream-rpms"]
  }'
```

```json
{
  "statements": [
    {
      "vendor": "redhat",
      "cve": "CVE-2021-44228",
      "product_id": "cpe:/a:redhat:enterprise_linux:8::appstream",
      "status": "not_affected",
      "source_format": "csaf",
      "match_reason": "via_alias"
    }
  ]
}
```

See [`docs/api.md`](./docs/api.md) for `/v1/cve/{id}`, `/v1/sbom`, `/v1/stats`, `/v1/ingest`, the OpenVEX output format, and the full field reference.

## Run it yourself

### Docker (recommended)

Prebuilt images are published to Docker Hub on every release, scanned for vulnerabilities before publishing (see `.github/workflows/release.yml`):

- `getreel/vex-hub:<version>` — pinned to a specific release (e.g. `v0.2.0`)
- `getreel/vex-hub:v0` — latest in the 0.x series
- `getreel/vex-hub:latest` — latest release

Minimal run:

```bash
docker run -d \
  --name vex-hub \
  --restart unless-stopped \
  -p 8080:8080 \
  -v $(pwd)/data:/data \
  -v $(pwd)/config.yaml:/config.yaml:ro \
  getreel/vex-hub:latest \
  -db /data/vex.db \
  -config /config.yaml \
  -admin-token your-secret-token \
  serve
```

The SQLite database lives in the mounted `data/` directory so it survives container restarts. First boot runs a full ingest (hours for Red Hat's CSAF; minutes for OVAL adapters); subsequent scheduled runs are incremental.

### From source

```bash
go build -o reel-vex ./cmd/server
./reel-vex -config config.yaml -db vex.db serve
```

`-addr`, `-ingest-interval`, `-admin-token`, and `-limit` are also available; `./reel-vex --help` for the full list. `./reel-vex -db vex.db query CVE-2021-44228` and `./reel-vex -db vex.db stats` query a local database without starting the server.

## Tests

```bash
# Unit + package tests
go test ./...

# Integration tests (builds binary, seeds DB, hits HTTP)
go test -tags integration ./test/integration/
```

All adapters have httptest-backed tests serving committed fixtures, so the test suite doesn't require network access.

## Contributing

The most impactful contributions:

1. **New CSAF providers.** If a vendor publishes CSAF 2.0 VEX feeds with a `provider-metadata.json` + `changes.csv`, add an entry to `config.yaml` under `adapters:` and open a PR.
2. **New OVAL sources.** Each new OVAL source means: extending `oval-to-vex` with a `translator.FromXOVAL()` for that vendor, plus a new adapter package under `pkg/source/xoval/`.
3. **New alias mappings.** Vendor-published identifier translation files (similar to Red Hat's `repository-to-cpe.json`) plug into `pkg/aliases/` as new `Fetcher` implementations.

For other formats (upstream `.vex/` repos, OCI attestations, OpenVEX files), open an issue to discuss before implementing.

## License

Apache 2.0
