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

Vulnerability scanners produce long lists of CVEs. Many of those CVEs don't actually affect you — the vendor already confirmed the vulnerable code isn't present, a fix is available, or it's still under investigation. This information is published as VEX (Vulnerability Exploitability eXchange) statements. Red Hat, SUSE, and others publish it as CSAF 2.0 JSON. Red Hat (and others) also publish it as OVAL XML — with different coverage from their CSAF feed.

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
│   │ RH OVAL     │                           │             │
│   │ adapter     │                           │             │
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

## Ingest pipeline

The pipeline is driven by `config.yaml`: a list of adapters (VEX feeds) and alias fetchers (identifier mapping files). Each adapter implements the same `source.Adapter` interface — `Discover`, then `Sync` — so the orchestrator is format-agnostic.

### CSAF adapter

Each CSAF provider publishes a `provider-metadata.json` at a well-known URL. The adapter fetches it, finds the VEX distribution URL, reads `changes.csv`, and enumerates documents since the last-synced watermark.

Parsing uses [`gocsaf/csaf`](https://github.com/gocsaf/csaf) (the strict path) with a permissive map-based fallback for vendor feeds that violate CSAF 2.0 schema rules (SUSE's CPE 2.3 deviations, for example). Extracted per document:

- **Product IDs** from `product_tree.branches` (recursive walk) and `product_tree.relationships` (composite products). Both PURL and CPE identifiers, inherited from both sides of each relationship so platform CPEs end up on composite products.
- **CVE statuses** from `vulnerabilities[].product_status`: `not_affected`, `fixed`, `affected`, `under_investigation`.
- **Justifications** for `not_affected`: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`.

### Red Hat OVAL adapter

Fetches a single OVAL XML file per adapter instance (each OVAL file gets its own config entry). `HEAD` check against `Last-Modified` short-circuits the GET when upstream hasn't regenerated the file. On a pull, the bz2-compressed response is streamed through `compress/bzip2` and parsed via [`getreeldev/oval-to-vex`](https://github.com/getreeldev/oval-to-vex) — a dedicated OVAL-to-VEX translator library maintained alongside reel-vex.

This adapter exists to fill the coverage gap that Red Hat's CSAF feed intentionally leaves: EUS / AUS / E4S / SAP / HA / NFV stream-suffix CPEs (see [SECDATA-1181](https://redhat.atlassian.net/browse/SECDATA-1181)). OVAL has them; CSAF doesn't.

### Alias fetchers

Independent from VEX adapters. Each fetcher pulls a vendor-published mapping file and writes rows into `product_aliases`. The first implementation is Red Hat's `repository-to-cpe.json` — lets a scanner querying with a PURL carrying `?repository_id=rhel-8-for-x86_64-appstream-rpms` match VEX statements keyed on `cpe:/a:redhat:enterprise_linux:8::appstream`.

### Sync strategy

- **First run**: adapters pull their entire feed. CSAF for Red Hat is ~313K per-CVE documents and takes hours; SUSE is ~54K. OVAL is one bz2 file per adapter, seconds to minutes.
- **Incremental**: every adapter stores its own watermark in `adapter_state.last_synced`. CSAF adapters skip documents older than their watermark; OVAL adapters HEAD the feed and skip the GET when unchanged.
- **Batch writes**: statements accumulate in memory and flush to SQLite in batches of 5,000.

### Scheduling

The `serve` command runs ingest automatically on a configurable interval (default 24h). First ingest starts on boot. On-demand ingest is available via `POST /v1/ingest` (requires admin token).

## Data sources

| Vendor | Format | Feed | Documents | Identifiers |
|--------|--------|------|-----------|-------------|
| Red Hat | CSAF VEX | [security.access.redhat.com/data/csaf/v2/vex/](https://security.access.redhat.com/data/csaf/v2/vex/) | ~313K | PURL + CPE |
| Red Hat | OVAL | [security.access.redhat.com/data/oval/v2/](https://security.access.redhat.com/data/oval/v2/) | 1 per stream (EUS/AUS/E4S/…) | CPE (incl. stream variants) |
| SUSE | CSAF VEX | [ftp.suse.com/pub/projects/security/csaf-vex/](https://ftp.suse.com/pub/projects/security/csaf-vex/) | ~54K | CPE |

Alias sources:

| Vendor | File | Purpose |
|--------|------|---------|
| Red Hat | [repository-to-cpe.json](https://security.access.redhat.com/data/metrics/repository-to-cpe.json) | Maps RPM `repository_id` qualifiers → platform CPEs |

### Adding adapters

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

aliases:
  - type: redhat-repository-to-cpe
    id: redhat
    # url: defaults to security.access.redhat.com/data/metrics/repository-to-cpe.json
```

**Adapter types currently registered:**
- `csaf` — any CSAF 2.0 provider (generic)
- `redhat-oval` — Red Hat OVAL (one URL per adapter entry)

**Alias fetcher types currently registered:**
- `redhat-repository-to-cpe` — Red Hat's repository → CPE mapping

Each adapter `id` must be unique across the config (used as the watermark key in `adapter_state`); the `vendor` written onto statements comes from `Adapter.Vendor()`. For CSAF adapters, `Vendor()` returns the same value as `id`. For the Red Hat OVAL adapter, `Vendor()` always returns `redhat` regardless of which OVAL file the adapter targets, so all Red Hat statements (CSAF + OVAL) live under one vendor string and are distinguished by `source_format`.

## Data model

```sql
CREATE TABLE vendors (
    id   TEXT PRIMARY KEY,  -- e.g. "redhat", "suse"
    name TEXT NOT NULL      -- e.g. "Red Hat"
);

CREATE TABLE adapter_state (
    adapter_id  TEXT PRIMARY KEY,  -- unique per adapter instance
    feed_url    TEXT,              -- canonical upstream URL
    last_synced TEXT,              -- RFC3339; newest upstream data absorbed
    updated     TEXT NOT NULL      -- RFC3339; last time we wrote this row
);

CREATE TABLE statements (
    vendor        TEXT NOT NULL,   -- from Adapter.Vendor()
    cve           TEXT NOT NULL,
    product_id    TEXT NOT NULL,   -- full PURL or CPE
    base_id       TEXT NOT NULL,   -- normalized base for indexing
    version       TEXT,
    id_type       TEXT NOT NULL,   -- "purl" or "cpe"
    status        TEXT NOT NULL,   -- not_affected, fixed, affected, under_investigation
    justification TEXT,            -- for not_affected only
    updated       TEXT NOT NULL,   -- RFC3339 from the upstream advisory
    source_format TEXT NOT NULL DEFAULT 'csaf',  -- "csaf" | "oval"
    PRIMARY KEY (vendor, cve, product_id, source_format)
);

CREATE TABLE product_aliases (
    vendor     TEXT NOT NULL,
    source_ns  TEXT NOT NULL,      -- e.g. "repository_id"
    source_id  TEXT NOT NULL,      -- e.g. "rhel-8-for-x86_64-appstream-rpms"
    target_ns  TEXT NOT NULL,      -- e.g. "cpe"
    target_id  TEXT NOT NULL,      -- e.g. "cpe:/a:redhat:enterprise_linux:8::appstream"
    confidence REAL NOT NULL DEFAULT 1.0,
    updated    TEXT NOT NULL,
    PRIMARY KEY (vendor, source_ns, source_id, target_ns, target_id)
);
```

A `schema_version` table tracks migrations. The DB is forward-migrated on every binary boot; rollback is manual (restore from a pre-upgrade backup).

## Resolver

At query time, user-supplied product identifiers get expanded into candidate base IDs that are matched against `statements.base_id`. Three expansion rules apply:

1. **Direct**: the base form of the input (PURL stripped of `@version` + qualifiers; CPE as-is).
2. **via_alias**: for PURLs carrying a `repository_id=` qualifier, the CPEs stored in `product_aliases` for that repository.
3. **via_cpe_prefix**: for CPE inputs, the first 5 CPE 2.2 URI parts (`part:vendor:product:version:update`) with trailing variants dropped. Implements Red Hat's [SECDATA-1220](https://redhat.atlassian.net/browse/SECDATA-1220) matching contract.

Each returned statement carries a `match_reason` field (`direct`, `via_alias`, `via_cpe_prefix`) so consumers can see which rule fired. Stronger reasons win when the same candidate is produced by multiple rules.

## API

Base URL: `https://vex.getreel.dev`. Full field-level reference — including all enum values, `match_reason` precedence, and the opt-in OpenVEX 0.2.0 format — lives in [`docs/api.md`](./docs/api.md).

### Look up a CVE

```bash
curl https://vex.getreel.dev/v1/cve/CVE-2021-44228
```

```json
{
  "statements": [
    {
      "vendor": "redhat",
      "cve": "CVE-2021-44228",
      "product_id": "pkg:rpm/redhat/log4j",
      "id_type": "purl",
      "status": "not_affected",
      "justification": "vulnerable_code_not_present",
      "updated": "2026-04-01T16:43:13Z",
      "source_format": "csaf"
    }
  ]
}
```

### Batch resolve

Match CVEs against product IDs. The resolver expands each input before matching. Optional `source_formats` filters by upstream format.

```bash
curl -X POST https://vex.getreel.dev/v1/resolve \
  -H "Content-Type: application/json" \
  -d '{
    "cves": ["CVE-2021-44228"],
    "products": ["pkg:rpm/redhat/log4j@2.14.0?repository_id=rhel-8-for-x86_64-appstream-rpms"],
    "source_formats": ["csaf"]
  }'
```

Each returned statement includes `match_reason` so callers can tell a direct hit from an alias-driven one:

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

### Upload SBOM

Upload a CycloneDX SBOM. The service extracts components + vulnerabilities, resolves through the translation layer, and returns the SBOM annotated with VEX analysis.

```bash
curl -X POST https://vex.getreel.dev/v1/sbom \
  -H "Content-Type: application/json" \
  -d @sbom.json
```

Each vulnerability with a matching vendor statement gets an `analysis` field:

```json
{
  "id": "CVE-2021-44228",
  "analysis": {
    "state": "not_affected",
    "justification": "code_not_present",
    "detail": "redhat: not_affected (vulnerable_code_not_present)"
  }
}
```

When multiple vendors have statements for the same CVE, the most actionable status wins (`not_affected` > `fixed` > `under_investigation` > `affected`), with all vendors listed in `detail`.

### Coverage stats

```bash
curl https://vex.getreel.dev/v1/stats
```

```json
{
  "vendors": 2,
  "cves": 31247,
  "statements": 2183441,
  "aliases": 12298,
  "last_updated": "2026-04-17T06:00:00Z"
}
```

`aliases` counts rows in `product_aliases`; the website displays this as "Product mappings".

### Ingest status

```bash
curl https://vex.getreel.dev/v1/ingest
curl -X POST https://vex.getreel.dev/v1/ingest \
  -H "Authorization: Bearer your-admin-token"
```

## Project structure

```
reel-vex/
  cmd/server/main.go           -- entry point; registers adapters + fetchers
  pkg/
    csaf/                      -- CSAF 2.0 parsing primitives (strict + permissive)
      provider.go, feed.go, extract.go, extract_permissive.go, purl.go
    source/                    -- source-adapter framework
      adapter.go               -- Adapter interface
      config.go, registry.go   -- AdapterConfig + factory registry
      csafadapter/             -- CSAF adapter (wraps pkg/csaf)
      redhatoval/              -- Red Hat OVAL adapter (wraps oval-to-vex)
    aliases/                   -- alias-fetcher framework
      aliases.go               -- Fetcher interface + registry
      redhat.go                -- Red Hat repository-to-cpe.json fetcher
    resolver/                  -- query-time identifier expansion
      cpe.go                   -- CPE 2.2 5-part prefix
      resolver.go              -- direct / via_alias / via_cpe_prefix
    ingest/ingest.go           -- orchestrator (adapters → statements; fetchers → aliases)
    db/                        -- SQLite + schema migrations
      db.go, migrations.go
    api/                       -- HTTP handlers
      handler.go, sbom.go, ingest.go
  test/integration/api_test.go -- end-to-end tests (binary + DB + HTTP)
  testdata/                    -- fixtures: CSAF slices, OVAL fixture, alias sample
  config.yaml                  -- adapter + alias-fetcher configuration
  Dockerfile                   -- golang:1.26-alpine → alpine:3.21
```

**Companion library**: [`getreeldev/oval-to-vex`](https://github.com/getreeldev/oval-to-vex) — standalone Go library that parses Red Hat OVAL XML and emits VEX-shaped statements. Zero dependencies beyond stdlib. reel-vex's RH OVAL adapter delegates to it; anyone else building scanners can `go get github.com/getreeldev/oval-to-vex/translator`.

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
# Build the binary
go build -o reel-vex ./cmd/server

# Ingest (useful for first population or testing)
./reel-vex -config config.yaml -db vex.db ingest

# Limit to N statements per adapter (dev convenience)
./reel-vex -config config.yaml -db vex.db -limit 100 ingest

# Start the server (runs ingest automatically on schedule)
./reel-vex -config config.yaml -db vex.db serve

# All flags
./reel-vex \
  -config config.yaml \
  -db vex.db \
  -addr :8080 \
  -ingest-interval 24h \
  -admin-token your-secret-token \
  serve

# Query the local database
./reel-vex -db vex.db query CVE-2021-44228
./reel-vex -db vex.db stats
```

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
2. **New OVAL sources.** Each new OVAL source means: extending `oval-to-vex` with a `translator.FromXOVAL()` for that vendor (Ubuntu, Debian, SUSE), plus a new adapter package under `pkg/source/xoval/`.
3. **New alias mappings.** Vendor-published identifier translation files (similar to Red Hat's `repository-to-cpe.json`) plug into `pkg/aliases/` as new `Fetcher` implementations.

For other formats (upstream `.vex/` repos, OCI attestations, OpenVEX files), open an issue to discuss before implementing.

## License

Apache 2.0
