<p align="center">
  <img src="./docs/logo-light.svg#gh-light-mode-only" alt="Reel Logo" width="80" height="80">
  <img src="./docs/logo.svg#gh-dark-mode-only" alt="Reel Logo" width="80" height="80">
</p>

<h1 align="center"><samp>reel</samp> vex</h1>

<p align="center">
  <strong>Free, open source VEX resolution service.</strong>
  <br>
  Aggregates vendor VEX statements from CSAF 2.0 feeds into a single SQLite database and serves them via HTTP API.
  <br><br>
  <a href="https://getreel.dev/vex">Web UI</a> · API <code>vex.getreel.dev</code>
</p>

## Why

Vulnerability scanners produce long lists of CVEs. Many of those CVEs don't actually affect you — the vendor already confirmed the vulnerable code isn't present, or a fix is available, or it's still under investigation. This information is published as VEX (Vulnerability Exploitability eXchange) statements in CSAF 2.0 feeds, but it's scattered across vendor sites in hundreds of thousands of individual JSON documents.

reel-vex does the aggregation work: it downloads, parses, and normalizes these feeds into a single queryable database. You query by CVE, by product ID, or by uploading an entire SBOM.

## How it works

```
                  config.yaml
                      |
                      v
    +---------------------------------+
    |         Ingest Pipeline          |
    |                                  |
    |  For each provider:              |
    |    1. Fetch provider-metadata    |
    |    2. Discover VEX feed URL      |
    |    3. Parse changes.csv          |
    |    4. Download CSAF documents    |
    |    5. Extract product IDs,       |
    |       CVEs, statuses             |
    |    6. Upsert into SQLite         |
    +---------------------------------+
                      |
                      v
                  +---------+
                  | SQLite  |
                  | vex.db  |
                  +---------+
                      |
                      v
    +---------------------------------+
    |           HTTP API               |
    |                                  |
    |  GET  /v1/cve/{id}              |
    |  POST /v1/resolve               |
    |  POST /v1/sbom                  |
    |  GET  /v1/stats                 |
    |  GET  /v1/ingest   (status)     |
    |  POST /v1/ingest   (trigger)    |
    |  GET  /healthz                  |
    +---------------------------------+
```

Single Go binary. Single SQLite file. No external dependencies at runtime.

## Ingest pipeline

The ingest pipeline is the core of the project. It pulls VEX data from CSAF 2.0 providers and writes it to SQLite.

### CSAF discovery

Each provider publishes a `provider-metadata.json` at a well-known URL. The pipeline fetches it, finds the VEX distribution URL, then reads `changes.csv` to enumerate documents.

### Document parsing

CSAF documents are parsed using the [`gocsaf/csaf`](https://github.com/gocsaf/csaf) library (the same one Trivy uses). From each document, the pipeline extracts:

- **Product IDs** from `product_tree.branches` (recursive walk to leaf nodes) and `product_tree.relationships` (composite products). Both PURL and CPE identifiers are stored.
- **CVE statuses** from `vulnerabilities[].product_status`: `known_not_affected`, `fixed`, `known_affected`, `under_investigation`.
- **Justifications** from `vulnerabilities[].flags[].label`: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`.

The parser handles any valid CSAF 2.0 document, not just a specific vendor's structure.

### Sync strategy

- **First run**: downloads every document listed in `changes.csv`. For Red Hat (~313K documents), this takes hours.
- **Incremental**: stores the timestamp of the newest processed document. On subsequent runs, only fetches documents newer than that timestamp.
- **Batch writes**: statements are accumulated in memory and flushed to SQLite in batches of 5,000.

### Scheduling

The `serve` command runs ingest automatically on a configurable interval (default 24h). First ingest starts on boot. On-demand ingest is available via `POST /v1/ingest` (requires admin token).

## Data sources

| Vendor | Feed | Documents | Product IDs | Status |
|--------|------|-----------|-------------|--------|
| Red Hat | [CSAF VEX](https://security.access.redhat.com/data/csaf/v2/vex/) | 313K | PURL + CPE | Active, daily updates |
| SUSE | [CSAF VEX](https://ftp.suse.com/pub/projects/security/csaf-vex/) | 54K | CPE | Active, daily updates |

### Adding a new provider

Add an entry to `config.yaml`:

```yaml
providers:
  - id: redhat
    name: Red Hat
    url: https://security.access.redhat.com/data/csaf/v2/provider-metadata.json
  - id: suse
    name: SUSE
    url: https://www.suse.com/.well-known/csaf/provider-metadata.json
  - id: your-vendor
    name: Your Vendor
    url: https://example.com/.well-known/csaf/provider-metadata.json
```

Requirements for a provider:
- Must publish a CSAF 2.0 `provider-metadata.json`
- Must have a VEX distribution (not just security advisories)
- Must include `changes.csv` for incremental sync
- Must update regularly

The pipeline handles the rest: discovery, download, parsing, and storage.

## Data model

```sql
CREATE TABLE vendors (
    id          TEXT PRIMARY KEY,     -- e.g. "redhat", "suse"
    name        TEXT NOT NULL,        -- e.g. "Red Hat"
    feed_url    TEXT NOT NULL,        -- discovered VEX feed URL
    last_synced TEXT                  -- RFC3339, for incremental sync
);

CREATE TABLE statements (
    vendor        TEXT NOT NULL,
    cve           TEXT NOT NULL,
    product_id    TEXT NOT NULL,      -- PURL or CPE
    id_type       TEXT NOT NULL,      -- "purl" or "cpe"
    status        TEXT NOT NULL,      -- not_affected, fixed, affected, under_investigation
    justification TEXT,               -- only for not_affected
    updated       TEXT NOT NULL,
    PRIMARY KEY (vendor, cve, product_id)
);
```

## API

Base URL: `https://vex.getreel.dev`

### Look up a CVE

```bash
curl https://vex.getreel.dev/v1/cve/CVE-2024-6387
```

```json
{
  "statements": [
    {
      "vendor": "redhat",
      "cve": "CVE-2024-6387",
      "product_id": "pkg:rpm/redhat/openssh@8.7p1-38.el9_4.1",
      "id_type": "purl",
      "status": "not_affected",
      "justification": "vulnerable_code_not_present",
      "updated": "2024-07-01T00:00:00Z"
    }
  ]
}
```

### Batch resolve

Match CVEs against product IDs (PURL or CPE). Returns only statements where both match.

```bash
curl -X POST https://vex.getreel.dev/v1/resolve \
  -H "Content-Type: application/json" \
  -d '{
    "cves": ["CVE-2024-6387"],
    "products": ["pkg:rpm/redhat/openssh@8.7p1"]
  }'
```

### Upload SBOM

Upload a CycloneDX SBOM. The service extracts components and vulnerabilities, resolves them against the database, and returns the SBOM annotated with VEX analysis.

```bash
curl -X POST https://vex.getreel.dev/v1/sbom \
  -H "Content-Type: application/json" \
  -d @sbom.json
```

Each vulnerability with a matching vendor statement gets an `analysis` field added:

```json
{
  "id": "CVE-2024-6387",
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

### Ingest status

```bash
# Check ingest status
curl https://vex.getreel.dev/v1/ingest

# Trigger ingest (requires admin token)
curl -X POST https://vex.getreel.dev/v1/ingest \
  -H "Authorization: Bearer your-admin-token"
```

## Project structure

```
reel-vex/
  cmd/server/main.go         -- entry point: serve, ingest, stats, query commands
  pkg/
    csaf/
      provider.go             -- fetch + parse provider-metadata.json
      feed.go                 -- parse changes.csv, enumerate documents
      extract.go              -- traverse product_tree, extract (product_id, CVE, status)
      extract_test.go         -- tests with real Red Hat + SUSE document samples
    db/
      db.go                   -- SQLite: open, migrate, upsert, query
    ingest/
      ingest.go               -- orchestrator: provider -> feed -> fetch -> extract -> db
    api/
      handler.go              -- HTTP handlers
      sbom.go                 -- SBOM upload + CycloneDX annotation
      ingest.go               -- ingest runner: scheduler, on-demand trigger, status
      handler_test.go         -- unit tests
  test/integration/
    api_test.go               -- end-to-end tests (builds binary, seeds DB, hits HTTP)
  config.yaml                 -- provider configuration
  Dockerfile                  -- multi-stage build (golang:1.26-alpine -> alpine:3.21)
```

## Run locally

```bash
# Build
go build -o reel-vex ./cmd/server

# Run ingest manually (useful for first population or testing)
./reel-vex -config config.yaml -db vex.db ingest

# Limit to N documents per provider (useful for testing)
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

# Query the local database directly
./reel-vex -db vex.db query CVE-2024-6387
./reel-vex -db vex.db stats
```

### Docker

```bash
docker build -t reel-vex .
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/data:/data \
  -v $(pwd)/config.yaml:/config.yaml:ro \
  reel-vex \
  -db /data/vex.db \
  -config /config.yaml \
  -admin-token your-secret-token \
  serve
```

## Tests

```bash
# Unit tests
go test ./...

# Integration tests (builds binary, seeds DB, starts server, tests all endpoints)
go test -tags integration ./test/integration/
```

## Contributing

The most impactful contribution is adding new CSAF VEX providers. If a vendor publishes CSAF 2.0 VEX feeds:

1. Verify the provider has a `provider-metadata.json` with a VEX distribution
2. Confirm it has `changes.csv` and updates regularly
3. Add it to `config.yaml`
4. Run `./reel-vex -config config.yaml -db vex.db -limit 10 ingest` to test
5. Open a PR

For other feed formats (upstream `.vex/` repos, OCI attestations), open an issue to discuss before implementing.

## License

Apache 2.0
