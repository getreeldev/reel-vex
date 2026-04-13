# reel-vex

Free, open source VEX resolution service. Query vendor VEX statements by CVE, batch resolve against product IDs, or upload a CycloneDX SBOM to get it annotated with exploitability data.

Live at **[vex.getreel.dev](https://vex.getreel.dev)** | Web UI at **[getreel.dev/vex](https://getreel.dev/vex)**

## What it does

Vendors publish VEX (Vulnerability Exploitability eXchange) statements declaring whether a CVE actually affects their products. This service aggregates those statements from CSAF 2.0 feeds and makes them queryable via a simple API.

Instead of triaging every CVE manually, check if the vendor already confirmed it's not exploitable.

## Data sources

| Vendor | Documents | Product IDs | Updated |
|--------|-----------|-------------|---------|
| Red Hat | 313K | PURL + CPE | Daily |
| SUSE | 54K | CPE | Daily |

More vendors added as they publish CSAF VEX feeds.

## API

Base URL: `https://vex.getreel.dev`

### Look up a CVE

```bash
curl https://vex.getreel.dev/v1/cve/CVE-2024-6387
```

Returns all vendor statements for that CVE:

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

Match a list of CVEs against a list of product IDs (PURL or CPE):

```bash
curl -X POST https://vex.getreel.dev/v1/resolve \
  -H "Content-Type: application/json" \
  -d '{
    "cves": ["CVE-2024-6387"],
    "products": ["pkg:rpm/redhat/openssh@8.7p1"]
  }'
```

### Upload SBOM

Upload a CycloneDX SBOM and get it back with VEX annotations on each vulnerability:

```bash
curl -X POST https://vex.getreel.dev/v1/sbom \
  -H "Content-Type: application/json" \
  -d @sbom.json
```

Each vulnerability with a matching vendor statement gets an `analysis` field:

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

### Coverage stats

```bash
curl https://vex.getreel.dev/v1/stats
```

## Run locally

```bash
# Build
go build -o reel-vex ./cmd/server

# Ingest VEX feeds (first run downloads all documents, takes hours for Red Hat)
./reel-vex -config config.yaml -db vex.db ingest

# Start the API server (runs ingest on schedule automatically)
./reel-vex -config config.yaml -db vex.db serve

# With options
./reel-vex \
  -config config.yaml \
  -db vex.db \
  -addr :8080 \
  -ingest-interval 24h \
  -admin-token your-secret-token \
  serve
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
  serve
```

## Configuration

```yaml
# config.yaml
providers:
  - id: redhat
    name: Red Hat
    url: https://security.access.redhat.com/data/csaf/v2/provider-metadata.json
  - id: suse
    name: SUSE
    url: https://www.suse.com/.well-known/csaf/provider-metadata.json
```

The service discovers feed URLs from each provider's `provider-metadata.json`. The config only points to the entry point.

## Tests

```bash
# Unit tests
go test ./...

# Integration tests (builds binary, starts server, hits real HTTP endpoints)
go test -tags integration ./test/integration/
```

## License

Apache 2.0
