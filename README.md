<p align="center">
  <img src="./docs/logo-light.svg#gh-light-mode-only" alt="Reel Logo" width="80" height="80">
  <img src="./docs/logo.svg#gh-dark-mode-only" alt="Reel Logo" width="80" height="80">
</p>

<h1 align="center"><samp>reel</samp> vex</h1>

<p align="center">
  <strong>Free, open-source VEX service.</strong>
  <br>
  Aggregates vendor VEX statements (CSAF 2.0, OVAL, OpenVEX) into one database and serves them over an HTTP API.
  <br><br>
  <a href="https://getreel.dev/vex">Web UI</a> · API <code>vex.getreel.dev</code> · <a href="./docs/api.md">API reference</a>
</p>

## What it does

Scanners report many CVEs that don't actually affect you — the vendor has often already assessed them and published a **VEX** statement: `not_affected`, `fixed`, `affected`, or `under_investigation`. But every vendor uses a different format, location, and identifier scheme.

reel-vex pulls those statements from Red Hat, SUSE, Ubuntu, and Debian into one database, bridges identifier schemes (PURL ↔ CPE), and serves the result over HTTP. We mirror what the vendor said and let you decide what to do with it — no pre-filtering.

## What you can ask it

- A **CVE** (and optionally some packages) → the vendor statements for it.
- A **package list or SBOM with no CVEs** → every vendor statement touching those packages (*broad mode*). Fetch once, reuse on every scan.
- A **CycloneDX SBOM** → the same SBOM annotated with vendor verdicts, ready for `trivy --vex`.

Request and response shapes are in [`docs/api.md`](./docs/api.md).

## How it works

```
   Vendor feeds                  reel-vex                  You
   ────────────            ┌──────────────────┐      ────────────
   Red Hat · SUSE          │ pull · normalize │       query a CVE,
   Ubuntu · Debian   ────► │ one SQLite file  │ ────► a package, or
   CSAF·OVAL·OpenVEX       │ HTTP API         │       a full SBOM
                           └──────────────────┘
```

One Go binary, one SQLite file, no runtime dependencies. The PURL ↔ CPE bridge means a query with a package identifier still matches statements a vendor filed against a platform identifier.

Deeper detail: [`docs/architecture.md`](./docs/architecture.md) (pipeline + layout), [`docs/data-model.md`](./docs/data-model.md) (schema), [`docs/api.md`](./docs/api.md) (every endpoint).

## Data sources

| Vendor | Format | Feed | Identifiers |
|--------|--------|------|-------------|
| Red Hat | CSAF VEX | [security.access.redhat.com/data/csaf/v2/vex/](https://security.access.redhat.com/data/csaf/v2/vex/) | PURL + CPE |
| Red Hat | OVAL | [security.access.redhat.com/data/oval/v2/](https://security.access.redhat.com/data/oval/v2/) | CPE (incl. stream variants) |
| SUSE | CSAF VEX | [ftp.suse.com/pub/projects/security/csaf-vex/](https://ftp.suse.com/pub/projects/security/csaf-vex/) | CPE |
| Ubuntu | OpenVEX 0.2.0 | [security-metadata.canonical.com/vex/](https://security-metadata.canonical.com/vex/) | PURL (`pkg:deb/ubuntu/…?distro=…`) |
| Ubuntu | OVAL | [security-metadata.canonical.com/oval/](https://security-metadata.canonical.com/oval/) | PURL (`pkg:deb/ubuntu/…?distro=…`) |
| Debian | OVAL | [www.debian.org/security/oval/](https://www.debian.org/security/oval/) | PURL (`pkg:deb/debian/…?distro=…`) |

Ubuntu has two feeds on purpose: the OpenVEX feed is broad, the OVAL feed covers ~10% of package-name shapes the OpenVEX feed spells differently. They aren't strict supersets, so we keep both.

## Run it yourself

### Docker

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

The database lives in the mounted `data/` directory, so it survives restarts. First boot ingests everything (Red Hat seeds from a bulk archive in minutes; Ubuntu and SUSE take longer). Scheduled runs after that fetch only what changed. Images: `getreel/vex-hub:latest`, `:v0`, or a pinned `:<version>`.

### From source

```bash
go build -o reel-vex ./cmd/server
./reel-vex -config config.yaml -db vex.db serve
```

Flags (`--help` for all): `-addr`, `-ingest-interval`, `-admin-token`, `-sbom-max-mb`, `-statements-max`. Query a local DB without the server: `./reel-vex -db vex.db query CVE-2021-44228`, `./reel-vex -db vex.db stats`.

## Adding a source

`config.yaml` lists `adapters:` (data sources) and `aliases:` (identifier-translation files). Registered adapter types: `csaf`, `redhat-oval`, `ubuntu-oval`, `debian-oval`, `ubuntu-vex`. The adapter-author guide and per-source quirks are in [`docs/architecture.md`](./docs/architecture.md).

## Tests

```bash
go test ./...                                    # unit + package (no network)
go test -tags integration ./test/integration/   # builds binary, seeds DB, hits HTTP
```

Adapters are tested against committed fixtures over `httptest`, so no network is needed.

## Contributing

Most useful: new CSAF providers (a `config.yaml` entry), new OVAL sources (a `translator.FromXOVAL()` in the sibling `oval-to-vex` repo + a small adapter), and new alias mappings. For other formats, open an issue first.

## License

Apache 2.0
