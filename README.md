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

reel-vex pulls those statements from Red Hat, SUSE, Rancher, Ubuntu, and Debian into one database, bridges identifier schemes (PURL ↔ CPE), and serves the result over HTTP. We mirror what the vendor said and let you decide what to do with it — no pre-filtering.

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
   Ubuntu · Debian   ────► │ Postgres-backed  │ ────► a package, or
   CSAF·OVAL·OpenVEX       │ HTTP API         │       a full SBOM
                           └──────────────────┘
```

A Go API service backed by PostgreSQL. The PURL ↔ CPE bridge means a query with a package identifier still matches statements a vendor filed against a platform identifier.

Deeper detail: [`docs/architecture.md`](./docs/architecture.md) (pipeline + layout), [`docs/data-model.md`](./docs/data-model.md) (schema), [`docs/api.md`](./docs/api.md) (every endpoint).

## Data sources

| Vendor | Format | Feed | Identifiers |
|--------|--------|------|-------------|
| Red Hat | CSAF VEX | [security.access.redhat.com/data/csaf/v2/vex/](https://security.access.redhat.com/data/csaf/v2/vex/) | PURL + CPE |
| Red Hat | OVAL | [security.access.redhat.com/data/oval/v2/](https://security.access.redhat.com/data/oval/v2/) | CPE (incl. stream variants) |
| SUSE | CSAF VEX | [ftp.suse.com/pub/projects/security/csaf-vex/](https://ftp.suse.com/pub/projects/security/csaf-vex/) | CPE |
| Rancher (SUSE) | OpenVEX 0.2.0 | [github.com/rancher/vexhub](https://github.com/rancher/vexhub) | PURL (image / Go-module-scoped) |
| Ubuntu | OpenVEX 0.2.0 | [security-metadata.canonical.com/vex/](https://security-metadata.canonical.com/vex/) | PURL (`pkg:deb/ubuntu/…?distro=…`) |
| Ubuntu | OVAL | [security-metadata.canonical.com/oval/](https://security-metadata.canonical.com/oval/) | PURL (`pkg:deb/ubuntu/…?distro=…`) |
| Debian | OVAL | [www.debian.org/security/oval/](https://www.debian.org/security/oval/) | PURL (`pkg:deb/debian/…?distro=…`) |

Ubuntu has two feeds on purpose: the OpenVEX feed is broad, the OVAL feed covers ~10% of package-name shapes the OpenVEX feed spells differently. They aren't strict supersets, so we keep both.

Rancher's feed is **product-scoped**: each `not_affected` is about a specific image or Go module (the *scope*), with the affected package in an OpenVEX subcomponent. reel-vex stores the package as the queryable identifier and the image/module as the row's scope, and only applies a scoped verdict when the caller names that product (the `scopes` field on `/v1/statements`, or an SBOM's root component on `/v1/analyze`) — so a suppression scoped to one image never hides the same package elsewhere.

## Run it yourself

reel-vex stores its data in **PostgreSQL**. The simplest single-box setup is the bundled Docker Compose — the app plus its database:

```bash
cp .env.example .env          # set POSTGRES_PASSWORD
cp /path/to/config.yaml .     # your adapter list (never baked into the image)
docker compose up -d
```

The DB lives in the `pgdata` volume, so it survives restarts. First boot ingests everything (Red Hat seeds from a bulk archive; Ubuntu and SUSE take longer); scheduled runs after that fetch only what changed. For a **managed/cloud Postgres**, drop the `postgres` service from `docker-compose.yml` and point `-db` at the external DSN. For **Kubernetes** (N read-only API replicas + a single ingest worker), use the Helm chart.

### From source

```bash
go build -o reel-vex ./cmd/server
./reel-vex -config config.yaml -db 'postgres://user:pass@host:5432/vex?sslmode=disable' serve
```

`-db` takes a Postgres connection URL. Run `./reel-vex --help` for all flags. Local one-off queries against a running DB: `./reel-vex -db '<dsn>' query CVE-2021-44228`, `./reel-vex -db '<dsn>' stats`.

### Limits

The public hub at `vex.getreel.dev` is breadth- and size-limited because it's a single shared instance. **Your own instance has no such constraint** — every limit is a flag, so set them to whatever your hardware allows (or effectively off):

| Flag | Default | Bounds |
|------|---------|--------|
| `-sbom-max-mb` | 10 | request body size (MB) for `/v1/analyze` and `/v1/statements` |
| `-analyze-max-cves` | 500 | distinct CVEs one `/v1/analyze` may query before a 400 |
| `-statements-max` | 50000 | rows `/v1/statements` returns (0 = unlimited) |
| `-query-timeout` | 20s | hard ceiling on a single DB query (over-broad request → 503) |
| `-max-sbom-components` | 50000 | components in an inbound SBOM |
| `-max-sbom-vulns` | 10000 | vulnerabilities in an inbound SBOM |
| `-max-statements-items` | 10000 | items in the `cves`/`products` arrays on `/v1/statements` |
| `-max-user-vex-statements` | 25000 | flattened user-VEX statements per `/v1/analyze` |
| `-ingest-interval` | 24h | how often feeds are re-pulled |

The HTTP write timeout auto-tracks `-query-timeout`, so raising the query ceiling won't cut a long response short.

## Adding a source

`config.yaml` lists `adapters:` (data sources) and `aliases:` (identifier-translation files). Registered adapter types: `csaf`, `redhat-oval`, `ubuntu-oval`, `debian-oval`, `ubuntu-vex`, `rancher-vex`. The adapter-author guide and per-source quirks are in [`docs/architecture.md`](./docs/architecture.md).

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
