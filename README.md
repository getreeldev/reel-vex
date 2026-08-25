<p align="center">
  <img src="./docs/logo-light.svg#gh-light-mode-only" alt="Reel Logo" width="80" height="80">
  <img src="./docs/logo.svg#gh-dark-mode-only" alt="Reel Logo" width="80" height="80">
</p>

<h1 align="center"><samp>reel</samp> vex</h1>

<p align="center">
  <strong>The free, open-source VEX hub.</strong>
  <br>
  Aggregates vendor VEX statements (CSAF 2.0, OVAL, OpenVEX) into one database and serves them over an HTTP API.
  <br><br>
  <a href="https://getreel.dev/vex">Web UI</a> · API <code>vex.getreel.dev</code> · <a href="./docs/api.md">API reference</a>
</p>

## What it does

Scanners report many CVEs that don't affect the product they were found in. The vendor has often already assessed the CVE and published a **VEX** statement saying so: `not_affected`, `fixed`, `affected`, or `under_investigation`. Each vendor publishes in a different format, at a different location, under a different identifier scheme.

reel-vex pulls those statements from Red Hat, SUSE, Rancher, Ubuntu, Debian, Alpine, Amazon Linux, AlmaLinux, and Oracle Linux into one database, bridges identifier schemes (PURL ↔ CPE), and serves the result over HTTP. Statements are mirrored as the vendor published them; nothing is filtered out by status.

## What it answers

- A **CVE**, optionally narrowed by packages → the vendor statements for it.
- A **package list or SBOM carrying no CVEs** → every vendor statement touching those packages (*broad mode*). The result is CVE-independent, so one document covers repeated scans of the same image.
- A **CycloneDX SBOM** → the same SBOM annotated with vendor verdicts, in the shape `trivy --vex` consumes.

Request and response shapes are in [`docs/api.md`](./docs/api.md).

## How it works

```
  vendor feeds                  reel-vex                     queries answered
  ────────────                  ────────                     ────────────────

  Red Hat    CSAF, OVAL    ┌────────────────────────┐   a CVE
  SUSE       CSAF          │ fetch                  │     → the vendor statements
  Rancher    OpenVEX       │   per feed, scheduled; │       filed against it
  Ubuntu     OpenVEX, OVAL │   incremental after    │
  Debian     OVAL     ────►│   the first run        ├─► a package list or SBOM
  Alpine     secdb         │                        │     → every statement touching
  Amazon     updateinfo    │ normalize              │       those packages, no CVE
  AlmaLinux  OVAL          │   one OpenVEX 0.2.0    │       filter (broad mode)
  Oracle     OVAL          │   shape; identifiers   │
                           │   bridged PURL → CPE   │   a CycloneDX SBOM
                           │                        │     → the same SBOM, annotated
                           │ store    PostgreSQL    │       in place with verdicts
                           │ serve    HTTP API      │
                           └────────────────────────┘
```

A Go service backed by PostgreSQL. Ingest runs on a schedule and writes normalized statements; the API reads them. The identifier bridge is what lets a query carrying a package identifier match a statement the vendor filed against a platform identifier.

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
| Alpine | secdb | [secdb.alpinelinux.org](https://secdb.alpinelinux.org/) | PURL (`pkg:apk/alpine/…?distro=alpine-<major.minor>`) |
| Amazon Linux | updateinfo | [alas.aws.amazon.com](https://alas.aws.amazon.com/) (repo `updateinfo.xml`) | PURL (`pkg:rpm/amazon/…?distro=amazon-<major>`) |
| AlmaLinux | OVAL | [security.almalinux.org/oval/](https://security.almalinux.org/oval/) | PURL (`pkg:rpm/almalinux\|alma/…?distro=almalinux-<major>`) |
| Oracle Linux | OVAL | [linux.oracle.com/security/oval/](https://linux.oracle.com/security/oval/) | PURL (`pkg:rpm/oracle/…?distro=oracle-<major>`) |

Ubuntu has two feeds on purpose: the OpenVEX feed is broad, the OVAL feed covers ~10% of package-name shapes the OpenVEX feed spells differently. They aren't strict supersets of each other, so both are kept.

Rancher's feed is **product-scoped**: each `not_affected` is about a specific image or Go module (the *scope*), with the affected package in an OpenVEX subcomponent. reel-vex stores the package as the queryable identifier and the image/module as the row's scope, and only applies a scoped verdict when the caller names that product (the `scopes` field on `/v1/statements`, or an SBOM's root component on `/v1/analyze`) — so a suppression scoped to one image never hides the same package elsewhere.

### Attribution & data licensing

reel-vex redistributes each vendor's published data, transformed into OpenVEX (the *mirror model*); every statement carries its origin (`vendor` + `source_format` + `status_notes` provenance). Sources and their licenses are listed in [`NOTICE.md`](./NOTICE.md). In particular, **Alpine's secdb is licensed [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)** — reel-vex's Alpine-derived statements are a transformed adaptation, attributed to [Alpine Linux](https://secdb.alpinelinux.org/) and redistributed under the same CC BY-SA 4.0 license; **AlmaLinux** errata data is MIT-licensed; the remaining feeds are redistributed under their respective vendors' terms.

## Run it yourself

reel-vex stores its data in **PostgreSQL**. The simplest single-box setup is the bundled Docker Compose — the app plus its database:

```bash
cp .env.example .env          # set POSTGRES_PASSWORD
cp /path/to/config.yaml .     # the adapter list (never baked into the image)
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

The public hub at `vex.getreel.dev` is breadth- and size-limited because it's a single shared instance. A self-hosted instance has no such constraint — every limit is a flag, and can be raised to whatever the hardware allows, or switched off:

| Flag | Default | Bounds |
|------|---------|--------|
| `-sbom-max-mb` | 10 | request body size (MB) for `/v1/analyze` and `/v1/statements` |
| `-analyze-max-cves` | 10000 | distinct CVEs one `/v1/analyze` may query before a 400 |
| `-statements-max` | 50000 | rows `/v1/statements` returns (0 = unlimited) |
| `-query-timeout` | 20s | hard ceiling on a single DB query (over-broad request → 503) |
| `-max-sbom-components` | 50000 | components in an inbound SBOM |
| `-max-sbom-vulns` | 10000 | vulnerabilities in an inbound SBOM |
| `-max-statements-items` | 10000 | items in the `cves`/`products` arrays on `/v1/statements` |
| `-max-user-vex-statements` | 25000 | flattened user-VEX statements per `/v1/analyze` |
| `-ingest-interval` | 24h | how often feeds are re-pulled |

The HTTP write timeout tracks `-query-timeout`, so raising the query ceiling does not truncate a long response.

## Adding a source

`config.yaml` lists `adapters:` (data sources) and `aliases:` (identifier-translation files). Registered adapter types: `csaf`, `redhat-oval`, `ubuntu-oval`, `debian-oval`, `ubuntu-vex`, `rancher-vex`, `alpine-secdb`, `amazon-alas`, `almalinux-oval`, `oracle-oval`. The adapter-author guide and per-source quirks are in [`docs/architecture.md`](./docs/architecture.md).

## Tests

```bash
go test ./...                                    # unit + package (no network)
go test -tags integration ./test/integration/   # builds binary, seeds DB, hits HTTP
```

Adapters are tested against committed fixtures over `httptest`, so no network is needed.

## Contributing

Most useful: new CSAF providers (a `config.yaml` entry), new OVAL sources (a `translator.FromXOVAL()` in the sibling `oval-to-vex` repo + a small adapter), and new alias mappings. For other formats, open an issue first.

## License

Apache 2.0 — see [`LICENSE`](./LICENSE). Vendor-data attribution and licensing is in [`NOTICE.md`](./NOTICE.md).
