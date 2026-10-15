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

  Red Hat    CSAF          ┌────────────────────────┐   a CVE
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

The DB lives in the `pgdata` volume, so it survives restarts. First boot ingests everything (Red Hat seeds from a bulk archive; Ubuntu and SUSE take longer); scheduled runs after that fetch only what changed, except Amazon Linux and Rancher, which re-read their whole feed every run. For a **managed/cloud Postgres**, drop the `postgres` service from `docker-compose.yml` and point `-db` at the external DSN. For **several API replicas** behind a load balancer, start them with `-no-scheduler` so they only serve, and run ingest from one place — one `serve` with its scheduler, or the `ingest` subcommand on a schedule (a CronJob, say).

**One ingest at a time.** An ingest holds a Postgres advisory lock for its whole run. A second one against the same database — a CronJob's `ingest` while a `serve` scheduler is mid-run, or a manual `ingest` beside `serve` — touches nothing and refuses with `another ingest is running` (the `ingest` subcommand exits non-zero). The lock ends with the holder's database session, so a crashed process never leaves it behind.

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
| `-sweep-max-fraction` | 0.2 | share of an adapter's rows (or CVEs, for a withdrawal) one removal may delete; `0` disables removal, `1` lifts the guard (see below) |
| `-sweep-force` | none | comma-separated adapter ids whose removal fraction guard is lifted, for every ingest the process runs; an id no adapter has refuses to start |

The HTTP write timeout tracks `-query-timeout`, so raising the query ceiling does not truncate a long response.

### Removing what vendors stop publishing

After each adapter's sync, reel-vex deletes the rows that adapter wrote and the vendor no longer publishes: a whole-feed sweep after a sync that read the entire feed, per-document replacement for re-published CSAF documents and for the Ubuntu OpenVEX documents that changed (the adapter re-reads only those), and withdrawal of CVEs missing from the vendor's `index.txt` or from Canonical's tarball. A whole-feed sweep is refused, deleting nothing, when it would remove more than `-sweep-max-fraction` (default `0.2`) of the adapter's rows, and a withdrawal when it would remove more than that fraction of the adapter's CVEs; a per-document replacement has no such guard, since a re-published document is the vendor's whole current word on its CVE. `0` disables removal, `1` lifts the guards. A refused or failed removal never fails the ingest.

A refused sweep stays refused: the rows it would have deleted are still there on the next run, and still count against the guard. Once you have checked that the vendor really did drop that much, run one ingest with `-sweep-force <adapter-id>` (several ids comma-separated) to lift the guard for those adapters only; their whole-feed `sweep` and `withdraw` lines then carry `forced=true`. Remove the flag afterwards, or every later run is forced too.

A verdict is part of a row's identity, so a changed verdict is a new row, and the old one goes only when removal deletes it. With removal disabled, or while an adapter's sweep is refused, both verdicts are served.

Each adapter run that gets as far as syncing logs one `sweep` line (a run that fails before, at discovery or reading its watermark, logs none). A CSAF run also logs one `withdraw` line when it trusted its `index.txt` and its removal was not skipped:

```
INFO sweep adapter=ubuntu-vex scope=all seen=195636880 owned=195702113 deleted=65233
INFO sweep adapter=debian-oval-bookworm scope=cves:0 seen=0 owned=0 deleted=0 skipped=incomplete
INFO withdraw adapter=redhat live=69854 held_cves=69864 withdrawn_cves=10 deleted=963
```

`skipped=incomplete` is the normal line for a feed that had not changed. A refusal is logged at WARN with its reason. Leave disk headroom: on the full Ubuntu OpenVEX feed a whole-feed sweep took 85 minutes and ~84-116 GB of transient disk above the database's steady size, released when it ends. Mechanisms, guards and sizing: [`docs/architecture.md`](./docs/architecture.md#removal).

## Adding a source

`config.yaml` lists `adapters:` (data sources) and `aliases:` (identifier-translation files). Registered adapter types: `csaf`, `ubuntu-oval`, `debian-oval`, `ubuntu-vex`, `rancher-vex`, `alpine-secdb`, `amazon-alas`, `almalinux-oval`, `oracle-oval`. The adapter-author guide and per-source quirks are in [`docs/architecture.md`](./docs/architecture.md).

## Tests

```bash
go test -count=1 ./...                               # unit + package (no network)
export REEL_VEX_TEST_PG_DSN='postgres://user:pass@host:5432/postgres?sslmode=disable'
go test -count=1 ./pkg/db/postgres/                  # TestPG, the Postgres backend
go test -tags integration -count=1 ./test/...        # integration + acceptance suites
```

Run `TestPG` and `test/integration` one after the other, not at once: both truncate the tables of the DSN's database. `-count=1` matters: the two suites under `test/` build the server binary with `go build`, which the test cache does not track, so a cached pass can describe an older binary.

Adapters are tested against committed fixtures over `httptest`, so no network is needed. The database suites (`TestPG` in `pkg/db/postgres`, `test/integration`, `test/acceptance`) need `REEL_VEX_TEST_PG_DSN`; without it they skip and still print `ok`, except under `CI=true`, where a missing DSN fails them. CI runs every one of them.

**`test/integration`** builds the binary, seeds hand-written rows into the database and checks the HTTP API.

**`test/acceptance`** checks answers against what the vendors actually published. Its fixtures are trimmed copies of one live feed per adapter type in `config.yaml` — Red Hat and SUSE CSAF, Canonical OpenVEX, Ubuntu OVAL noble, Debian OVAL bookworm, Rancher, Alpine v3.22 main and community, Amazon Linux 2 and 2023, AlmaLinux 9, Oracle ol8 and ol9 (`test/acceptance/testdata`; the README there gives each file's source URL, fetch date and what was kept). The suite creates a database of its own on the `REEL_VEX_TEST_PG_DSN` server (so it can run beside `test/integration`), serves the fixtures over HTTP at URLs shaped like the real ones, runs the server binary's `ingest` against them, then starts `serve` and runs each case over HTTP. The binary runs with its HTTP proxy pointed at a closed port, so nothing it fetches can reach a live feed. A case compares the exact answer — every statement's CVE, supplier, status, justification, `impact_statement`, timestamp, `status_notes` and products, each product in the shape the encoder writes it, and nothing else — with what the vendor document says, and every expected statement cites where in the fixture the vendor says it. A second fixture generation and a second `ingest` then check removal.

Each `ingest` also fails the suite when it logs a WARN or ERROR it should not, misses one it must (the day-2 refusals, each exactly once), leaves an adapter's first run incomplete, owns a different number of rows per adapter than expected, asks the fixture server for a file it does not have, or never asks for one it has; the `serve` log must stay free of WARN and ERROR lines. Compressed fixtures are rebuilt from the uncompressed content under `testdata/src` with `cd test/acceptance/testdata && go run gen.go` (needs `bzip2`); `TestFixturesMatchSource`, which needs no database or build tag, fails when the two differ.

## Contributing

Most useful: new CSAF providers (a `config.yaml` entry), new OVAL sources (a `translator.FromXOVAL()` in the sibling `oval-to-vex` repo + a small adapter), and new alias mappings. For other formats, open an issue first.

## License

Apache 2.0 — see [`LICENSE`](./LICENSE). Vendor-data attribution and licensing is in [`NOTICE.md`](./NOTICE.md).
