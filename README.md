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

Scanners flag many CVEs that don't affect the package they were found in. The vendor often says so: `not_affected`, `fixed`, `affected` or `under_investigation`. A statement like that is called **VEX**.

reel-vex collects those statements from nine vendors, translating the feeds that are not VEX already (OVAL, Alpine secdb, Amazon updateinfo), and serves them over HTTP. Trivy reads the answers with `--vex`.

**Words used below**

- **PURL**: the package URL a scanner gives a package, e.g. `pkg:deb/debian/zlib?distro=debian-12`.
- **CPE**: a platform identifier some vendors use instead. A PURL query also finds statements filed under a CPE.
- **Adapter**: the code that reads one feed, one per `adapters:` entry in `config.yaml`.

## Try it

Ask the public hub about one CVE on one package:

```bash
curl -s https://vex.getreel.dev/v1/statements \
  -H 'Content-Type: application/json' \
  -d '{"cves":["CVE-2021-44228"],
       "products":["pkg:rpm/redhat/log4j?repository_id=rhel-8-for-x86_64-appstream-rpms"]}'
```

The answer is an OpenVEX document: Red Hat says its log4j package is `not_affected` by Log4Shell (`vulnerable_code_not_present`). If no vendor said anything, the answer is `204 No Content` with an empty body.

### Hide cleared findings in Trivy

Scan to a CycloneDX SBOM, ask reel-vex, pass the answer to Trivy:

```bash
IMAGE=registry.access.redhat.com/ubi9-minimal
trivy image --format cyclonedx --scanners vuln $IMAGE > sbom.json
jq '{sbom: .}' sbom.json | curl -s https://vex.getreel.dev/v1/statements \
  -H 'Content-Type: application/json' -d @- > vex.json
trivy image --vex vex.json $IMAGE
```

Trivy hides findings the vendor marked `not_affected` or `fixed`. On a `204`, `vex.json` is empty and Trivy refuses it, so scan without `--vex`.

### Other ways to ask

- **Packages without CVEs.** Send only `products`, or an SBOM with no vulnerabilities, to get every statement for those packages, cacheable per image.
- **For `trivy sbom --vex`**, send the SBOM to `POST /v1/analyze`, which returns it annotated with the verdicts.
- **Every status comes back**, `affected` and `under_investigation` included. Pass `statuses` to get fewer.
- **A version in the PURL** gets only the verdicts that hold for it. See [Versioned queries](./docs/api.md#versioned-queries).

More: [API reference](./docs/api.md), [how it works](./docs/architecture.md), [database schema](./docs/data-model.md).

## Data sources

| Vendor | Format | Feed | Releases | Identifiers |
|--------|--------|------|----------|-------------|
| Red Hat | CSAF VEX | [security.access.redhat.com/data/csaf/v2/vex/](https://security.access.redhat.com/data/csaf/v2/vex/) | all | PURL + CPE |
| SUSE | CSAF VEX | [ftp.suse.com/pub/projects/security/csaf-vex/](https://ftp.suse.com/pub/projects/security/csaf-vex/) | all | CPE |
| Rancher (SUSE) | OpenVEX | [github.com/rancher/vexhub](https://github.com/rancher/vexhub) | Rancher images, Go modules | PURL |
| Ubuntu | OpenVEX | [security-metadata.canonical.com/vex/](https://security-metadata.canonical.com/vex/) | all | `pkg:deb/ubuntu/…?distro=…` |
| Ubuntu | OVAL | [security-metadata.canonical.com/oval/](https://security-metadata.canonical.com/oval/) | 20.04, 22.04, 24.04 | `pkg:deb/ubuntu/…?distro=…` |
| Debian | OVAL | [www.debian.org/security/oval/](https://www.debian.org/security/oval/) | 11, 12, 13 | `pkg:deb/debian/…?distro=…` |
| Alpine | secdb | [secdb.alpinelinux.org](https://secdb.alpinelinux.org/) | 3.19 to 3.24 | `pkg:apk/alpine/…?distro=alpine-<major.minor>` |
| Amazon Linux | updateinfo | [alas.aws.amazon.com](https://alas.aws.amazon.com/) | 2, 2023 | `pkg:rpm/amazon/…?distro=amazon-<major>` |
| AlmaLinux | OVAL | [security.almalinux.org/oval/](https://security.almalinux.org/oval/) | 8, 9, 10 | `pkg:rpm/almalinux/…?distro=almalinux-<major>` (or `alma`) |
| Oracle Linux | OVAL | [linux.oracle.com/security/oval/](https://linux.oracle.com/security/oval/) | 8, 9, 10 | `pkg:rpm/oracle/…?distro=oracle-<major>` |

- **Ubuntu has two feeds on purpose.** OpenVEX has triage OVAL lacks, and OVAL covers package names OpenVEX spells differently.
- **Rancher statements are about one image or Go module** and apply only when you name it (the `scopes` field, or the SBOM's root component). See [Product-scoped statements](./docs/api.md#product-scoped-statements).

### Attribution and licensing

Every statement names its vendor in `supplier` and its feed format in `status_notes`. [`NOTICE.md`](./NOTICE.md) gives each source's license. **Alpine's secdb is [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)**, so the Alpine-derived statements are an adaptation, attributed to [Alpine Linux](https://secdb.alpinelinux.org/) and redistributed under the same license.

## Run it yourself

reel-vex is one Go binary and a PostgreSQL database. Your own instance can raise or remove every limit the public hub sets.

### With Docker Compose

```bash
git clone https://github.com/getreeldev/reel-vex && cd reel-vex
cp .env.example .env      # set POSTGRES_PASSWORD and ADMIN_TOKEN
docker compose up -d
```

- **`config.yaml`** lists the feeds. It is mounted, not baked in, so edit it freely.
- **To upgrade**, change the pinned `image:` line in `docker-compose.yml`.
- **The API listens on `127.0.0.1:8080`.** Put a reverse proxy in front for TLS.
- **The first ingest reads every feed** and can take hours. The bundled Compose file then runs an ingest every 4 hours (the binary's own default is 24), and later runs fetch only what changed (Amazon Linux and Rancher always re-read everything).
- **Postgres is tuned for 16 to 32 GB of RAM.** Set `shared_buffers` and `effective_cache_size` to about 25% and 75% of yours.
- **For managed Postgres**, delete the `postgres` service and point `-db` at it.

### From source

Needs Go 1.27 or later.

```bash
go build -o reel-vex ./cmd/server
./reel-vex -config config.yaml -db 'postgres://user:pass@host:5432/vex?sslmode=disable' serve
```

Other commands: `ingest` (once, then exit), `stats`, and `query CVE-2021-44228`. `serve` ingests on start, unless the last ingest is newer than `-ingest-interval`, then once per interval.

### Several replicas

- **Start API replicas with `-no-scheduler`**, and ingest from one place: one `serve` with its scheduler, or a scheduled `reel-vex ingest`.
- **One ingest runs at a time per database.** A second one logs `ingest not started: another ingest is running on this database` and changes nothing. `ingest` then exits non-zero; `serve` logs `ingest failed` and retries next interval.
- **`GET /healthz` returns `503` while the database is unreachable.** Use it for readiness, not liveness, or an outage restarts every replica.

### Flags

| Flag | Default | What it does |
|------|---------|--------------|
| `-db` | required | Postgres URL (`postgres://` or `postgresql://`) |
| `-config` | `config.yaml` | the adapter list |
| `-addr` | `:8080` | listen address |
| `-admin-token` | empty | bearer token for `POST /v1/ingest`; **empty lets anyone start an ingest** |
| `-ingest-interval` | `24h` | time between scheduled ingests |
| `-no-scheduler` | off | serve only, never ingest |
| `-sweep-max-fraction` | `0.2` | removal guard: `0` turns removal off, `1` lifts the guard |
| `-sweep-force` | none | adapter ids exempt from the guard; an unknown id stops start-up |

`reel-vex -h` lists every flag with its default, including the request limits (`-sbom-max-mb`, `-statements-max`, `-max-*`, `-query-timeout` and more). The [API reference](./docs/api.md) says what a client gets when one is hit.

### Removing what vendors stop publishing

After each sync, reel-vex deletes what the adapter wrote and the vendor no longer publishes.

- **A big removal is refused.** A whole-feed *sweep* of over 20% of the adapter's rows, or a withdrawal (Red Hat, SUSE or Ubuntu OpenVEX dropping CVEs from their list) of over 20% of its CVEs, deletes nothing. `-sweep-max-fraction` sets the share. Refusals log at WARN (`sweep … refused=…`, `withdraw … refused=…`), failures at ERROR. The ingest carries on.
- **A refusal repeats on the next run that reads the feed again** (for OVAL and Alpine, the next time the file changes). Once you've confirmed the vendor dropped that much, run one ingest with `-sweep-force <adapter-id>`, then remove the flag (on `serve`, it applies until a restart without it).
- **Leave disk headroom.** Removal on the full Ubuntu OpenVEX feed needs up to about 116 GB of temporary disk beyond the database.

Details and every log line: [Removal](./docs/architecture.md#removal).

## Adding a source

`config.yaml` lists the feeds under `adapters:` and identifier-translation files (such as Red Hat's `redhat-repository-to-cpe`) under `aliases:`.

- **A new CSAF provider** is one `type: csaf` entry with its `provider-metadata.json` URL.
- **Known adapter types:** `csaf`, `ubuntu-vex`, `ubuntu-oval`, `debian-oval`, `rancher-vex`, `alpine-secdb`, `amazon-alas`, `almalinux-oval`, `oracle-oval`. Any other type stops reel-vex from starting.
- **A new feed format** needs a new adapter: see [architecture](./docs/architecture.md).

## Tests

```bash
go test -count=1 ./...                          # no network, no database
export REEL_VEX_TEST_PG_DSN='postgres://user:pass@host:5432/postgres?sslmode=disable'
go test -count=1 ./pkg/db/postgres/
go test -tags integration -count=1 ./test/...
```

- **Without `REEL_VEX_TEST_PG_DSN`** the last two skip and still print `ok` (under `CI=true` they fail).
- **Run the last two one after the other.** Both empty the DSN's database.
- **Keep `-count=1`.** The suites build the server binary, and Go's test cache misses its changes.
- **`test/acceptance`** checks answers against trimmed real vendor feeds, offline. [Its README](./test/acceptance/testdata/README.md) lists the fixtures; `cd test/acceptance/testdata && go run gen.go` rebuilds them (needs `bzip2`).

## Contributing

Most useful: new CSAF providers (a `config.yaml` entry), new OVAL sources (a parser in the sibling [`oval-to-vex`](https://github.com/getreeldev/oval-to-vex) library plus a small adapter) and new identifier-translation files. For other formats, open an issue first.

## License

Apache 2.0, see [`LICENSE`](./LICENSE). Vendor data attribution and licensing: [`NOTICE.md`](./NOTICE.md).
