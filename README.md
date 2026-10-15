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

Vulnerability scanners flag many CVEs that don't affect the package they were found in. The vendor often knows this and says so: `not_affected`, `fixed`, `affected` or `under_investigation`. A statement like that is called **VEX**.

reel-vex collects those statements from nine vendors into one PostgreSQL database and serves them over HTTP. Some feeds are VEX already (CSAF, OpenVEX). Others are not (OVAL, Alpine secdb, Amazon updateinfo), and reel-vex translates them into VEX on the way in.

`/v1/statements` answers in OpenVEX. `/v1/analyze` returns your CycloneDX SBOM annotated with the verdicts. Trivy reads either one with `--vex`.

**Words used below**

- **PURL**: a package URL, the identifier scanners give a package, e.g. `pkg:deb/debian/zlib?distro=debian-12`.
- **CPE**: a platform identifier some vendors file statements under instead, e.g. `cpe:/a:redhat:enterprise_linux:8::appstream`. reel-vex translates between the two, so a PURL query also finds statements filed under a CPE.
- **Adapter**: the code that reads one feed. Each entry under `adapters:` in `config.yaml` is one adapter.

## Try it

Ask the public hub about one CVE on one package:

```bash
curl -s https://vex.getreel.dev/v1/statements \
  -H 'Content-Type: application/json' \
  -d '{"cves":["CVE-2021-44228"],
       "products":["pkg:rpm/redhat/log4j?repository_id=rhel-8-for-x86_64-appstream-rpms"]}'
```

The answer is an OpenVEX document. Here Red Hat says its log4j package is `not_affected` by Log4Shell (`vulnerable_code_not_present`).

If no vendor said anything about what you asked, the answer is `204 No Content` with an empty body.

### Hide cleared findings in Trivy

Scan the image to a CycloneDX SBOM, ask reel-vex about it, and hand the answer back to Trivy:

```bash
IMAGE=registry.access.redhat.com/ubi9-minimal
trivy image --format cyclonedx --scanners vuln $IMAGE > sbom.json
jq '{sbom: .}' sbom.json | curl -s https://vex.getreel.dev/v1/statements \
  -H 'Content-Type: application/json' -d @- > vex.json
trivy image --vex vex.json $IMAGE
```

Trivy then hides the findings the vendor marked `not_affected` or `fixed` (on this image, 10 of 180 when this was written).

If the hub answers `204`, `vex.json` is empty and Trivy refuses to load it. Run the scan without `--vex` in that case.

### Other ways to ask

- **Packages without CVEs.** Send only `products`, or an SBOM with no vulnerabilities, and you get every statement for those packages (*broad mode*). The answer doesn't depend on what a scan found, so you can cache it and reuse it for every scan of the same image.
- **`trivy sbom --vex`.** Send the SBOM to `POST /v1/analyze` instead. It returns the same SBOM annotated with vendor verdicts, referenced the way `trivy sbom --vex` needs. Use `/v1/statements` for `trivy image --vex`.
- **Every status comes back.** reel-vex returns what the vendor said, `affected` and `under_investigation` included. Pass `statuses` to get fewer. Trivy acts only on `not_affected` and `fixed`.
- **A specific version.** Put a version in the PURL and you get only the verdicts that hold for it. See [Versioned queries](./docs/api.md#versioned-queries).

Everything else: the [API reference](./docs/api.md), [how it works](./docs/architecture.md) and the [database schema](./docs/data-model.md).

## Data sources

| Vendor | Format | Feed | Releases | Identifiers |
|--------|--------|------|----------|-------------|
| Red Hat | CSAF VEX | [security.access.redhat.com/data/csaf/v2/vex/](https://security.access.redhat.com/data/csaf/v2/vex/) | all | PURL + CPE |
| SUSE | CSAF VEX | [ftp.suse.com/pub/projects/security/csaf-vex/](https://ftp.suse.com/pub/projects/security/csaf-vex/) | all | CPE |
| Rancher (SUSE) | OpenVEX | [github.com/rancher/vexhub](https://github.com/rancher/vexhub) | Rancher images and Go modules | PURL, per image or module |
| Ubuntu | OpenVEX | [security-metadata.canonical.com/vex/](https://security-metadata.canonical.com/vex/) | all | `pkg:deb/ubuntu/…?distro=…` |
| Ubuntu | OVAL | [security-metadata.canonical.com/oval/](https://security-metadata.canonical.com/oval/) | 20.04, 22.04, 24.04 | `pkg:deb/ubuntu/…?distro=…` |
| Debian | OVAL | [www.debian.org/security/oval/](https://www.debian.org/security/oval/) | 11, 12, 13 | `pkg:deb/debian/…?distro=…` |
| Alpine | secdb | [secdb.alpinelinux.org](https://secdb.alpinelinux.org/) | 3.19 to 3.24 | `pkg:apk/alpine/…?distro=alpine-<major.minor>` |
| Amazon Linux | updateinfo | [alas.aws.amazon.com](https://alas.aws.amazon.com/) | 2, 2023 | `pkg:rpm/amazon/…?distro=amazon-<major>` |
| AlmaLinux | OVAL | [security.almalinux.org/oval/](https://security.almalinux.org/oval/) | 8, 9, 10 | `pkg:rpm/almalinux/…?distro=almalinux-<major>` (or `alma`) |
| Oracle Linux | OVAL | [linux.oracle.com/security/oval/](https://linux.oracle.com/security/oval/) | 8, 9, 10 | `pkg:rpm/oracle/…?distro=oracle-<major>` |

- **Ubuntu has two feeds on purpose.** Neither covers everything the other does. OpenVEX has triage that OVAL lacks, and OVAL covers package names OpenVEX spells differently.
- **Rancher statements are about one image or Go module.** They apply only when you name that image or module (the `scopes` field, or the SBOM's root component), so they never hide the same package anywhere else. See the [API reference](./docs/api.md).

### Attribution and licensing

Every statement says where it came from (`supplier`, and `source_format` in `status_notes`). Each source and its license is listed in [`NOTICE.md`](./NOTICE.md).

- **Alpine's secdb is licensed [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).** reel-vex's Alpine-derived statements are an adaptation, attributed to [Alpine Linux](https://secdb.alpinelinux.org/) and redistributed under the same license.
- **AlmaLinux** errata data is MIT-licensed.
- The other feeds are redistributed under their vendors' terms.

## Run it yourself

reel-vex is one Go binary and a PostgreSQL database. The public hub is one shared instance with tight limits. Your own instance can raise or remove every one of them.

### With Docker Compose

```bash
git clone https://github.com/getreeldev/reel-vex && cd reel-vex
cp .env.example .env      # set POSTGRES_PASSWORD and ADMIN_TOKEN
docker compose up -d
```

- **`config.yaml`** in the repo root lists the feeds, one adapter each. Compose mounts it read-only. It is never baked into the image, so edit it to drop feeds you don't need.
- **The image version is pinned** on the `image:` line of `docker-compose.yml`. Change it to upgrade.
- **The API listens on `127.0.0.1:8080`.** Put a reverse proxy in front for TLS.
- **Data lives in the `pgdata` volume** and survives restarts.
- **The first ingest reads every feed in full** and can take several hours. Later runs fetch only what changed, except Amazon Linux and Rancher, which re-read their whole feed every time. Compose runs an ingest every 4 hours.
- **Postgres is tuned for a 16 to 32 GB host.** Scale `shared_buffers` and `effective_cache_size` in `docker-compose.yml` to about 25% and 75% of your RAM.
- **For a managed Postgres**, delete the `postgres` service and point `-db` at your database.

### From source

Needs Go 1.27 or later.

```bash
go build -o reel-vex ./cmd/server
./reel-vex -config config.yaml -db 'postgres://user:pass@host:5432/vex?sslmode=disable' serve
```

Other commands, with the same `-db`: `ingest` (run one ingest, then exit), `stats`, and `query CVE-2021-44228`.

`serve` ingests on start, then every `-ingest-interval`. It skips the start-up ingest when the last one is more recent than the interval.

### Several replicas

- **Start API replicas with `-no-scheduler`** so they only serve.
- **Run ingest from one place:** one `serve` with its scheduler, or `reel-vex ingest` on a schedule (a CronJob, say).
- **One ingest runs at a time per database.** A second one changes nothing and logs `ingest not started: another ingest is running on this database`. The `ingest` command then exits non-zero. A `serve` scheduler logs `ingest failed` and tries again at its next interval. The lock is released when its process ends, even in a crash.
- **`GET /healthz` returns `503` while the database is unreachable.** Use it as a readiness probe. As a liveness probe it restarts every replica during a database outage.

### Flags

| Flag | Default | What it does |
|------|---------|--------------|
| `-db` | required | Postgres URL, starting `postgres://` or `postgresql://` |
| `-config` | `config.yaml` | the adapter list |
| `-addr` | `:8080` | listen address |
| `-admin-token` | empty | bearer token for `POST /v1/ingest`. **Empty means anyone who can reach the API can start an ingest.** |
| `-ingest-interval` | `24h` | time between scheduled ingests |
| `-no-scheduler` | off | serve only, never ingest on a schedule |
| `-limit` | `0` (none) | `ingest` only: stop each adapter after this many statements. For testing. A limited run removes nothing. |
| `-sbom-max-mb` | `10` | max request body on `/v1/statements` and `/v1/analyze`; larger gets `413` |
| `-statements-max` | `50000` | max statements in one answer (`0` = no cap); more is cut short and marked `X-Reel-Truncated` |
| `-max-statements-items` | `10000` | max entries in `cves` or `products` on `/v1/statements`; more gets `400` |
| `-max-sbom-components` | `50000` | max components in an SBOM; more gets `400` |
| `-max-sbom-vulns` | `10000` | max vulnerabilities in an SBOM; more gets `400` |
| `-analyze-max-cves` | `10000` | max distinct CVEs one `/v1/analyze` may look up; more gets `400` |
| `-max-user-vex-statements` | `25000` | max user-supplied VEX statements in one `/v1/analyze`; more gets `400` |
| `-query-timeout` | `20s` | longest one database query may run. Hitting it fails the request: `503` on `/v1/analyze`, `500` on `/v1/statements`. The HTTP write timeout follows it. |
| `-sweep-max-fraction` | `0.2` | removal guard, see below. Between `0` and `1`; `0` turns removal off, `1` lifts the fraction guard. |
| `-sweep-force` | none | comma-separated adapter ids whose removal guard is lifted, see below. An id no adapter has stops reel-vex from starting. |

### Removing what vendors stop publishing

After each adapter's sync, reel-vex deletes the statements that adapter wrote and the vendor no longer publishes. An adapter only ever deletes its own rows.

- **A big removal is refused.** If a whole-feed sweep would delete more than 20% of the adapter's rows, or a withdrawal (Red Hat, SUSE or Ubuntu OpenVEX dropping CVEs from their published list) more than 20% of its CVEs, nothing is deleted. Replacing a re-published document has no such limit. `-sweep-max-fraction` sets the share. A refusal is logged at WARN (`sweep … refused=…` or `withdraw … refused=…`) and the ingest carries on.
- **A removal that fails** is logged at ERROR, and the ingest still carries on.
- **A refused removal stays refused**, because the stale rows are still there next run. Once you've checked the vendor really dropped that much, run one ingest with `-sweep-force <adapter-id>`, then remove the flag. On `serve` it applies to every scheduled ingest until you restart without it.
- **Leave disk headroom.** Removal on the full Ubuntu OpenVEX feed needs up to about 116 GB of temporary disk on top of the database. It is released when the removal ends.

How each kind of removal works, and every log line: [Removal](./docs/architecture.md#removal).

## Adding a source

`config.yaml` has two lists. `adapters:` holds the feeds. `aliases:` holds identifier-translation files, such as Red Hat's repository-to-CPE map (`redhat-repository-to-cpe`).

- **A new CSAF provider** is one `type: csaf` entry with its `provider-metadata.json` URL.
- **Adapter types** the binary knows: `csaf`, `ubuntu-vex`, `ubuntu-oval`, `debian-oval`, `rancher-vex`, `alpine-secdb`, `amazon-alas`, `almalinux-oval`, `oracle-oval`. A config entry with any other type stops reel-vex from starting.
- **A new feed format** needs a new adapter. See [architecture](./docs/architecture.md).

## Tests

```bash
go test -count=1 ./...                               # unit and package tests, no network
export REEL_VEX_TEST_PG_DSN='postgres://user:pass@host:5432/postgres?sslmode=disable'
go test -count=1 ./pkg/db/postgres/                  # TestPG, the Postgres backend
go test -tags integration -count=1 ./test/...        # integration and acceptance suites
```

- **The database suites need `REEL_VEX_TEST_PG_DSN`.** Without it they skip and still print `ok`. Under `CI=true` a missing DSN fails them instead.
- **Run `TestPG` and `test/integration` one after the other.** Both empty the tables of the DSN's database.
- **Keep `-count=1`.** The suites under `test/` build the server binary, and Go's test cache doesn't notice when it changes.
- **`test/acceptance`** ingests trimmed copies of real vendor feeds from a local server, with no network access, and checks each answer against what the vendor document says. A second ingest checks removal. Where each fixture came from: [`test/acceptance/testdata/README.md`](./test/acceptance/testdata/README.md). To rebuild the compressed fixtures, run `cd test/acceptance/testdata && go run gen.go` (needs `bzip2`).

## Contributing

The most useful contributions:

- new CSAF providers (a `config.yaml` entry)
- new OVAL sources (a parser in the sibling [`oval-to-vex`](https://github.com/getreeldev/oval-to-vex) library plus a small adapter)
- new identifier-translation files

For other formats, open an issue first.

## License

Apache 2.0, see [`LICENSE`](./LICENSE). Vendor data attribution and licensing: [`NOTICE.md`](./NOTICE.md).
