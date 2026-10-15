# reel-vex architecture

How reel-vex fills its database, and what an operator controls. For the HTTP API see [`api.md`](./api.md). For the tables see [`data-model.md`](./data-model.md).

Terms used below:

- **VEX** (Vulnerability Exploitability eXchange): a vendor's verdict on whether a CVE affects a product: `not_affected`, `fixed`, `affected` or `under_investigation`.
- **PURL** (package URL): a package identifier, e.g. `pkg:deb/debian/zlib?distro=debian-12`.
- **CPE** (Common Platform Enumeration): a product identifier, e.g. `cpe:/a:redhat:enterprise_linux:8::appstream`.
- **Adapter**: the code that reads one feed. Each feed in `config.yaml` is one adapter with its own `id`.
- **Removal**: deleting the rows a vendor no longer publishes, by one of three mechanisms (whole-feed sweep, per-document replacement, withdrawal). See [Removal](#removal).

## How ingest works

`config.yaml` lists the adapters and the alias fetchers. An ingest runs them one after another:

```
config.yaml
  ├─ adapters (one per feed) ──► Discover ──► Sync ──► upsert into statements
  │                                              └───► removal (sweep, withdrawal)
  └─ alias fetchers ───────────────────────────────► upsert into product_aliases

afterwards: build the query index (first ingest only), refresh /v1/stats, ANALYZE
```

- **Discover** finds and checks the feed URL. **Sync** streams the vendor's statements.
- Every row records the adapter that wrote it, so removal can delete only that adapter's rows.
- A failing adapter is logged (`adapter ingest failed`) and skipped. The others still run.

## Adapters

| `type` | Feeds in `config.yaml` | Format (`source_format`) | A later run reads | Removal |
|---|---|---|---|---|
| `csaf` | Red Hat, SUSE | CSAF 2.0 (`csaf`) | documents `changes.csv` lists since the watermark | per-document replacement, withdrawal against `index.txt`; whole-feed sweep after a clean first run |
| `ubuntu-vex` | Canonical OpenVEX, all releases | OpenVEX 0.2.0 (`openvex`) | nothing if `Last-Modified` has not moved, else the documents that changed | per-document replacement and withdrawal; whole-feed sweep after a whole read |
| `ubuntu-oval`, `debian-oval`, `almalinux-oval`, `oracle-oval` | Ubuntu focal/jammy/noble, Debian bullseye/bookworm/trixie, AlmaLinux 8/9/10, Oracle Linux 8/9/10 | OVAL (`oval`) | nothing if `Last-Modified` has not moved, else the whole file | whole-feed sweep when the file changed |
| `alpine-secdb` | Alpine 3.19 to 3.24, `main` and `community` | secdb JSON (`secdb`) | as OVAL | as OVAL |
| `amazon-alas` | Amazon Linux 2 and 2023, core repos | `updateinfo` (`updateinfo`) | the whole feed | whole-feed sweep |
| `rancher-vex` | SUSE Rancher VEX hub | OpenVEX 0.2.0 (`openvex`) | the whole snapshot | whole-feed sweep when every listed file parsed |

The OVAL adapters parse with [`oval-to-vex`](https://github.com/getreeldev/oval-to-vex), a standalone Go library.

### CSAF (Red Hat, SUSE)

The adapter finds the VEX distribution through the vendor's `provider-metadata.json`. Every run reads `changes.csv` and `index.txt` (the list of live documents) first.

- **First run.** Red Hat publishes a weekly bulk archive, named in `archive_latest.txt`. The adapter walks it locally, skipping documents `changes.csv` dates after the archive and documents `index.txt` no longer lists, then fetches the rest. SUSE has no archive, so every document is fetched.
- **Later runs.** Only the documents `changes.csv` lists since the watermark.
- **Statuses.** SUSE's `recommended` (older documents: `first_fixed`) is stored as `fixed`. Justifications are kept as the vendor wrote them.

<details><summary>Read failures</summary>

- A body counts only if it is the CSAF document its path names (`document.csaf_version`, `document.tracking.id`, and the CVE as tracking id or in `vulnerabilities[].cve`). An error page served with HTTP 200 is a failed read.
- A 404 or 410 for a document `index.txt` does not list is a withdrawal, not a failure.
- Other failures are read once more about 30 s later. A second failure makes the run incomplete and holds the watermark just before that document, so the next run reads it again. If the document's `changes.csv` date is more than 7 days old, it is given up on instead (WARN). It is read again when the vendor republishes it.
- If `index.txt` lacks a document this run fetched, it is not trusted: WARN, no withdrawal, run not complete.

Log lines: INFO `csaf reading failed documents once more`, `csaf failed documents read once more`, `csaf document withdrawn: gone, and index.txt does not list it`. WARN `csaf document gone but not withdrawn`, `csaf document failed and is older than the retry window; giving up on it`, `csaf index.txt lacks documents fetched this run; no live manifest this run`.
</details>

### Canonical OpenVEX (`ubuntu-vex`)

One tarball, one OpenVEX document per CVE, including Canonical's triage before a USN (Ubuntu Security Notice) is out. The Ubuntu OVAL feeds stay beside it because neither covers the other.

- The tarball has no list of what changed. The adapter stores a fingerprint per document in `adapter_documents` and re-reads only changed documents, each in full.
- **It reads the whole tarball when:**
  - it is the first run, or its `adapter_documents` rows were deleted
  - removal is off (`-sweep-max-fraction 0`)
  - more than a fifth of the documents, and over 1,000, changed
  - a document covers another CVE, or two files share a name

  A whole read gets the guarded whole-feed sweep, unless a document was skipped (malformed, or over 256 MiB). Then nothing is removed.
- Canonical's `distro` shapes (`ubuntu/jammy`, `esm-infra/xenial`, `fips-updates/jammy`, `trusty/esm`) are rewritten to the `ubuntu-<version>` scanners send.
- **To force a whole read**, delete the adapter's rows in `adapter_documents`. Clear its `adapter_state.last_synced` too to fetch now rather than at the next publish.

### OVAL, Alpine and Amazon

- **OVAL**: one bz2 file per release. Ubuntu and Debian rows are `pkg:deb/<vendor>/<name>?distro=<vendor>-<version>`. The `distro` is identity: focal and noble `openssl` are different products.
- **AlmaLinux** reads its release from `alsa-<N>` in the URL. Rows are written under both `pkg:rpm/almalinux/` and `pkg:rpm/alma/`, because scanners use both.
- **Oracle Linux**: each adapter keeps only its own release, read from `ol<N>` in the URL. Without one, the server refuses to start. Ksplice variants are skipped. The files can disagree: ELSA-2026-500137 in the ol8 file names 19 OL9 packages the ol9 file lacks, so those get no OL9 `fixed` row.
- **Alpine**: the secdb key `"0"` means the CVE does not apply, stored `not_affected` (`vulnerable_code_not_present`). A CVE under several keys is one row, at the highest fixed version.
- **Amazon**: `mirror.list` → `repomd.xml` → `updateinfo.xml.gz`, followed on every run. Every advisory package is `fixed`.

### Rancher VEX hub (`rancher-vex`)

`not_affected` verdicts for packages inside SUSE's cloud-native images (Rancher, RKE2, K3s, Harvester, Longhorn). The adapter downloads the snapshot tarball the hub's `vex-repository.json` names and parses every file its `index.json` lists.

These statements are **product-scoped**: each is about a package inside one image or Go module. The package is the row's `product_id`. The image is its `scope`, without version or digest (`repository_url` kept). A scoped row is returned only when the caller names that scope, so it never hides the same package elsewhere. See [`api.md`](./api.md#product-scoped-statements).

Skipped and counted in the sync log: statements with no CVE name (`skipped_non_cve`), no subcomponent (`skipped_no_subcomponent`), or a subcomponent that is neither PURL nor CPE (`skipped_bad_subcomponent`).

### Scanner distro names

Scanners send point releases where feeds store a major or major.minor. The resolver also tries the stored form: `alpine-3.21.2 → alpine-3.21`, `amazon-2023.7.x → amazon-2023`, `alma-9.1 → almalinux-9`, `debian-12.11 → debian-12`, `oracle-8.10 → oracle-8`.

## Version lists

A `statements` row is one verdict. It lists every version the vendor stated for that verdict, and its `version_kind` says how a versioned query reads the list:

| `version_kind` | Feeds | A versioned query gets the row when |
|---|---|---|
| `exact` | Ubuntu OpenVEX, Rancher | the version is in the list. An empty list (Rancher's deb, rpm, apk) matches any version. |
| `boundary` | `fixed` rows of OVAL, Alpine, Amazon | the version is at or above the fixed-in version (dpkg, rpm or apk ordering) |
| `''` | Red Hat and SUSE CSAF; other verdicts of the fixed-in feeds (Debian's `0:0` `affected`, Alpine's `"0"` `not_affected`) | always: the version is ignored |

For example, glibc `2.35-1` listed `affected` and `2.35-2` listed `fixed` for one CVE is two rows: `affected [2.35-1]` and `fixed [2.35-2]`. A rebuild changes a list rather than adding a row. A verdict whose list empties is swept.

- The store **replaces** a list on write, never merges. An exact-list adapter must emit each key once per sync with its full list, so both read whole documents.
- An exact row is answered once per matched version, written as Trivy writes it: `pkg:deb/ubuntu/bind9@9.11.3%2Bdfsg-1ubuntu1.18?arch=amd64&distro=ubuntu-18.04&epoch=1`. A boundary row is answered under the identifier the caller sent.
- Where a feed states several fixed-in versions for one key (parallel kernel or module streams), the last one written is kept. A version fixed in another stream may get no `fixed` answer.

Client view: [`api.md`](./api.md#versioned-queries).

## Alias fetchers

Alias fetchers load vendor mapping files into `product_aliases`. The one today, Red Hat's `repository-to-cpe.json`, lets `?repository_id=rhel-8-for-x86_64-appstream-rpms` match statements keyed on `cpe:/a:redhat:enterprise_linux:8::appstream`. Aliases are added and updated, never removed.

## Sync strategy

- **Watermark**: `adapter_state.last_synced`, the newest statement date the adapter emitted (Ubuntu OpenVEX: the tarball's `Last-Modified`).
- **First run** (no watermark): every adapter reads its whole feed.
- **Later runs**: as in the [Adapters](#adapters) table. An unchanged file logs `up to date, skipping GET` and emits nothing.
- **Re-writing** a row whose content is unchanged leaves its `updated` date alone.

## Removal

Removal deletes the rows a vendor no longer publishes. It runs right after each adapter's sync, and touches only rows that adapter owns: the ones it wrote last. Ownerless rows (from versions before 0.13) are never removed.

### What gets deleted, and when

| Mechanism | Runs when | Deletes | Guard |
|---|---|---|---|
| **Whole-feed sweep** | the sync read the whole feed without error (see the [Adapters](#adapters) table) | every row the adapter owns that it did not emit this run | refused above `-sweep-max-fraction` of the adapter's rows, or when the sync emitted nothing |
| **Per-document replacement** | documents read in full on a run that is not whole: CSAF, and Ubuntu OpenVEX's changed documents | those CVEs' rows the document no longer states | none: a re-published document is the vendor's whole answer for its CVE, even if empty |
| **Withdrawal** | Red Hat and SUSE with a trusted `index.txt`; Ubuntu OpenVEX when it read only changed documents (the tarball's CVE list is the manifest) | every row of a CVE not in the manifest and not read this run | refused on an empty manifest, or above `-sweep-max-fraction` of the adapter's CVEs |

- **Nothing is removed** when the run cannot vouch for what it emitted: a sync error, a failed write, a run cut short by `-limit` (an `ingest` test flag), or a file that had not changed. A CSAF run with failed documents still replaces what it read, and still withdraws.
- **A failed or refused removal never fails the adapter.** The rows stay and the watermark moves on. The next run that re-reads the feed retries: every run for Amazon, Rancher and withdrawals, the next changed file for OVAL and Alpine. A failed CSAF per-document replacement waits until that document changes again. Ubuntu OpenVEX is the exception: its watermark waits until removal finishes, so the next run fetches the same tarball again.
- **A changed verdict is a new row**, because the verdict is part of the key. The old row goes only when removal deletes it. While removal is off or refused, both verdicts are served.
- **One ingest at a time.** An ingest holds a database lock. A second one on the same database (a CronJob beside `serve`, say) changes nothing and stops with `another ingest is running`: the `ingest` subcommand exits non-zero, and a `serve` scheduled run logs it and retries at the next interval.

### Operator controls

| Flag | Default | Effect |
|---|---|---|
| `-sweep-max-fraction` | `0.2` | Fraction guard for whole-feed sweeps and withdrawals, within `[0, 1]` (anything else refuses to start). `0` turns all removal off. `1` lifts the fraction guards. |
| `-sweep-force <id>[,<id>…]` | none | Lifts the fraction guards for the named adapters only. An unknown id refuses to start. No effect when `-sweep-max-fraction` is `0`. |

- **A refused sweep stays refused**: the rows it would delete are still counted next run. Check the vendor really dropped that much, run one ingest with `-sweep-force <adapter-id>`, then remove the flag. On `serve` it applies to every ingest until a restart without it.
- Neither `1` nor `-sweep-force` lifts the `nothing seen` or `empty manifest` refusals.

### Log lines to watch

Each adapter that reaches its sync logs exactly one `sweep` line (none if it fails earlier, e.g. at discovery). Red Hat, SUSE and Ubuntu OpenVEX also log a `withdraw` line on runs that have a manifest and whose removal was not skipped.

```
INFO sweep adapter=ubuntu-vex scope=all seen=195636880 owned=195702113 deleted=65233
INFO sweep adapter=redhat scope=cves:412 seen=38117 owned=40269 deleted=2152
INFO sweep adapter=debian-oval-bookworm scope=cves:0 seen=0 owned=0 deleted=0 skipped=incomplete
WARN sweep adapter=alpine-secdb-v3.21-main scope=all seen=5120 owned=7012 deleted=0 refused="would delete 1892 of 7012 owned rows (26.98%), over the 20.00% limit"
INFO withdraw adapter=redhat live=69854 held_cves=69864 withdrawn_cves=10 deleted=963
WARN withdraw adapter=suse live=3 held_cves=4 withdrawn_cves=1 deleted=0 refused="would withdraw 1 of 4 held CVEs (25.00%), over the 20.00% limit"
```

(Numbers illustrative.)

- `scope=all` is a whole-feed sweep. `scope=cves:<n>` replaces `n` CVEs. `seen` counts keys emitted, duplicates included. `owned` counts the adapter's rows in scope.
- `skipped=incomplete` is normal for an unchanged feed. Other values: `disabled`, `sync error`, `flush error`, `limit`, `start error`, `aborted`.
- **Refusal**: WARN, `deleted=0`, `refused="<reason>"` (also `nothing seen`, `empty manifest`). **Failure**: ERROR with `error=`. A forced sweep or withdrawal adds `forced=true`.

### Disk headroom

A whole-feed sweep needs temporary disk, released when it ends. On the full Ubuntu OpenVEX feed it took about 85 minutes and up to about 116 GB above the database's normal size. Provision for it on a first ingest and whenever Ubuntu OpenVEX reads whole. reel-vex caps the sweep's temp files at 100 GB only when its database role is a superuser. On managed Postgres the only limit is free disk.

Deleting rows also writes WAL, about one page per row. Set `wal_compression=lz4`, as the bundled `docker-compose.yml` does, to cut it.

Each sweep statement is capped at 2 hours and each sweep at 6. On slow storage a full Ubuntu OpenVEX sweep can hit the cap and log an ERROR `sweep` line.

## Scheduling

- `serve` ingests every `-ingest-interval` (default `24h`). At boot it ingests at once unless the last ingest is within the interval (`boot ingest skipped; data within schedule window`).
- `-no-scheduler` turns this off, for read-only replicas. Run the `ingest` subcommand from one place instead.
- `POST /v1/ingest` starts an ingest now. It needs `Authorization: Bearer <token>` when `-admin-token` is set (no auth otherwise), and answers 409 `ingest already running` while this process is ingesting. `GET /v1/ingest` reports status.
- Every ingest takes the same database lock, so two never overlap.

## Project structure

```
cmd/server/          flags, subcommands (serve, ingest, stats, query), adapter registry
pkg/source/          Adapter interface; one package per adapter type; httpretry/
pkg/csaf/            CSAF parsing, PURL helpers
pkg/openvex/         OpenVEX types and response encoder
pkg/aliases/         alias fetchers
pkg/resolver/        query-time identifier expansion
pkg/ingest/          orchestrator: sync, write, removal
pkg/db/              Store interface, version matching; postgres/ backend, dbtest/ fake
pkg/api/             HTTP handlers
pkg/uservex/         user-supplied VEX
test/integration/    end-to-end tests
test/acceptance/     trimmed vendor feeds checked against exact answers
config.yaml          adapters and alias fetchers
```
