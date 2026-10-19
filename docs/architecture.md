# reel-vex architecture

How reel-vex fills its database, and what an operator controls. The HTTP API is in [`api.md`](./api.md), the tables in [`data-model.md`](./data-model.md).

- **VEX** (Vulnerability Exploitability eXchange): a vendor's verdict on whether a CVE affects a product.
- **PURL** (package URL) and **CPE** (Common Platform Enumeration): two ways to name the product, e.g. `pkg:deb/debian/zlib?distro=debian-12` and `cpe:/a:redhat:enterprise_linux:8::appstream`.
- **Adapter**: the code that reads one feed. Each feed in `config.yaml` is one adapter with its own `id`.
- **Removal** deletes the rows a vendor no longer publishes. A **sweep** is removal across a whole feed.

## How ingest works

An ingest runs each adapter in `config.yaml` in turn: it reads the vendor's statements, writes them, and runs [removal](#removal). Then the alias fetchers run, and the first ingest builds the query index. A failing adapter is logged (`adapter ingest failed`) and skipped.

Each adapter keeps a **watermark**: the newest statement date it read (Ubuntu OpenVEX: the tarball's `Last-Modified`). The first run reads the whole feed, later runs what the table below says.

## Feeds

| `type` | Feeds | A later run reads |
|---|---|---|
| `csaf` | Red Hat, SUSE | the documents `changes.csv` lists since the watermark |
| `ubuntu-vex` | Canonical OpenVEX, all releases | nothing if `Last-Modified` has not moved, else the changed documents |
| `ubuntu-oval`, `debian-oval`, `almalinux-oval`, `oracle-oval` | Ubuntu focal/jammy/noble, Debian bullseye/bookworm/trixie, AlmaLinux and Oracle Linux 8/9/10 | nothing if `Last-Modified` has not moved, else the whole file |
| `alpine-secdb` | Alpine 3.19 to 3.24, `main` and `community` | as OVAL |
| `amazon-alas` | Amazon Linux 2 and 2023, core repos | the whole feed |
| `rancher-vex` | SUSE Rancher VEX hub | the whole snapshot |

An unchanged file logs `up to date, skipping GET`. OVAL is parsed by the [`oval-to-vex`](https://github.com/getreeldev/oval-to-vex) library. Each feed's code is under [pkg/source](../pkg/source).

### Red Hat and SUSE (CSAF)

- Every run reads `changes.csv` (what changed) and `index.txt` (what is live) first.
- **First run.** Red Hat's weekly bulk archive (`archive_latest.txt`) is read locally, and only documents changed since it, or missing from it, are fetched. SUSE has no archive, so every document is fetched.
- SUSE's `recommended` and `first_fixed` are stored as `fixed`.

<details><summary>When a document cannot be read</summary>

- An error page served with HTTP 200 is a failed read. A 404 or 410 for a document `index.txt` no longer lists is a withdrawal. One it still lists logs WARN `csaf document gone but not withdrawn`.
- A failed document is read again about 30 s later, then on the next run. Once its `changes.csv` date is over 7 days old it is given up on until republished (WARN `csaf document failed and is older than the retry window; giving up on it`).
- If `index.txt` lacks a document this run fetched, nothing is withdrawn (WARN `csaf index.txt lacks documents fetched this run; no live manifest this run`).
</details>

### Canonical OpenVEX (`ubuntu-vex`)

One tarball, one document per CVE, including Canonical's triage before a USN (Ubuntu Security Notice). The Ubuntu OVAL feeds complement it.

- **It reads every document** on a first run, when removal is off (`-sweep-max-fraction 0`), and when a publish changed over a fifth of the documents and over 1,000 (WARN `ubuntu-vex reading every document`). A whole read is swept, unless a document was skipped as malformed or over 256 MiB.
- Canonical's `distro` values (`ubuntu/jammy`, `esm-infra/xenial`) are stored as the `ubuntu-<version>` scanners send.
- **To force a whole read**, delete the adapter's rows in the `adapter_documents` table. Clear its `last_synced` in `adapter_state` too, to fetch now rather than at the next publish.

### OVAL, Alpine and Amazon

- **Ubuntu and Debian** rows are `pkg:deb/<vendor>/<name>?distro=<vendor>-<version>`. The `distro` is part of the identity: focal and noble `openssl` are different products.
- **AlmaLinux** reads its release from `alsa-<N>` in the URL, and writes rows under both `pkg:rpm/almalinux/` and `pkg:rpm/alma/`, because scanners use both.
- **Oracle Linux**: each adapter keeps only its own release, read from `ol<N>` in the URL. Without one, the server refuses to start. Ksplice variants are skipped.
- **Alpine**: the secdb key `"0"` is stored as `not_affected` (`vulnerable_code_not_present`). A CVE under several keys is one row, at the highest fixed version.
- **Amazon**: every advisory package is `fixed`.

A scanner's point release also finds the feed's major or major.minor: `alpine-3.21.2` finds `alpine-3.21`, and likewise for Amazon, AlmaLinux, Debian and Oracle.

### Rancher VEX hub (`rancher-vex`)

`not_affected` verdicts for packages inside SUSE's cloud-native images. Each is **product-scoped**: it is about a package inside one image or Go module, and is returned only when the caller names that image. See [`api.md`](./api.md#product-scoped-statements). A sweep runs only when every file the snapshot lists parsed. Statements with no CVE name or no usable package are skipped and counted in the sync log (`skipped_*`).

## Alias fetchers

Alias fetchers load vendor mapping files. The one today, Red Hat's `repository-to-cpe.json`, lets `?repository_id=rhel-8-for-x86_64-appstream-rpms` match statements filed under `cpe:/a:redhat:enterprise_linux:8::appstream`. Aliases are added and updated, never removed.

## Removal

Removal runs right after each adapter's sync, and touches only rows that adapter wrote last. Rows written before 0.13 have no owner and are never removed. The code is in [pkg/ingest](../pkg/ingest).

| Mechanism | Runs when | Deletes | Refused when |
|---|---|---|---|
| **Whole-feed sweep** | the run read the whole feed without error | the adapter's rows it did not see this run | over `-sweep-max-fraction` of the adapter's rows would go, or the run saw nothing |
| **Per-document replacement** | documents read in full on a run that is not whole (CSAF, Ubuntu OpenVEX) | those CVEs' rows the document no longer states | never: a re-published document is the vendor's whole answer |
| **Withdrawal** | Red Hat and SUSE with a trusted `index.txt`; Ubuntu OpenVEX when it read only changed documents | every row of a CVE the vendor's list of live CVEs no longer names, unless this run read it | the list is empty, or over `-sweep-max-fraction` of the adapter's CVEs would go |

- **Nothing is removed** when the run cannot vouch for what it read: a sync error, a failed write, a run cut short by `-limit` (an `ingest` flag for testing), or an unchanged file. A CSAF run with failed documents still replaces what it read, and still withdraws.
- **A failed or refused removal never fails the adapter.** The rows stay, and the next run that reads the feed again retries: every run for Amazon, Rancher and withdrawals; the next changed file for OVAL and Alpine; a CSAF document only when it changes again. Ubuntu OpenVEX holds its watermark, so its next run fetches the same tarball again.
- **A changed verdict is a new row.** While removal is off or refused, the old and new verdicts are both served.
- **One ingest at a time** per database. A second one stops with `another ingest is running`: the `ingest` subcommand exits non-zero, and a scheduled run in `serve` retries at the next interval.

### Operator controls

| Flag | Default | Effect |
|---|---|---|
| `-sweep-max-fraction` | `0.2` | Fraction guard for sweeps and withdrawals, within `[0, 1]` (anything else refuses to start). `0` turns all removal off. `1` lifts the fraction guards. |
| `-sweep-force <id>[,<id>…]` | none | Lifts the fraction guards for the named adapters only. An unknown id refuses to start. No effect when `-sweep-max-fraction` is `0`. |

- **A refused sweep stays refused** on every retry above, because the rows it would delete are still there. Check the vendor really dropped that much, run one ingest with `-sweep-force <adapter-id>`, then remove the flag. On `serve` it applies until a restart without it.
- Neither `1` nor `-sweep-force` lifts the `nothing seen` or `empty manifest` refusals.

### Log lines to watch

Every adapter that reaches its sync logs one `sweep` line. Red Hat, SUSE and Ubuntu OpenVEX also log a `withdraw` line when they had a list of live CVEs and removal was not skipped.

```
INFO sweep adapter=ubuntu-vex scope=all seen=195636880 owned=195702113 deleted=65233
WARN sweep adapter=alpine-secdb-v3.21-main scope=all seen=5120 owned=7012 deleted=0 refused="would delete 1892 of 7012 owned rows (26.98%), over the 20.00% limit"
INFO withdraw adapter=redhat live=69854 held_cves=69864 withdrawn_cves=10 deleted=963
```

(Numbers illustrative.)

- `scope=all` is a whole-feed sweep. `scope=cves:<n>` replaces `n` CVEs.
- `skipped=incomplete` (normal for an unchanged feed) or another reason: `disabled`, `sync error`, `flush error`, `limit`, `start error`, `aborted`.
- **Refused**: WARN, `deleted=0`, `refused="<reason>"`. **Failed**: ERROR with `error=`. A forced sweep or withdrawal adds `forced=true`.

### Disk headroom

Sweeping the full Ubuntu OpenVEX feed needs up to about 116 GB of temporary disk above the database's size, for about 85 minutes. Provision for it on a first ingest and whenever Ubuntu OpenVEX reads every document. The temporary files are capped at 100 GB only when reel-vex's database role is a superuser.

Set `wal_compression=lz4`, as the bundled `docker-compose.yml` does, to cut the WAL that deletes write. Each sweep statement is capped at 2 hours, and each sweep at 6. On slow storage a full Ubuntu OpenVEX sweep can hit it and log an ERROR `sweep` line.

## Scheduling

- `serve` ingests every `-ingest-interval` (default `24h`). At boot it ingests at once, unless the last ingest is within the interval (`boot ingest skipped; data within schedule window`).
- `-no-scheduler` turns this off, for read-only replicas. Run the `ingest` subcommand elsewhere.
- `POST /v1/ingest` starts an ingest now. It needs `Authorization: Bearer <token>` when `-admin-token` is set (no auth otherwise), and answers 409 `ingest already running` while this process is ingesting. `GET /v1/ingest` reports status.

## Where the code is

```
cmd/server/        flags and subcommands (serve, ingest, stats, query)
pkg/source/        one package per feed type
pkg/resolver/      identifier translation at query time
pkg/ingest/        ingest and removal
pkg/db/postgres/   storage and migrations
pkg/api/           HTTP handlers
test/acceptance/   trimmed vendor feeds checked against exact answers
```
