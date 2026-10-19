# reel-vex data model

The PostgreSQL schema behind reel-vex. Migrations are in [pkg/db/postgres/migrations.go](../pkg/db/postgres/migrations.go) and run on every start. The `schema_version` table records the last one applied. Migrations are forward-only: to roll back, restore a backup taken before the upgrade.

A **VEX** statement is a vendor's verdict on whether a CVE affects a product, named by a **PURL** (`pkg:deb/debian/zlib?distro=debian-12`) or a **CPE** (`cpe:/a:redhat:enterprise_linux:8::appstream`). An **adapter** reads one configured feed. How rows are written and removed: [`architecture.md`](./architecture.md).

## `statements`

One row per vendor verdict. Primary key: `vendor`, `cve`, `product_id`, `source_format`, `scope`, `stream`, `status`, `justification`.

| Column | Holds |
|---|---|
| `vendor` | e.g. `redhat`, `ubuntu` |
| `cve` | the CVE id |
| `product_id` | the full PURL or CPE as the vendor wrote it, `arch` included |
| `base_id` | the identifier lookups use: a PURL without version, subpath and every qualifier except `distro`; a CPE as is |
| `versions` | the versions stated for this verdict, sorted, no duplicates. Replaced whole on each write. |
| `version_kind` | how a versioned query reads `versions` (below) |
| `id_type` | `purl` or `cpe` |
| `status` | `not_affected`, `fixed`, `affected` or `under_investigation` |
| `justification` | for `not_affected` only |
| `updated` | the vendor's date, RFC 3339 UTC. A write that changes nothing leaves it alone. |
| `source_format` | `csaf`, `oval`, `openvex`, `secdb` or `updateinfo` |
| `scope` | the image or Go module a Rancher verdict is limited to; empty for a package-level verdict. See [`api.md`](./api.md#product-scoped-statements). |
| `stream` | the vendor's product stream; empty for every feed today |
| `adapter_id` | the adapter that last wrote the row. Removal deletes only its own rows, and never one with no owner (written before 0.13). |

Queries never return `stream` or `adapter_id`.

- **A verdict the vendor changes is a new row**, because the verdict is part of the key. The old row stays until [removal](./architecture.md#removal) deletes it.
- The same CVE and product can also appear once per `source_format` (Ubuntu has both OVAL and OpenVEX) and once per `scope`.
- `distro` is part of the identity: `openssl` on `ubuntu-22.04` and on `ubuntu-24.04` are different products.

| `version_kind` | Rows | Matches a versioned query when |
|---|---|---|
| `exact` | Ubuntu OpenVEX, Rancher | the version is in `versions`. An empty list matches any version. |
| `boundary` | `fixed` rows of the OVAL feeds, Alpine and Amazon | the version is at or above the fixed-in version in `versions` |
| empty | Red Hat and SUSE CSAF, and the other verdicts of the fixed-in feeds | always: the version is ignored |

Client view: [`api.md`](./api.md#versioned-queries).

## Other tables

| Table | Key | Columns |
|---|---|---|
| `vendors` | `id` | `name` (display only, e.g. `Red Hat`) |
| `adapter_state` | `adapter_id` | `feed_url`, `last_synced` (the watermark, RFC 3339), `updated` |
| `adapter_documents` | `adapter_id`, `document` | `fingerprint` of each document Ubuntu OpenVEX read last, by CVE id. Delete an adapter's rows to make its next fetch read every document. |
| `product_aliases` | `vendor`, `source_ns`, `source_id`, `target_ns`, `target_id` | `confidence` (default `1.0`), `updated`. E.g. `repository_id` `rhel-8-for-x86_64-appstream-rpms` → `cpe` `cpe:/a:redhat:enterprise_linux:8::appstream`. |

Indexes are in the migrations, except `idx_statements_broad` on `statements`, which the first ingest builds. Tables named `sweep_seen_*` are temporary working tables of an ingest, not part of the schema.

## Migrations

| Version | Adds |
|---|---|
| v1 | `vendors`, `statements`, `product_aliases`, `adapter_state` |
| v2 | `statements.adapter_id`, its index, and autovacuum settings for `statements` |
| v3 | one row per verdict: `versions`, `version_kind`, `stream`, and the current primary key |
| v4 | `adapter_documents` |
