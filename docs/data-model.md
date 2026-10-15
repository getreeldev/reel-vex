# reel-vex data model

The PostgreSQL schema behind reel-vex. Migrations live in `pkg/db/postgres/migrations.go` and run automatically on every start. A `schema_version` table records the last one applied. Migrations are forward-only: to roll back, restore a backup taken before the upgrade.

Terms used below:

- **VEX**: a vendor's verdict on whether a CVE affects a product.
- **PURL** and **CPE**: the two identifier schemes for that product (`pkg:deb/debian/zlib?distro=debian-12`, `cpe:/a:redhat:enterprise_linux:8::appstream`).
- **Adapter**: the code that reads one configured feed.

For how rows are written and removed, see [`architecture.md`](./architecture.md).

## Tables

```sql
CREATE TABLE statements (
    vendor        TEXT NOT NULL,                 -- e.g. "redhat", "ubuntu"
    cve           TEXT NOT NULL,
    product_id    TEXT NOT NULL,                 -- full PURL or CPE, as the vendor wrote it
    base_id       TEXT NOT NULL,                 -- product_id normalised for lookup
    versions      TEXT[] NOT NULL DEFAULT '{}',  -- versions stated for this verdict, sorted, de-duplicated
    version_kind  TEXT NOT NULL DEFAULT '',      -- '' | 'exact' | 'boundary'
    id_type       TEXT NOT NULL,                 -- 'purl' | 'cpe'
    status        TEXT NOT NULL,                 -- not_affected | fixed | affected | under_investigation
    justification TEXT NOT NULL DEFAULT '',      -- for not_affected only
    updated       TEXT NOT NULL,                 -- RFC 3339 UTC, the vendor's date
    source_format TEXT NOT NULL DEFAULT 'csaf',  -- csaf | oval | openvex | secdb | updateinfo
    scope         TEXT NOT NULL DEFAULT '',      -- image/module a verdict is limited to ('' = package-level)
    stream        TEXT NOT NULL DEFAULT '',      -- vendor product stream ('' for every feed today)
    adapter_id    TEXT,                          -- the adapter that last wrote the row
    PRIMARY KEY (vendor, cve, product_id, source_format, scope, stream, status, justification)
);

CREATE TABLE vendors (
    id   TEXT PRIMARY KEY,                       -- e.g. "redhat"
    name TEXT NOT NULL                           -- e.g. "Red Hat"
);

CREATE TABLE adapter_state (
    adapter_id  TEXT PRIMARY KEY,                -- the adapter's config id
    feed_url    TEXT,
    last_synced TEXT,                            -- RFC 3339 watermark
    updated     TEXT NOT NULL                    -- when this row was last written
);

CREATE TABLE adapter_documents (
    adapter_id  TEXT NOT NULL,                   -- ubuntu-vex only today
    document    TEXT NOT NULL,                   -- the document's CVE id
    fingerprint TEXT NOT NULL,                   -- "<fingerprintVersion>:<sha256 hex>"
    PRIMARY KEY (adapter_id, document)
);

CREATE TABLE product_aliases (
    vendor     TEXT NOT NULL,
    source_ns  TEXT NOT NULL,                    -- e.g. "repository_id"
    source_id  TEXT NOT NULL,                    -- e.g. "rhel-8-for-x86_64-appstream-rpms"
    target_ns  TEXT NOT NULL,                    -- e.g. "cpe"
    target_id  TEXT NOT NULL,                    -- e.g. "cpe:/a:redhat:enterprise_linux:8::appstream"
    confidence REAL NOT NULL DEFAULT 1.0,
    updated    TEXT NOT NULL,
    PRIMARY KEY (vendor, source_ns, source_id, target_ns, target_id)
);
```

Indexes: `statements (cve)`, `statements (source_format)`, `statements (adapter_id, cve)` for removal, and two on `product_aliases` (source and target). The main query index, `idx_statements_broad`, is not in the migrations. It is built at the end of the first ingest, so the initial bulk load runs without it:

```sql
CREATE INDEX idx_statements_broad ON statements (base_id, cve, product_id, source_format)
    INCLUDE (vendor, versions, version_kind, id_type, status, justification, updated, scope);
```

| Version | Adds |
|---|---|
| v1 | `vendors`, `statements`, `product_aliases`, `adapter_state` |
| v2 | `statements.adapter_id`, its index, and autovacuum settings for `statements` |
| v3 | one row per verdict: `versions`, `version_kind`, `stream`, and the current primary key |
| v4 | `adapter_documents` |

## Notes

**One row per verdict.** The verdict (`status`, `justification`) is part of the key. So a verdict the vendor changes is a new row, and the old one stays until [removal](./architecture.md#removal) deletes it. The same CVE and product can also appear once per `source_format` (Ubuntu has both OVAL and OpenVEX) and once per `scope`.

**Writes.** `versions` is sorted and de-duplicated on write. A re-write changes a row's content and `updated` only when `versions`, `base_id`, `id_type` or `version_kind` changed. The list is replaced, never merged.

**`version_kind`** says how a versioned query reads `versions`. Details in [`architecture.md`](./architecture.md#version-lists) and [`api.md`](./api.md#versioned-queries).

| Kind | Rows | `versions` holds | Match |
|---|---|---|---|
| `exact` | Ubuntu OpenVEX, Rancher | every version stated for this verdict. `product_id` has no version. | the queried version is in the list. An empty list matches any version. |
| `boundary` | `fixed` rows of the OVAL feeds, Alpine and Amazon | the fixed-in version, in the feed's own dpkg, rpm or apk syntax | the queried version is at or above it |
| `''` | Red Hat and SUSE CSAF, and the fixed-in feeds' other verdicts (Debian's open `0:0` is `affected`, Alpine's `"0"` is `not_affected`) | at most one version | the version is ignored |

**Ownership.** `adapter_id` is the adapter that last wrote the row. An identical write by another adapter moves only `adapter_id` (an Alpine package that moved between repositories, say), so when the first adapter stops emitting it, its removal cannot delete a row the other still publishes. Removal deletes only the running adapter's rows. It never deletes a row with a NULL `adapter_id`. Such rows exist only in databases filled before 0.13, and an adapter that writes one again takes it over.

**Not returned by queries:** `stream` and `adapter_id`.

**`scope`** is set only by the Rancher VEX hub. The package goes in `product_id`, and the image or Go module the verdict is about goes in `scope` (normalised by `pkg/csaf.NormalizeScope`: version and digest removed, `repository_url` kept). A scoped row is returned only when the caller names a matching scope. See [`api.md`](./api.md#product-scoped-statements).

**`base_id`** is what lookups use. For a PURL it drops the `@version`, the subpath and every qualifier except `distro`. `distro` is identity: `openssl` on `ubuntu-22.04` and `ubuntu-24.04` are different products. A CPE is stored as is.

**`product_id`** keeps everything, including `arch`. Matching ignores architecture by default, and `strict_arch` reads it back from `product_id`. Rows stay one per architecture on purpose: the vendors publish the same verdict for every architecture today, but merging them at ingest would make a future difference impossible to store.

**`adapter_documents`** is what Ubuntu OpenVEX read last. A document whose fingerprint is unchanged is skipped on the next run. The table is cleared before a run changes any row and written again only after that run's removal succeeds. Deleting an adapter's rows here makes its next fetch read every document.

**`vendors`** is display only. Per-feed state (URL, watermark) lives in `adapter_state`, so several adapters under one vendor (one Ubuntu OVAL adapter per release, say) keep separate watermarks.

**Seen tables** (`sweep_seen_*`) exist only while an adapter syncs, to record the keys it emitted. They are not part of the schema.
