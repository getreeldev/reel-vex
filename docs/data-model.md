# reel-vex data model

Schema for the SQLite database that backs reel-vex. Migrations are applied automatically on every binary boot via `pkg/db/migrations.go`; a `schema_version` table tracks the current revision.

## Tables

```sql
CREATE TABLE vendors (
    id   TEXT PRIMARY KEY,  -- e.g. "redhat", "suse"
    name TEXT NOT NULL      -- e.g. "Red Hat"
);

CREATE TABLE adapter_state (
    adapter_id  TEXT PRIMARY KEY,  -- unique per adapter instance
    feed_url    TEXT,              -- canonical upstream URL
    last_synced TEXT,              -- RFC3339; newest upstream data absorbed
    updated     TEXT NOT NULL      -- RFC3339; last time we wrote this row
);

CREATE TABLE statements (
    vendor        TEXT NOT NULL,   -- from Adapter.Vendor()
    cve           TEXT NOT NULL,
    product_id    TEXT NOT NULL,   -- full PURL or CPE
    base_id       TEXT NOT NULL,   -- normalized base for indexing
    version       TEXT,
    id_type       TEXT NOT NULL,   -- "purl" or "cpe"
    status        TEXT NOT NULL,   -- not_affected, fixed, affected, under_investigation
    justification TEXT,            -- for not_affected only
    updated       TEXT NOT NULL,   -- RFC3339 from the upstream advisory
    source_format TEXT NOT NULL DEFAULT 'csaf',  -- "csaf" | "oval"
    PRIMARY KEY (vendor, cve, product_id, source_format)
);

CREATE TABLE product_aliases (
    vendor     TEXT NOT NULL,
    source_ns  TEXT NOT NULL,      -- e.g. "repository_id"
    source_id  TEXT NOT NULL,      -- e.g. "rhel-8-for-x86_64-appstream-rpms"
    target_ns  TEXT NOT NULL,      -- e.g. "cpe"
    target_id  TEXT NOT NULL,      -- e.g. "cpe:/a:redhat:enterprise_linux:8::appstream"
    confidence REAL NOT NULL DEFAULT 1.0,
    updated    TEXT NOT NULL,
    PRIMARY KEY (vendor, source_ns, source_id, target_ns, target_id)
);
```

## Notes

- `statements` PK is `(vendor, cve, product_id, source_format)` — the same vendor + CVE + product combo can appear under different upstream feeds (CSAF and OVAL for Red Hat, for example) and both rows are preserved.
- `base_id` is the normalized form of `product_id` used by the resolver: PURLs stripped of `@version` and most qualifiers (but `distro` preserved for deb-shaped identity); CPEs as-is. Indexed for `/v1/resolve` lookups.
- `vendors` is display metadata only; runtime data (feed URLs, watermarks) lives in `adapter_state` so multiple adapters under one vendor (e.g., several Red Hat OVAL streams) don't stomp on each other.
- A `schema_version` table tracks migration state. Forward-migration is automatic on every binary boot; rollback is manual (restore from a pre-upgrade backup).
