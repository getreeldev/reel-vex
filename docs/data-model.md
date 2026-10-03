# reel-vex data model

Schema for the PostgreSQL database that backs reel-vex. Migrations are applied automatically on every binary boot via `pkg/db/postgres/migrations.go`; a `schema_version` table tracks the current revision. The Postgres backend is greenfield — schema v1 declares the shape below directly.

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
    updated     TEXT NOT NULL      -- RFC3339; when this row was last written
);

CREATE TABLE statements (
    vendor        TEXT NOT NULL,   -- from Adapter.Vendor()
    cve           TEXT NOT NULL,
    product_id    TEXT NOT NULL,   -- full PURL or CPE
    base_id       TEXT NOT NULL,   -- normalized base for indexing
    versions      TEXT[] NOT NULL DEFAULT '{}',  -- versions stated for this verdict, sorted, de-duplicated
    version_kind  TEXT NOT NULL DEFAULT '',      -- '' (legacy) | 'exact' | 'boundary'
    id_type       TEXT NOT NULL,   -- "purl" or "cpe"
    status        TEXT NOT NULL,   -- not_affected, fixed, affected, under_investigation
    justification TEXT NOT NULL DEFAULT '',      -- for not_affected only
    updated       TEXT NOT NULL,   -- RFC3339 from the upstream advisory
    source_format TEXT NOT NULL DEFAULT 'csaf',  -- "csaf" | "oval" | "openvex" | "secdb" | "updateinfo"
    scope         TEXT NOT NULL DEFAULT '',      -- product the verdict is scoped to ('' = unscoped/package-level)
    stream        TEXT NOT NULL DEFAULT '',      -- vendor product stream a boundary holds within ('' today)
    adapter_id    TEXT,            -- the adapter that last inserted or changed the row
    PRIMARY KEY (vendor, cve, product_id, source_format, scope, stream, status, justification)
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

- `statements` PK is `(vendor, cve, product_id, source_format, scope, stream, status, justification)` — the same vendor + CVE + product combo can appear under different upstream feeds (OpenVEX and OVAL for Ubuntu), for product-scoped sources under different products, and once per verdict; all such rows are preserved.
- **One row per verdict, carrying the versions stated for it** (schema v3). `versions` is sorted and de-duplicated on write, so a list that differs only in order is not a change; a re-insert rewrites a row only when its `versions`, `base_id`, `id_type` or `version_kind` changed. `version_kind` says how the list is read: `''` (every feed today: one version per statement, so the list has zero or one element), `'exact'` (the queried version must be in the list) or `'boundary'` (fixed-in boundaries). `stream` is the vendor product stream a boundary holds within (CSAF's `relates_to` product); it is `''` for every feed today and keyed now so that recording it never changes the primary key. Neither `stream` nor `adapter_id` is returned by queries.
- `scope` restricts a statement to one product context — an OpenVEX product `@id` such as a container image or Go module. It is `''` for every package-level feed (CSAF, OVAL, Canonical OpenVEX), leaving their storage and query behaviour unchanged. Subcomponent-scoped sources (the Rancher VEX hub) set it: the matchable package is stored in `product_id`/`base_id` while `scope` records *which image/module the verdict was made about*. The query layer only surfaces a scoped row when the caller names a matching scope (see [`api.md`](./api.md)), so a verdict scoped to one image never suppresses the same package elsewhere. Normalised via `pkg/csaf.NormalizeScope` (keeps `repository_url`, strips version/digest).
- `base_id` is the normalized form of `product_id` used by the resolver: PURLs stripped of `@version` and most qualifiers (but `distro` preserved for deb-shaped identity); CPEs as-is. Indexed for `/v1/statements` lookups.
- **`product_id` is the full identifier and keeps what `base_id` drops**, including the `arch` qualifier. Matching is arch-blind by default, but `strict_arch` (see [`api.md`](./api.md)) re-parses `product_id` at query time, so architectures never need to be stored separately or indexed. Rows stay one-per-architecture on purpose: today the vendors publish the same verdict for every arch, but that is data, not a guarantee, and collapsing it at ingest would make a future divergence unrepresentable.
- `vendors` is display metadata only; runtime data (feed URLs, watermarks) lives in `adapter_state` so multiple adapters under one vendor (e.g., one Ubuntu OVAL adapter per release) don't stomp on each other.
- A `schema_version` table tracks migration state. Forward-migration is automatic on every binary boot; the Postgres backend is forward-only (v1 declares the current shape), and rollback is manual (restore from a pre-upgrade backup/snapshot).
- The broad-mode covering index (`idx_statements_broad`) is **not** part of the schema — it's built once after the cold bulk load by `EnsureCoveringIndex` (end of each ingest), so the first load stays index-free; later cycles find it present and just maintain it.
