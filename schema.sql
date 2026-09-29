-- ============================================================================
-- Domain / Pivot tracking schema (MySQL/MariaDB, InnoDB, utf8mb4)
-- ============================================================================
-- Design summary
-- ---------------
--   domains        one row per unique NORMALIZED domain string
--   pivots         one row per unique pivot STRING, globally deduplicated
--   domain_pivots  many-to-many association, deduplicated per (domain, pivot)
--
-- Dedup mechanism chosen: INSERT ... ON DUPLICATE KEY UPDATE (see application
-- code for why, in short: we need re-submission of an existing row to bump a
-- last_seen_at timestamp, and INSERT IGNORE cannot do that -- it silently
-- discards the row with no way to run an UPDATE clause on the conflict path).
--
-- Collation choice: utf8mb4_bin everywhere.
--   - For `pivots.pivot_text`, this is a HARD REQUIREMENT, not a preference:
--     the spec requires case-sensitive pivot matching. A case-insensitive
--     collation (e.g. utf8mb4_unicode_ci / utf8mb4_0900_ai_ci) would silently
--     treat 'ABC123' and 'abc123' as the same key and collapse them into one
--     row, corrupting distinct investigative artifacts.
--   - For `domains.domain`, the application layer always lowercases before
--     insert (see normalize_domain()), so case sensitivity is moot in
--     practice. utf8mb4_bin is still used here as defense-in-depth: if
--     someone ever writes to this table outside the normalization layer
--     (a manual `INSERT`, a future service, a migration script), a
--     case-insensitive collation would let 'Example.com' and 'example.com'
--     silently coexist as two "different" keys that a human reader would
--     consider identical, or -- worse -- collide unexpectedly with the
--     lowercase row in ways that depend on the specific collation's rules.
--     Binary collation makes the uniqueness constraint mean exactly what it
--     says: unique bytes.
-- ============================================================================

SET NAMES utf8mb4;
SET sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO';

-- ----------------------------------------------------------------------------
-- domains
-- ----------------------------------------------------------------------------
CREATE TABLE domains (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    -- Fully normalized form only: lowercased, scheme/userinfo/path/query/
    -- fragment/port stripped, trailing dot removed, IDN converted to
    -- punycode (see normalize_domain() in the application layer). 253 is the
    -- RFC 1035 maximum length of the textual dotted representation.
    domain        VARCHAR(253) NOT NULL,

    -- First time this domain was ever ingested.
    created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    -- Most recent time this domain was re-submitted. MySQL's
    -- "ON UPDATE CURRENT_TIMESTAMP" auto-bumps this on any UPDATE to the row,
    -- which is exactly the semantics an ON DUPLICATE KEY UPDATE needs.
    last_seen_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                              ON UPDATE CURRENT_TIMESTAMP(6),

    PRIMARY KEY (id),

    -- THE dedup constraint for domains: a domain string can exist exactly
    -- once. This is also the index that makes "look up a domain" and
    -- "does this domain already exist" both O(log n).
    UNIQUE KEY uq_domains_domain (domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
  COMMENT='One row per unique normalized domain.';

-- ----------------------------------------------------------------------------
-- pivots
-- ----------------------------------------------------------------------------
CREATE TABLE pivots (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    -- Arbitrary investigative artifact: IP, hash, email, registrant name,
    -- etc. Stored verbatim (only leading/trailing whitespace and one layer
    -- of wrapping quotes are trimmed) -- NEVER lowercased, because pivot
    -- matching is required to be case-sensitive. 512 chars comfortably
    -- covers IPs, emails, SHA-512 hex digests (128 chars), and most
    -- registrant-name-style free text; enforced identically in Python via
    -- MAX_PIVOT_LENGTH so a too-long value is rejected before it ever
    -- reaches this column.
    pivot_text   VARCHAR(512) NOT NULL,

    created_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    PRIMARY KEY (id),

    -- THE dedup constraint for pivots: the same pivot STRING is stored
    -- exactly once globally, no matter how many domains reference it.
    UNIQUE KEY uq_pivots_text (pivot_text)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
  COMMENT='One row per unique pivot string, deduplicated globally.';

-- ----------------------------------------------------------------------------
-- domain_pivots  (many-to-many junction / association table)
-- ----------------------------------------------------------------------------
CREATE TABLE domain_pivots (
    domain_id     BIGINT UNSIGNED NOT NULL,
    pivot_id      BIGINT UNSIGNED NOT NULL,

    -- First time THIS SPECIFIC domain-pivot pair was observed together.
    created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    -- Most recent time this pair was re-submitted (e.g. domain re-scanned
    -- and the same pivot seen again). Re-adding an existing pair is a
    -- no-op except for bumping this column.
    last_seen_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                              ON UPDATE CURRENT_TIMESTAMP(6),

    -- The composite PRIMARY KEY *is* the UNIQUE(domain_id, pivot_id)
    -- constraint the spec asks for -- a primary key is unique by
    -- definition, so a separate UNIQUE KEY on the same two columns would
    -- just be a redundant, wasted index. This is what makes "add the same
    -- domain-pivot pair twice" collapse into a single row instead of
    -- erroring or duplicating.
    PRIMARY KEY (domain_id, pivot_id),

    -- InnoDB only builds an index on the LEFTMOST prefix of a composite
    -- key, so PRIMARY KEY (domain_id, pivot_id) speeds up "given a domain,
    -- list its pivots" for free, but does nothing for the reverse
    -- direction ("given a pivot, list its domains"). This secondary index
    -- on pivot_id alone is what makes that reverse lookup fast instead of
    -- a full table scan.
    KEY idx_domain_pivots_pivot_id (pivot_id),

    CONSTRAINT fk_dp_domain FOREIGN KEY (domain_id)
        REFERENCES domains(id) ON DELETE CASCADE,
    CONSTRAINT fk_dp_pivot FOREIGN KEY (pivot_id)
        REFERENCES pivots(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
  COMMENT='Many-to-many association between domains and pivots, deduplicated per pair.';
