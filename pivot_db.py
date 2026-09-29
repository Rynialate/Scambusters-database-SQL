"""
pivot_db.py
===========

Application layer for the domain/pivot tracking system.

Library choice: PyMySQL (pure-Python, no compiled C extension, so it
installs the same way in any environment via `pip install pymysql`, unlike
mysql-connector-python which pulls a heavier native/Protobuf dependency
chain, or MySQLdb which needs system dev headers). Its DB-API 2.0 cursor
interface with %s placeholders gives us real server-side parameter binding,
which is what we need for the "never string-concatenated SQL" requirement.

Layout:
  - Validation / normalization functions (pure, no DB access; auditable
    independently of persistence): normalize_domain, sanitize_pivot
  - Parsing (pure, no DB access): parse_entry, _split_records
  - Persistence (parameterized SQL only): get_or_create_domain,
    get_or_create_pivot, link_domain_pivot
  - Public API: add_entry, search
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

import idna
import pymysql
import pymysql.cursors


# ============================================================================
# Exceptions
# ============================================================================

class DomainValidationError(ValueError):
    """Raised when a candidate domain token fails format validation."""


class PivotValidationError(ValueError):
    """Raised when a candidate pivot string fails sanitization."""


class ParseError(ValueError):
    """Raised when a raw entry cannot be split into (domain, pivots)."""


# ============================================================================
# Constants
# ============================================================================

# RFC 1035 §3.1: the maximum length of a domain name's textual dotted
# representation is 253 characters (255 octets minus the length-prefix
# bytes and trailing root label).
MAX_DOMAIN_LENGTH = 253

# Matches VARCHAR(512) on pivots.pivot_text in schema.sql.
MAX_PIVOT_LENGTH = 512

# A hard ceiling on a whole raw input string/line before we even try to
# parse it, to keep pathological input (megabytes of text) from being
# tokenized at all.
MAX_RAW_INPUT_LENGTH = 8192

# Each DNS label: 1-63 chars, alphanumeric or hyphen, cannot start or end
# with a hyphen (RFC 1035 / RFC 1123).
_LABEL_RE = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')

# A syntactically valid TLD is alphabetic (>=2 chars) or an IDNA ACE label
# (xn--...). This deliberately rejects all-numeric final labels so that
# bare IPv4 addresses like "1.2.3.4" are NOT accepted as "domains" -- IPs
# are pivots in this system, not domains.
_TLD_RE = re.compile(r'^([A-Za-z]{2,}|xn--[A-Za-z0-9-]+)$')

# Control characters (excluding nothing -- all of C0 plus DEL) and the NUL
# byte specifically called out in the spec.
_CONTROL_CHAR_RE = re.compile(r'[\x00-\x1f\x7f]')

# Tokenizer for free-text / delimited formats. Splits on whitespace, comma,
# semicolon, and colon -- but deliberately NOT on '.', because domains,
# IPv4 addresses, IPv6 addresses, and email-address pivots all legitimately
# contain dots as part of a single token.
_TOKEN_SPLIT_RE = re.compile(r'[,;:\s]+')


# ============================================================================
# Validation / normalization (pure functions, no DB access)
# ============================================================================

def _reject_control_chars(s: str, what: str) -> None:
    if _CONTROL_CHAR_RE.search(s):
        raise ValueError(f"{what} contains null bytes or control characters")


def normalize_domain(raw: str) -> str:
    """
    Normalize a raw domain-ish string into canonical storage form:
      1. Trim whitespace.
      2. Reject null bytes / control characters / excessive length up front.
      3. Strip a URL scheme ("http://", "https://", "ftp://", ...) if present.
      4. Strip "user:pass@" userinfo if present.
      5. Cut off any path, query string, or fragment.
      6. Strip a trailing port (":8080"). IPv6 literals ("[::1]") are
         rejected outright -- this system stores *domains*, not IP
         literals; IPs belong in the pivots table.
      7. Lowercase.
      8. Strip a single trailing dot (the "root" dot of an FQDN).
      9. IDNA/punycode-encode so Unicode (internationalized) domains are
         stored in a single canonical ASCII form (uts46=True normalizes
         common look-alike/full-width variants before encoding, matching
         how browsers resolve IDNs).
     10. Validate the *encoded* result against strict DNS label rules,
         requiring >= 2 labels and a syntactically plausible TLD.

    Raises DomainValidationError with a human-readable reason on any
    failure. Never raises any other exception type for malformed input.
    """
    if raw is None:
        raise DomainValidationError("domain is missing")

    s = raw.strip()
    if not s:
        raise DomainValidationError("domain is empty")
    if len(s) > MAX_RAW_INPUT_LENGTH:
        raise DomainValidationError("input exceeds maximum allowed length")
    try:
        _reject_control_chars(s, "domain")
    except ValueError as e:
        raise DomainValidationError(str(e)) from e

    # 3. Strip scheme, e.g. "https://example.com/path" -> "example.com/path"
    s = re.sub(r'^[A-Za-z][A-Za-z0-9+.-]*://', '', s)
    # Handle a bare "//host" (scheme-relative URL) form too.
    if s.startswith('//'):
        s = s[2:]

    # 4. Cut off everything from the first path/query/fragment separator
    # onward, leaving only the host[:port] (plus optional userinfo@)
    # portion to work with.
    path_match = re.search(r'[\/\?\#]', s)
    host_part = s[:path_match.start()] if path_match else s

    # Strip "user:pass@" userinfo, if present, from what's left.
    if '@' in host_part:
        host_part = host_part.rsplit('@', 1)[1]

    if not host_part:
        raise DomainValidationError("no host portion found")

    # 6. Reject IPv6 literals explicitly (they are pivots, not domains).
    if host_part.startswith('['):
        raise DomainValidationError(
            "IPv6 literals are not domains; store them as pivots instead")

    # Strip a trailing ":port".
    if host_part.count(':') == 1:
        host_part, _sep, port = host_part.partition(':')
        if not port.isdigit():
            raise DomainValidationError(f"invalid port suffix: {port!r}")
    elif host_part.count(':') > 1:
        raise DomainValidationError("malformed host (unexpected ':')")

    # 7. Lowercase.
    host_part = host_part.lower()

    # 8. Strip a single trailing dot.
    host_part = host_part.rstrip('.')
    if not host_part:
        raise DomainValidationError("domain is empty after normalization")

    # 9. IDNA / punycode encode. uts46=True applies Unicode TR46 mapping
    # (case-folding, full-width -> ASCII, etc.) before ToASCII, which is
    # what real-world IDN-aware resolvers do.
    try:
        encoded_bytes = idna.encode(host_part, uts46=True)
    except idna.IDNAError as e:
        raise DomainValidationError(f"invalid internationalized domain: {e}") from e
    except UnicodeError as e:
        raise DomainValidationError(f"invalid domain encoding: {e}") from e
    encoded = encoded_bytes.decode('ascii')

    # 10. Strict structural validation of the ASCII/punycode form.
    if len(encoded) > MAX_DOMAIN_LENGTH:
        raise DomainValidationError(
            f"domain exceeds max length of {MAX_DOMAIN_LENGTH}")

    labels = encoded.split('.')
    if len(labels) < 2:
        raise DomainValidationError(
            "domain must have at least two labels (e.g. 'name.tld')")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise DomainValidationError(f"invalid domain label: {label!r}")
    if not _TLD_RE.match(labels[-1]):
        raise DomainValidationError(f"invalid top-level domain: {labels[-1]!r}")

    return encoded


def _looks_like_domain(token: str) -> bool:
    """True if `token` would survive normalize_domain() unchanged in kind
    (used only to *classify* tokens during parsing; the caller still calls
    normalize_domain() again to get the canonical stored form)."""
    try:
        normalize_domain(token)
        return True
    except DomainValidationError:
        return False


def sanitize_pivot(raw: str) -> str:
    """
    Validate and normalize a candidate pivot string. Pivots are stored
    verbatim (case preserved -- matching is case-sensitive) apart from:
      - surrounding whitespace, trimmed
      - one layer of surrounding straight quotes, trimmed (an artifact of
        naive delimiter-splitting of quoted CSV/JSON-ish input)

    Raises PivotValidationError on null bytes/control characters or
    excessive length. Returns '' for input that is empty after trimming
    (callers treat '' as "skip this candidate", not an error -- empty
    tokens are common noise from splitting, not malicious input).
    """
    if raw is None:
        return ''
    s = str(raw).strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        s = s[1:-1].strip()
    if not s:
        return ''
    _reject_control_chars(s, "pivot")
    if len(s) > MAX_PIVOT_LENGTH:
        raise PivotValidationError(
            f"pivot exceeds max length of {MAX_PIVOT_LENGTH}: {s[:40]!r}...")
    return s


# ============================================================================
# Parsing (pure functions, no DB access)
# ============================================================================

def _split_records(raw: str) -> list[str]:
    """
    Split a raw multi-format input into a list of individual record
    strings, each of which is handed to parse_entry() independently.

    - If the ENTIRE input parses as JSON, it is treated as a single record
      (we do not split JSON on internal newlines/whitespace).
    - Otherwise, the input is split on newlines: "multi-line input with one
      domain-plus-pivots record per line" (spec section 3) becomes one
      record per non-blank line.
    - A single-line, non-JSON input is returned as a single record.
    """
    if raw is None:
        raise ParseError("input is missing")
    if len(raw) > MAX_RAW_INPUT_LENGTH:
        raise ParseError("input exceeds maximum allowed length")
    stripped = raw.strip()
    if not stripped:
        raise ParseError("input is empty")

    try:
        json.loads(stripped)
        return [stripped]
    except json.JSONDecodeError:
        pass

    lines = [ln.strip() for ln in stripped.splitlines() if ln.strip()]
    return lines if lines else [stripped]


def parse_entry(raw: str) -> tuple[str, list[str]]:
    """
    Parse a single record into (domain_raw, pivots_raw). Handles:
      - JSON object: {"domain": "...", "pivots": [...]}
      - Delimited/free text: tokens separated by whitespace, ',', ';', ':'
        (NOT '.', since domains/IPs/emails all legitimately contain dots)

    Domain-token detection rule (explicit, as required by the spec):
    tokens are scanned LEFT TO RIGHT and the FIRST token that passes strict
    domain-format validation (normalize_domain succeeds) is taken as THE
    domain. Every other token -- including any later token that also
    happens to look like a domain -- is treated as a pivot. Rationale:
    "first match wins" is simple, deterministic, and matches the natural
    reading order of every example format in the spec (domain always comes
    first). We do not silently guess among multiple domain-looking tokens
    beyond that rule, and we do not reject as "ambiguous", because rejecting
    would make legitimate inputs like "example.com backup-domain.net" (a
    domain plus a *pivot* that happens to itself be a resolvable name, e.g.
    a related/typosquat domain used as an investigative artifact) fail for
    no good reason -- treating extra domain-looking tokens as pivots is the
    more useful default for this system.

    Raises ParseError if the record is empty/unparseable, or if no token
    validates as a domain at all.
    """
    if raw is None:
        raise ParseError("entry is missing")
    s = raw.strip()
    if not s:
        raise ParseError("entry is empty")

    if s.startswith('{'):
        try:
            obj = json.loads(s)
        except json.JSONDecodeError as e:
            raise ParseError(f"entry looks like JSON but failed to parse: {e}") from e
        if not isinstance(obj, dict):
            raise ParseError("JSON entry must be an object")
        if 'domain' not in obj or obj['domain'] is None:
            raise ParseError("JSON entry is missing required 'domain' key")
        domain_raw = str(obj['domain'])
        pivots_field = obj.get('pivots', [])
        if not isinstance(pivots_field, list):
            raise ParseError("JSON 'pivots' field must be a list")
        pivots_raw = [str(p) for p in pivots_field]
        return domain_raw, pivots_raw

    tokens = [t for t in _TOKEN_SPLIT_RE.split(s) if t]
    if not tokens:
        raise ParseError("no tokens found in entry")

    domain_raw = None
    domain_idx = None
    for i, tok in enumerate(tokens):
        if _looks_like_domain(tok):
            domain_raw, domain_idx = tok, i
            break  # first-match-wins disambiguation rule, see docstring

    if domain_raw is None:
        raise ParseError(
            "no token in entry validates as a domain "
            f"(tokens seen: {tokens!r})")

    pivots_raw = [t for i, t in enumerate(tokens) if i != domain_idx]
    return domain_raw, pivots_raw


# ============================================================================
# Persistence (parameterized SQL exclusively -- no string-built SQL anywhere)
# ============================================================================

def get_connection() -> pymysql.connections.Connection:
    """
    Open a new DB connection from environment-provided configuration.
    autocommit is OFF: add_entry() wraps its writes in an explicit
    transaction so a domain row and its pivot links are committed (or
    rolled back) atomically.
    """
    return pymysql.connect(
        host=os.environ.get('PIVOT_DB_HOST', '127.0.0.1'),
        port=int(os.environ.get('PIVOT_DB_PORT', '3306')),
        user=os.environ.get('PIVOT_DB_USER', 'pivot_app'),
        password=os.environ.get('PIVOT_DB_PASSWORD', ''),
        database=os.environ.get('PIVOT_DB_NAME', 'pivot_tracker'),
        charset='utf8mb4',
        autocommit=False,
    )


def get_or_create_domain(conn: pymysql.connections.Connection, domain: str) -> int:
    """
    Insert `domain` if new, or -- if it already exists -- update its
    last_seen_at and return its EXISTING id, all in one round trip.

    Chosen dedup mechanism: INSERT ... ON DUPLICATE KEY UPDATE, not
    INSERT IGNORE. Rationale: INSERT IGNORE would silently drop the insert
    on a duplicate key and leave last_seen_at untouched -- there is no
    UPDATE clause it can run. Since the spec explicitly requires re-adding
    an existing domain/pivot pair to refresh a "last seen" time rather than
    just no-op silently, ON DUPLICATE KEY UPDATE is the only one of the two
    that can express that. The `id = LAST_INSERT_ID(id)` trick makes
    cursor.lastrowid return the EXISTING row's id on the duplicate-key path
    (instead of 0, which is what a plain ON DUPLICATE KEY UPDATE would
    otherwise leave it as), so callers always get a usable id either way.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO domains (domain)
            VALUES (%s)
            ON DUPLICATE KEY UPDATE
                last_seen_at = CURRENT_TIMESTAMP(6),
                id = LAST_INSERT_ID(id)
            """,
            (domain,),
        )
        return cur.lastrowid


def get_or_create_pivot(conn: pymysql.connections.Connection, pivot_text: str) -> int:
    """Same INSERT ... ON DUPLICATE KEY UPDATE pattern as
    get_or_create_domain(), applied to the globally-deduplicated pivots
    table. (pivots have no last_seen_at of their own -- "last seen" is
    tracked per domain-pivot association in domain_pivots, since the same
    pivot string can be freshly re-observed on one domain while being
    stale on another.)"""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO pivots (pivot_text)
            VALUES (%s)
            ON DUPLICATE KEY UPDATE
                id = LAST_INSERT_ID(id)
            """,
            (pivot_text,),
        )
        return cur.lastrowid


def link_domain_pivot(conn: pymysql.connections.Connection, domain_id: int, pivot_id: int) -> None:
    """
    Associate a domain with a pivot. If the (domain_id, pivot_id) pair
    already exists, this is a true no-op on the data (no new row, no
    duplicate storage) except for bumping last_seen_at -- this is exactly
    the "accumulation" behavior required by spec section 1a: submitting the
    same pivot for the same domain on a later date must not create a
    second association row.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO domain_pivots (domain_id, pivot_id)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE last_seen_at = CURRENT_TIMESTAMP(6)
            """,
            (domain_id, pivot_id),
        )


# ============================================================================
# Bulk persistence -- for tens of thousands of rows in one request
# ============================================================================
#
# Why this exists as separate code, not just "call add_entry() in a loop":
#
# add_entry()'s get_or_create_domain/pivot + link_domain_pivot pattern does
# one round trip per row per table (domain upsert, then N pivot upserts,
# then N link upserts) inside its own commit. That is fine at human scale
# (a person pasting a few lines) but breaks down at tens of thousands of
# rows for two separate reasons:
#
#   1. Round trips. Even a fast localhost MySQL connection has real
#      per-query overhead (network syscall + protocol parsing), typically
#      low milliseconds. Multiply that by ~3 queries per pivot across
#      30,000 rows averaging a few pivots each, and you're issuing
#      hundreds of thousands of individual queries -- minutes of wall
#      clock time spent almost entirely on round-trip latency, not on the
#      database actually doing work.
#
#   2. Commits. add_entry() calls conn.commit() once per RECORD.  A commit
#      on an InnoDB table durably syncs the transaction log to disk. Tens
#      of thousands of individual commits means tens of thousands of
#      fsyncs, which is often the single biggest cost in a naive
#      "insert one row, commit, repeat" bulk load -- far more than the
#      inserts themselves.
#
# The fix for both: batch many rows into few multi-row INSERT statements
# (BULK_CHUNK_SIZE rows per statement), and commit once for the whole
# batch (or once per bulk API call) instead of once per row.
#
# Multi-row INSERT ... ON DUPLICATE KEY UPDATE is built explicitly here
# (INSERT INTO t (col) VALUES (%s),(%s),(%s) ON DUPLICATE KEY UPDATE ...)
# rather than relying on PyMySQL's executemany() to auto-batch a
# single-row INSERT template into a multi-row statement. PyMySQL *can* do
# that rewrite for simple INSERTs, but whether it recognizes an
# ON DUPLICATE KEY UPDATE clause when deciding how to batch is an
# internal, undocumented detail of that optimization rather than a
# guaranteed part of its public API -- building the multi-row SQL text
# ourselves means the actual statement sent to the server is exactly what
# the code says, and it doesn't get silently slower (falling back to
# one-row-at-a-time) if a future PyMySQL version changes that heuristic.
#
# The other structural difference from the single-row helpers: those use
# `id = LAST_INSERT_ID(id)` so a single-row upsert's result tells you that
# row's id whether it was inserted or already existed. That trick doesn't
# generalize to a multi-row INSERT -- MySQL only reports one id back per
# *statement*, not one per row. So bulk upsert and "get me the ids" are
# two separate steps here: upsert everything in a chunk, then a follow-up
# SELECT ... WHERE col IN (...) to fetch the {value: id} mapping for the
# whole chunk at once.

BULK_CHUNK_SIZE = 1000

# Hard ceiling on a single bulk API call. This exists to keep any one
# request's memory footprint, transaction length, and lock duration
# bounded and predictable -- a request for, say, 500,000 rows should be
# split into several calls by the caller rather than accepted as one
# giant all-or-nothing unit of work. The bundled webpage's importer
# chunks CSV files into batches at or under this size automatically; see
# static/index.html.
MAX_BULK_ENTRIES = 5000


def _chunked(seq: list, size: int):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def _bulk_upsert_get_ids(
    conn: pymysql.connections.Connection,
    table: str,
    column: str,
    values: list[str],
    update_clause: str | None = None,
) -> dict[str, int]:
    """
    Upsert every distinct string in `values` into `table.column`, then
    return a {value: id} map covering all of them (whether each one was
    newly inserted or already existed).

    `table` and `column` are interpolated directly into the SQL text
    rather than passed as query parameters -- MySQL's protocol does not
    allow identifiers (table/column names) to be bound as placeholders at
    all, only VALUES data can be. This is safe here specifically because
    both arguments are always one of this module's own hardcoded schema
    names at every call site below (never derived from request input);
    the actual user-controlled data (`values`) is still passed through
    %s placeholders exactly as everywhere else in this file, never
    string-interpolated.
    """
    distinct = sorted(set(values))
    if not distinct:
        return {}

    clause = update_clause or f"{column} = {column}"  # no-op update if the caller doesn't need one
    with conn.cursor() as cur:
        for chunk in _chunked(distinct, BULK_CHUNK_SIZE):
            placeholders = ",".join(["(%s)"] * len(chunk))
            cur.execute(
                f"INSERT INTO {table} ({column}) VALUES {placeholders} "
                f"ON DUPLICATE KEY UPDATE {clause}",
                chunk,
            )

    id_map: dict[str, int] = {}
    with conn.cursor() as cur:
        for chunk in _chunked(distinct, BULK_CHUNK_SIZE):
            placeholders = ",".join(["%s"] * len(chunk))
            cur.execute(
                f"SELECT id, {column} FROM {table} WHERE {column} IN ({placeholders})",
                chunk,
            )
            for row_id, value in cur.fetchall():
                id_map[value] = row_id
    return id_map


def _bulk_upsert_links(conn: pymysql.connections.Connection, pairs: list[tuple[int, int]]) -> None:
    """Same multi-row-INSERT batching as _bulk_upsert_get_ids, applied to
    domain_pivots. No id lookup afterward -- this table's rows ARE the
    data (a plain association), there's no surrogate id anything else
    needs to reference."""
    distinct = sorted(set(pairs))
    if not distinct:
        return
    with conn.cursor() as cur:
        for chunk in _chunked(distinct, BULK_CHUNK_SIZE):
            placeholders = ",".join(["(%s,%s)"] * len(chunk))
            flat_params = [v for pair in chunk for v in pair]
            cur.execute(
                f"INSERT INTO domain_pivots (domain_id, pivot_id) VALUES {placeholders} "
                f"ON DUPLICATE KEY UPDATE last_seen_at = CURRENT_TIMESTAMP(6)",
                flat_params,
            )


@dataclass
class BulkEntryResult:
    index: int                       # position in the original input list, for matching results back to source rows
    status: str                      # "ok" or "error"
    domain: str | None = None
    pivots_added: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None


def bulk_add_entries(
    entries: list[dict[str, Any]],
    conn: pymysql.connections.Connection | None = None,
) -> list[BulkEntryResult]:
    """
    Add many {"domain": ..., "pivots": [...]} entries in one call, batching
    the actual database work instead of doing it once per entry.

    Deliberately takes already-structured {"domain", "pivots"} dicts, NOT
    arbitrary raw strings run through parse_entry(). parse_entry()'s job is
    resolving genuinely ambiguous free-text input for the single-entry
    add_entry()/search() path; for a bulk call, the caller (here, the
    webpage's CSV importer) has ALREADY unambiguously split each row into
    a domain and its pivots by parsing the CSV properly, so re-deriving
    that structure by re-running text-tokenization heuristics over tens of
    thousands of rows would be pure wasted work solving an already-solved
    problem.

    Two-pass design:
      Pass 1 (pure Python, no DB access): validate/normalize every row
        independently via normalize_domain() / sanitize_pivot() -- the
        exact same validation used everywhere else in this file, so a
        row's fate here matches what add_entry() would have decided for
        it one at a time. A bad domain fails only that row; a bad pivot
        is dropped from that row with a warning, not fatal to the row.
      Pass 2 (batched DB access): bulk-upsert every distinct valid domain,
        then every distinct valid pivot, then every distinct
        (domain_id, pivot_id) pair -- each in chunks of BULK_CHUNK_SIZE
        rows per statement -- inside ONE transaction for the whole call.

    Returns one BulkEntryResult per input entry, in the same order, so the
    caller can report success/failure per original row.

    Note on partial failure: this raises MAX_BULK_ENTRIES as a hard cap
    (see that constant) rather than silently truncating a larger input.
    Validation failures (bad domain/pivot) are reported per row and do
    NOT roll back the batch. A DB-level failure during the write pass
    (e.g. a dropped connection mid-batch) DOES roll back the whole
    transaction -- every valid row in this call either lands together or
    none of them do, which is simpler to reason about than a batch that's
    silently half-applied. This is a real trade-off: a single bad
    connection blip loses the whole call's writes, not just one row's.
    Keeping MAX_BULK_ENTRIES bounded (rather than one transaction for,
    say, a 200,000-row file) limits how much work such a rollback can
    ever throw away.
    """
    if len(entries) > MAX_BULK_ENTRIES:
        raise ValueError(
            f"batch of {len(entries)} entries exceeds the {MAX_BULK_ENTRIES}-entry "
            "limit for a single bulk call; split the input into smaller batches"
        )

    results: list[BulkEntryResult] = [
        BulkEntryResult(index=i, status="error", error="not processed") for i in range(len(entries))
    ]

    # --- Pass 1: validation only, no DB access yet ---
    per_row_domain: dict[int, str] = {}
    per_row_pivots: dict[int, list[str]] = {}
    for i, entry in enumerate(entries):
        domain_raw = entry.get("domain") if isinstance(entry, dict) else None
        try:
            if domain_raw is None:
                raise DomainValidationError("missing 'domain' field")
            domain = normalize_domain(str(domain_raw))
        except DomainValidationError as e:
            results[i] = BulkEntryResult(index=i, status="error", error=str(e))
            continue

        clean_pivots: list[str] = []
        warnings: list[str] = []
        for p in (entry.get("pivots") or []):
            try:
                cp = sanitize_pivot(p)
            except PivotValidationError as e:
                warnings.append(f"skipped pivot {p!r}: {e}")
                continue
            if cp:
                clean_pivots.append(cp)

        seen: set[str] = set()
        deduped_pivots: list[str] = []
        for p in clean_pivots:
            if p not in seen:
                seen.add(p)
                deduped_pivots.append(p)

        per_row_domain[i] = domain
        per_row_pivots[i] = deduped_pivots
        results[i] = BulkEntryResult(index=i, status="ok", domain=domain, warnings=warnings)

    valid_indices = list(per_row_domain.keys())
    if not valid_indices:
        return results  # every row failed validation -- nothing to write, skip the DB entirely

    # --- Pass 2: batched writes, one transaction for the whole call ---
    owns_conn = conn is None
    if owns_conn:
        conn = get_connection()
    try:
        conn.begin()
        try:
            all_domains = [per_row_domain[i] for i in valid_indices]
            domain_id_by_name = _bulk_upsert_get_ids(
                conn, "domains", "domain", all_domains,
                update_clause="last_seen_at = CURRENT_TIMESTAMP(6)",
            )

            all_pivots = [p for i in valid_indices for p in per_row_pivots[i]]
            pivot_id_by_text = _bulk_upsert_get_ids(conn, "pivots", "pivot_text", all_pivots)

            all_pairs = [
                (domain_id_by_name[per_row_domain[i]], pivot_id_by_text[p])
                for i in valid_indices
                for p in per_row_pivots[i]
            ]
            _bulk_upsert_links(conn, all_pairs)

            conn.commit()
        except Exception:
            conn.rollback()
            raise

        for i in valid_indices:
            results[i].pivots_added = per_row_pivots[i]
    finally:
        if owns_conn:
            conn.close()

    return results


# ============================================================================
# Public API
# ============================================================================

@dataclass
class AddResult:
    domain: str
    pivots_added: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def add_entry(raw: str, conn: pymysql.connections.Connection | None = None) -> list[AddResult]:
    """
    Parse `raw` (any supported format; possibly multiple newline-separated
    records) and upsert each resulting domain plus its pivots, with full
    accumulation/dedup semantics. Returns one AddResult per record.

    A caller-supplied `conn` lets tests/scripts reuse one connection across
    multiple add_entry() calls (needed to observe accumulation across
    "separate submissions" as required by spec 1a); if omitted, a
    connection is opened and closed internally.

    Each record is applied in its own transaction: a bad pivot within a
    record is skipped with a warning (not fatal to the whole record), but a
    bad *domain* fails that whole record with no partial writes.
    """
    records = _split_records(raw)
    owns_conn = conn is None
    if owns_conn:
        conn = get_connection()
    results: list[AddResult] = []
    try:
        for record_raw in records:
            domain_raw, pivots_raw = parse_entry(record_raw)  # ParseError -> propagates
            domain = normalize_domain(domain_raw)              # DomainValidationError -> propagates

            result = AddResult(domain=domain)
            clean_pivots: list[str] = []
            for p in pivots_raw:
                try:
                    cp = sanitize_pivot(p)
                except PivotValidationError as e:
                    result.warnings.append(f"skipped pivot {p!r}: {e}")
                    continue
                if cp:
                    clean_pivots.append(cp)

            # De-dupe within THIS single call (order-preserving) before
            # hitting the DB -- avoids redundant round trips when the same
            # pivot appears twice in one submission; the UNIQUE constraints
            # would also catch it, this just saves a couple of statements.
            seen = set()
            deduped_pivots = []
            for p in clean_pivots:
                if p not in seen:
                    seen.add(p)
                    deduped_pivots.append(p)

            conn.begin()
            try:
                domain_id = get_or_create_domain(conn, domain)
                for p in deduped_pivots:
                    pivot_id = get_or_create_pivot(conn, p)
                    link_domain_pivot(conn, domain_id, pivot_id)
                    result.pivots_added.append(p)
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            results.append(result)
    finally:
        if owns_conn:
            conn.close()
    return results


def _search_by_domain(conn: pymysql.connections.Connection, domain: str) -> dict[str, Any]:
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute(
            "SELECT id, domain, created_at, last_seen_at FROM domains WHERE domain = %s",
            (domain,),
        )
        domain_row = cur.fetchone()
        if not domain_row:
            return {"query_type": "domain", "domain": domain, "found": False, "pivots": []}

        cur.execute(
            """
            SELECT p.pivot_text, dp.created_at, dp.last_seen_at
            FROM domain_pivots dp
            JOIN pivots p ON p.id = dp.pivot_id
            WHERE dp.domain_id = %s
            ORDER BY p.pivot_text
            """,
            (domain_row['id'],),
        )
        pivot_rows = cur.fetchall()
        return {
            "query_type": "domain",
            "domain": domain_row['domain'],
            "found": True,
            "created_at": domain_row['created_at'],
            "last_seen_at": domain_row['last_seen_at'],
            "pivots": [r['pivot_text'] for r in pivot_rows],
        }


def _search_by_pivot(conn: pymysql.connections.Connection, pivot_text: str) -> dict[str, Any]:
    """Reverse lookup: given a pivot string, find every domain it's
    associated with. Exact, case-sensitive match against pivot_text (the
    utf8mb4_bin collation on that column makes this comparison
    byte-exact)."""
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute("SELECT id FROM pivots WHERE pivot_text = %s", (pivot_text,))
        pivot_row = cur.fetchone()
        if not pivot_row:
            return {"query_type": "pivot", "pivot": pivot_text, "found": False, "domains": []}

        cur.execute(
            """
            SELECT d.domain, dp.created_at, dp.last_seen_at
            FROM domain_pivots dp
            JOIN domains d ON d.id = dp.domain_id
            WHERE dp.pivot_id = %s
            ORDER BY d.domain
            """,
            (pivot_row['id'],),
        )
        domain_rows = cur.fetchall()
        return {
            "query_type": "pivot",
            "pivot": pivot_text,
            "found": True,
            "domains": [r['domain'] for r in domain_rows],
        }


def export_all(conn: pymysql.connections.Connection | None = None) -> list[dict[str, Any]]:
    """
    Return every domain with its full accumulated pivot list, e.g. for a
    CSV/JSON export of the whole dataset.

    Deliberately does NOT use MySQL's GROUP_CONCAT() to build the pivot
    list in SQL: GROUP_CONCAT has a default 1024-byte output cap
    (group_concat_max_len) that silently truncates a domain with many/long
    pivots unless a server-side setting is raised -- easy to miss and hard
    to notice until an export goes out already truncated. Instead this
    pulls both tables with two plain queries and groups pivots per domain
    in Python, which has no such hidden limit.
    """
    owns_conn = conn is None
    if owns_conn:
        conn = get_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute(
                "SELECT id, domain, created_at, last_seen_at FROM domains ORDER BY domain"
            )
            domain_rows = cur.fetchall()

            cur.execute(
                """
                SELECT dp.domain_id, p.pivot_text
                FROM domain_pivots dp
                JOIN pivots p ON p.id = dp.pivot_id
                ORDER BY dp.domain_id, p.pivot_text
                """
            )
            link_rows = cur.fetchall()

        pivots_by_domain_id: dict[int, list[str]] = {}
        for row in link_rows:
            pivots_by_domain_id.setdefault(row['domain_id'], []).append(row['pivot_text'])

        return [
            {
                "domain": d['domain'],
                "created_at": d['created_at'],
                "last_seen_at": d['last_seen_at'],
                "pivots": pivots_by_domain_id.get(d['id'], []),
            }
            for d in domain_rows
        ]
    finally:
        if owns_conn:
            conn.close()


def search(raw: str, conn: pymysql.connections.Connection | None = None) -> list[dict[str, Any]]:
    """
    Parse `raw` with the SAME logic add_entry() uses, then look up matching
    rows. This guarantees format-agnostic input behaves identically for
    writes and reads (spec section 3's requirement that add/search share
    parsing logic).

    For each record:
      - If a domain token is found, look up that domain and return its full
        accumulated pivot set (forward lookup).
      - If no domain token is found at all, fall back to treating the
        record as a single pivot value and look up every domain associated
        with it (reverse lookup) -- this is what lets a bare pivot value
        like an IP or hash be searched on its own, per spec section 1's
        requirement to support "given a pivot, find all associated
        domains".
    """
    records = _split_records(raw)
    owns_conn = conn is None
    if owns_conn:
        conn = get_connection()
    results: list[dict[str, Any]] = []
    try:
        for record_raw in records:
            try:
                domain_raw, _pivots_raw = parse_entry(record_raw)
                domain = normalize_domain(domain_raw)
            except ParseError:
                try:
                    pivot_candidate = sanitize_pivot(record_raw)
                except PivotValidationError as e:
                    results.append({"query": record_raw, "error": str(e)})
                    continue
                if not pivot_candidate:
                    results.append({
                        "query": record_raw,
                        "error": "no valid domain or usable pivot found in query",
                    })
                    continue
                results.append(_search_by_pivot(conn, pivot_candidate))
                continue
            except DomainValidationError as e:
                results.append({"query": record_raw, "error": str(e)})
                continue

            results.append(_search_by_domain(conn, domain))
    finally:
        if owns_conn:
            conn.close()
    return results
