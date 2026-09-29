"""
api.py
======

FastAPI wrapper around pivot_db.py, exposing add/search over HTTP.

Security model (this is a PUBLIC-INTERNET-FACING service, per the stated
requirement):
  - API-key auth (X-API-Key header) required on every data endpoint.
  - Per-IP rate limiting on every data endpoint (slowapi).
  - This process itself only ever speaks plain HTTP on 127.0.0.1 -- it does
    NOT terminate TLS. It must sit behind a reverse proxy / tunnel that
    does (Caddy or Cloudflare Tunnel; see DEPLOYMENT.md). Never bind this
    directly to 0.0.0.0 and expose it to the internet without a TLS
    front end -- the API key would then travel in plaintext.

Run locally for development:
    uvicorn api:app --host 127.0.0.1 --port 8000 --reload
"""

from __future__ import annotations

import csv
import hmac
import io
import os
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

import pivot_db

# ============================================================================
# Auth: shared API key(s) from an environment variable, e.g.
#   PIVOT_API_KEYS=key-for-alice,key-for-bob-CHANGE-ME
# Rotating a key means removing it from this list and restarting the
# process -- keys are never written to the database, so there is nothing
# to clean up there.
# ============================================================================

_VALID_KEYS = [
    k.strip() for k in os.environ.get("PIVOT_API_KEYS", "").split(",") if k.strip()
]

if not _VALID_KEYS:
    raise RuntimeError(
        "PIVOT_API_KEYS is not set (or empty). Refusing to start a "
        "public-facing API with no configured keys -- set at least one "
        "key before starting this process."
    )


def require_api_key(x_api_key: str = Header(default="")) -> None:
    """hmac.compare_digest is used instead of `==` so that comparing an
    incorrect key does not leak timing information about how many
    characters matched, which is a real (if minor) attack surface for a
    key that will be reachable from the public internet."""
    if not any(hmac.compare_digest(x_api_key, k) for k in _VALID_KEYS):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


# ============================================================================
# App setup
# ============================================================================

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Pivot Tracker API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS: needed only because the bundled webpage calls this API from the
# browser via fetch(). Tighten PIVOT_CORS_ORIGINS to your real domain(s)
# before going live -- "*" is fine for local development only.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("PIVOT_CORS_ORIGINS", "*").split(",")],
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)


class AddEntryRequest(BaseModel):
    raw: str


class BulkEntryItem(BaseModel):
    domain: str
    pivots: list[str] = Field(default_factory=list)


class BulkAddRequest(BaseModel):
    # max_length here mirrors pivot_db.MAX_BULK_ENTRIES: rejecting an
    # oversized request at the validation layer (a clean 422 naming the
    # limit) is friendlier than letting it reach bulk_add_entries() only
    # to raise a plain ValueError there.
    entries: list[BulkEntryItem] = Field(max_length=pivot_db.MAX_BULK_ENTRIES)


@app.get("/health")
def health() -> dict:
    """Unauthenticated on purpose: lets an uptime monitor or the reverse
    proxy's health check hit this without a key, while every endpoint that
    touches data still requires one."""
    return {"status": "ok"}


@app.post("/api/entries", dependencies=[Depends(require_api_key)])
@limiter.limit("30/minute")
def api_add_entry(request: Request, body: AddEntryRequest) -> list[dict[str, Any]]:
    try:
        results = pivot_db.add_entry(body.raw)
    except (pivot_db.ParseError, pivot_db.DomainValidationError, pivot_db.PivotValidationError) as e:
        raise HTTPException(status_code=422, detail=str(e))
    return [
        {"domain": r.domain, "pivots_added": r.pivots_added, "warnings": r.warnings}
        for r in results
    ]


@app.post("/api/bulk", dependencies=[Depends(require_api_key)])
@limiter.limit("20/minute")
def api_bulk_add(request: Request, body: BulkAddRequest) -> list[dict[str, Any]]:
    """
    Add up to MAX_BULK_ENTRIES already-structured entries in one call,
    batching the database work (see the design notes in pivot_db.py's
    "Bulk persistence" section for why this exists as a separate endpoint
    rather than just calling /api/entries in a loop).

    Unlike /api/entries, a bad row here does NOT fail the whole request --
    each entry gets its own status in the returned list, since the whole
    point of this endpoint is surviving one malformed row among tens of
    thousands without losing the rest. The only thing that can fail the
    whole call is a request over MAX_BULK_ENTRIES (rejected by
    BulkAddRequest's validation before this function even runs) or an
    actual database-level error partway through the batched write, which
    rolls back that one call's writes -- see pivot_db.bulk_add_entries's
    docstring for that trade-off.
    """
    entries = [{"domain": e.domain, "pivots": e.pivots} for e in body.entries]
    results = pivot_db.bulk_add_entries(entries)
    return [
        {
            "index": r.index,
            "status": r.status,
            "domain": r.domain,
            "pivots_added": r.pivots_added,
            "warnings": r.warnings,
            "error": r.error,
        }
        for r in results
    ]


@app.get("/api/search", dependencies=[Depends(require_api_key)])
@limiter.limit("60/minute")
def api_search(request: Request, q: str) -> list[dict[str, Any]]:
    try:
        return pivot_db.search(q)
    except (pivot_db.ParseError, pivot_db.DomainValidationError) as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.get("/api/export", dependencies=[Depends(require_api_key)])
@limiter.limit("10/minute")
def api_export(request: Request) -> Response:
    """
    Export the entire dataset as CSV: one row per domain, with that
    domain's full accumulated pivot list as the remaining columns on the
    same row (a "wide" format, variable number of columns per row since
    domains have different pivot counts). This is the same row shape the
    bundled webpage's CSV import expects.

    Re-importing an export is safe for round-tripping ANY pivot content,
    including values containing commas or quotes -- but only because the
    importer parses each CSV row into distinct cells first (respecting
    quoting) and then sends each row to /api/entries as a JSON entry
    ({"domain": ..., "pivots": [...]}), not as re-joined comma-delimited
    text. Rejoining cells with ',' and sending that as free text would
    silently corrupt any pivot that itself contains a comma, since the
    free-text tokenizer's comma-splitting has no way to know that comma
    was inside a quoted CSV field rather than a separator.

    csv.writer (not manual string-joining) handles quoting any pivot value
    that itself contains a comma, quote, or newline, so those characters
    in a pivot don't corrupt the file or get silently mangled.
    """
    rows = pivot_db.export_all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for row in rows:
        writer.writerow([row["domain"], *row["pivots"]])
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=pivot_export.csv"},
    )


# The bundled single-page frontend (static/index.html) is served at "/".
# Mounted last so it never shadows the /health or /api/* routes above.
app.mount("/", StaticFiles(directory="static", html=True), name="static")
