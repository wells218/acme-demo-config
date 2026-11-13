#!/usr/bin/env python3
"""Upsert customers.csv into the payments database, keyed on customer_id.

Safety properties:
  * Dry run by default. Nothing is written unless --execute is passed.
  * DB settings come from environment variables only (never files or CLI args).
  * The connection must use TLS (sslmode verify-full by default; anything
    weaker than "require" is refused).
  * Logs carry counts only: no row values, IDs, hostnames or credentials.
  * Refuses to load CVV/CVC columns or values that look like full card numbers
    (PCI DSS forbids storing CVV and full PANs must not travel in plain CSV).

Environment variables:
  PAYMENTS_DB_HOST        required
  PAYMENTS_DB_PORT        optional, default 5432
  PAYMENTS_DB_NAME        required
  PAYMENTS_DB_USER        required
  PAYMENTS_DB_PASSWORD    required
  PAYMENTS_DB_SSLMODE     optional, default verify-full (require|verify-ca|verify-full)
  PAYMENTS_DB_SSLROOTCERT optional, CA bundle path for verify-ca/verify-full
  PAYMENTS_DB_TABLE       optional, default "customers"

Usage:
  python deploy.py [--csv customers.csv]            # dry run
  python deploy.py [--csv customers.csv] --execute  # write to the DB
"""
from __future__ import annotations

import argparse
import csv
import logging
import os
import re
import sys

KEY = "customer_id"
REQUIRED_ENV = ("PAYMENTS_DB_HOST", "PAYMENTS_DB_NAME", "PAYMENTS_DB_USER", "PAYMENTS_DB_PASSWORD")
ALLOWED_SSLMODES = {"require", "verify-ca", "verify-full"}
IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
FORBIDDEN_COLUMN_RE = re.compile(r"(cvv|cvc|cvv2|cid|security_code|card_?number|^pan$)", re.I)
DIGITS_RE = re.compile(r"\D")

log = logging.getLogger("deploy")


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def looks_like_pan(value: str) -> bool:
    stripped = value.strip()
    if not stripped or not re.fullmatch(r"[\d \-]+", stripped):
        return False
    digits = DIGITS_RE.sub("", stripped)
    return 13 <= len(digits) <= 19 and luhn_ok(digits)


def load_csv(path: str) -> tuple[list[str], list[dict[str, str]], dict[str, int]]:
    """Read and validate the CSV. Returns (columns, unique rows, stats)."""
    stats = {"rows_read": 0, "rows_valid": 0, "missing_key": 0, "duplicate_key": 0, "pan_like_values": 0}
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            raise ValueError("CSV has no header row")
        columns = [c.strip().lower() for c in reader.fieldnames]
        if KEY not in columns:
            raise ValueError(f"CSV is missing the key column '{KEY}'")
        bad_idents = [c for c in columns if not IDENT_RE.match(c)]
        if bad_idents:
            raise ValueError(f"{len(bad_idents)} column name(s) are not safe SQL identifiers")
        if len(set(columns)) != len(columns):
            raise ValueError("CSV has duplicate column names")
        forbidden = [c for c in columns if FORBIDDEN_COLUMN_RE.search(c)]
        if forbidden:
            raise ValueError(f"CSV has {len(forbidden)} card-security/PAN column(s); refusing to load")

        seen: dict[str, dict[str, str]] = {}
        for raw in reader:
            stats["rows_read"] += 1
            row = {k.strip().lower(): (v or "").strip() for k, v in raw.items() if k is not None}
            key = row.get(KEY, "")
            if not key:
                stats["missing_key"] += 1
                continue
            if any(looks_like_pan(v) for c, v in row.items() if c != KEY):
                stats["pan_like_values"] += 1
            if key in seen:
                stats["duplicate_key"] += 1  # last occurrence wins
            seen[key] = row
        stats["rows_valid"] = len(seen)
    if stats["pan_like_values"]:
        raise ValueError(f"{stats['pan_like_values']} row(s) contain values that look like full card numbers; refusing to load")
    return columns, list(seen.values()), stats


def db_settings() -> dict[str, str]:
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        raise RuntimeError("missing required environment variable(s): " + ", ".join(missing))
    sslmode = os.environ.get("PAYMENTS_DB_SSLMODE", "verify-full")
    if sslmode not in ALLOWED_SSLMODES:
        raise RuntimeError(f"PAYMENTS_DB_SSLMODE must be one of {sorted(ALLOWED_SSLMODES)}")
    table = os.environ.get("PAYMENTS_DB_TABLE", "customers")
    if not IDENT_RE.match(table):
        raise RuntimeError("PAYMENTS_DB_TABLE is not a safe SQL identifier")
    settings = {
        "host": os.environ["PAYMENTS_DB_HOST"],
        "port": os.environ.get("PAYMENTS_DB_PORT", "5432"),
        "dbname": os.environ["PAYMENTS_DB_NAME"],
        "user": os.environ["PAYMENTS_DB_USER"],
        "password": os.environ["PAYMENTS_DB_PASSWORD"],
        "sslmode": sslmode,
        "table": table,
    }
    if os.environ.get("PAYMENTS_DB_SSLROOTCERT"):
        settings["sslrootcert"] = os.environ["PAYMENTS_DB_SSLROOTCERT"]
    return settings


def upsert(columns: list[str], rows: list[dict[str, str]], settings: dict[str, str]) -> dict[str, int]:
    import psycopg2  # imported lazily so dry runs work without the driver
    from psycopg2 import sql
    from psycopg2.extras import execute_values

    table = settings.pop("table")
    update_cols = [c for c in columns if c != KEY]
    if update_cols:
        conflict = sql.SQL("DO UPDATE SET {}").format(
            sql.SQL(", ").join(sql.SQL("{0} = EXCLUDED.{0}").format(sql.Identifier(c)) for c in update_cols)
        )
    else:
        conflict = sql.SQL("DO NOTHING")
    query = sql.SQL("INSERT INTO {t} ({cols}) VALUES %s ON CONFLICT ({key}) {conflict} RETURNING (xmax = 0)").format(
        t=sql.Identifier(table),
        cols=sql.SQL(", ").join(sql.Identifier(c) for c in columns),
        key=sql.Identifier(KEY),
        conflict=conflict,
    )
    values = [tuple(r.get(c) or None for c in columns) for r in rows]

    conn = psycopg2.connect(connect_timeout=10, application_name="acme-payments-deploy", **settings)
    try:
        with conn:  # single transaction: commit on success, rollback on any error
            with conn.cursor() as cur:
                results = execute_values(cur, query.as_string(conn), values, page_size=500, fetch=True)
    finally:
        conn.close()
    inserted = sum(1 for (is_insert,) in results if is_insert)
    return {"inserted": inserted, "updated": len(results) - inserted}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Upsert customers.csv into the payments DB (dry run by default).")
    parser.add_argument("--csv", default="customers.csv", help="path to the customers CSV (default: customers.csv)")
    parser.add_argument("--execute", action="store_true", help="actually write to the database")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    mode = "EXECUTE" if args.execute else "DRY RUN"
    log.info("mode=%s", mode)

    try:
        columns, rows, stats = load_csv(args.csv)
    except FileNotFoundError:
        log.error("CSV file not found")
        return 2
    except (ValueError, csv.Error) as exc:
        log.error("CSV validation failed: %s", exc)
        return 2
    log.info("columns=%d rows_read=%d rows_to_upsert=%d missing_key=%d duplicate_key=%d",
             len(columns), stats["rows_read"], stats["rows_valid"], stats["missing_key"], stats["duplicate_key"])

    if not args.execute:
        missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
        log.info("db_env_vars_present=%d/%d (no connection made in dry run)",
                 len(REQUIRED_ENV) - len(missing), len(REQUIRED_ENV))
        log.info("DRY RUN complete: would upsert %d row(s). Re-run with --execute to write.", stats["rows_valid"])
        return 0

    try:
        settings = db_settings()
        counts = upsert(columns, rows, settings)
    except Exception as exc:  # noqa: BLE001 - report type only; messages can carry connection details
        log.error("upsert failed (%s); transaction rolled back", type(exc).__name__)
        return 1
    log.info("EXECUTE complete: inserted=%d updated=%d", counts["inserted"], counts["updated"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
