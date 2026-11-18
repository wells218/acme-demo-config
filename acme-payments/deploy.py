#!/usr/bin/env python3
"""Upsert customers.csv into the payments database, keyed on customer_id.

Safety properties
-----------------
* DRY RUN BY DEFAULT. Nothing is written unless --execute is passed.
* DB settings come from environment variables only (no config files, no CLI flags):
    PAYMENTS_DB_HOST         required to connect
    PAYMENTS_DB_NAME         required to connect
    PAYMENTS_DB_USER         required to connect
    PAYMENTS_DB_PASSWORD     required to connect
    PAYMENTS_DB_PORT         optional, default 5432
    PAYMENTS_DB_TABLE        optional, default "customers" (may be "schema.table")
    PAYMENTS_DB_SSLMODE      optional, default "verify-full"; only require/verify-ca/verify-full allowed
    PAYMENTS_DB_SSLROOTCERT  optional path to the CA bundle used to verify the server
* SSL is mandatory; plaintext / "prefer" / "allow" modes are rejected.
* Logs counts only: never row values, never connection settings, and for DB errors
  only the exception class and SQLSTATE (driver messages can echo row data).
* Refuses to load PCI-prohibited data: CVV/CVC columns, full card-number columns,
  or any value that looks like a Luhn-valid card number (13-19 digits).

Usage
-----
    python deploy.py [--csv customers.csv]            # dry run
    python deploy.py [--csv customers.csv] --execute  # write (single transaction)

Exit codes: 0 ok, 1 validation failure, 2 configuration error, 3 database error.
"""
from __future__ import annotations

import argparse
import csv
import logging
import os
import re
import sys

KEY = "customer_id"
BATCH_SIZE = 500
IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
ALLOWED_SSLMODES = {"require", "verify-ca", "verify-full"}
# Columns that must never be stored (PCI DSS 3.2: no sensitive authentication data;
# full PAN must not be loaded through this path).
FORBIDDEN_COLUMN_RE = re.compile(
    r"(^|_)(cvv2?|cvc2?|cid|csc|pan|card_?num(ber)?|cc_?num(ber)?|credit_?card(_?number)?|track_?data|pin)($|_)"
)
CARD_LIKE_RE = re.compile(r"^(?:\d[ -]?){12,18}\d$")

log = logging.getLogger("deploy")


def luhn_ok(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()][::-1]
    total = 0
    for i, d in enumerate(digits):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class ValidationError(Exception):
    pass


def load_csv(path: str) -> tuple[list[str], list[tuple]]:
    """Read and validate the CSV. Returns (columns, rows). Raises ValidationError."""
    if not os.path.isfile(path):
        raise ValidationError("input file not found")
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration:
            raise ValidationError("input file is empty")
        cols = [h.strip().lower() for h in header]

        bad = [i for i, c in enumerate(cols) if not IDENT_RE.match(c)]
        if bad:
            raise ValidationError(f"{len(bad)} column name(s) are not safe SQL identifiers")
        if len(set(cols)) != len(cols):
            raise ValidationError("duplicate column names in header")
        if KEY not in cols:
            raise ValidationError(f"header has no {KEY} column")
        forbidden = [c for c in cols if FORBIDDEN_COLUMN_RE.search(c)]
        if forbidden:
            raise ValidationError(
                f"{len(forbidden)} PCI-prohibited column(s) present (CVV/card number); refusing to load"
            )

        key_idx = cols.index(KEY)
        rows: list[tuple] = []
        seen: set[str] = set()
        stats = {"wrong_width": 0, "blank_key": 0, "duplicate_key": 0, "card_like_values": 0}
        for raw in reader:
            if not raw or all(not v.strip() for v in raw):
                continue  # skip blank lines
            if len(raw) != len(cols):
                stats["wrong_width"] += 1
                continue
            vals = [v.strip() for v in raw]
            if any(CARD_LIKE_RE.match(v) and luhn_ok(v) for v in vals):
                stats["card_like_values"] += 1
            key = vals[key_idx]
            if not key:
                stats["blank_key"] += 1
                continue
            if key in seen:
                stats["duplicate_key"] += 1
                continue
            seen.add(key)
            rows.append(tuple(v if v != "" else None for v in vals))

    log.info("csv: columns=%d valid_rows=%d wrong_width=%d blank_key=%d duplicate_key=%d card_like_rows=%d",
             len(cols), len(rows), stats["wrong_width"], stats["blank_key"],
             stats["duplicate_key"], stats["card_like_values"])
    if stats["card_like_values"]:
        raise ValidationError("rows contain values that look like full card numbers; refusing to load")
    if stats["wrong_width"] or stats["blank_key"] or stats["duplicate_key"]:
        raise ValidationError("csv has malformed, keyless or duplicate rows; fix the file first")
    if not rows:
        raise ValidationError("no data rows")
    return cols, rows


def db_settings() -> dict | None:
    """Return connection kwargs from the environment, or None if not configured."""
    required = ["PAYMENTS_DB_HOST", "PAYMENTS_DB_NAME", "PAYMENTS_DB_USER", "PAYMENTS_DB_PASSWORD"]
    present = [k for k in required if os.environ.get(k)]
    if not present:
        return None
    if len(present) != len(required):
        raise SystemExit(_cfg_error(f"{len(required) - len(present)} required PAYMENTS_DB_* variable(s) missing"))
    sslmode = os.environ.get("PAYMENTS_DB_SSLMODE", "verify-full")
    if sslmode not in ALLOWED_SSLMODES:
        raise SystemExit(_cfg_error("PAYMENTS_DB_SSLMODE must be require, verify-ca or verify-full"))
    port = os.environ.get("PAYMENTS_DB_PORT", "5432")
    if not port.isdigit():
        raise SystemExit(_cfg_error("PAYMENTS_DB_PORT must be numeric"))
    kw = {
        "host": os.environ["PAYMENTS_DB_HOST"],
        "port": int(port),
        "dbname": os.environ["PAYMENTS_DB_NAME"],
        "user": os.environ["PAYMENTS_DB_USER"],
        "password": os.environ["PAYMENTS_DB_PASSWORD"],
        "sslmode": sslmode,
        "connect_timeout": 15,
        "application_name": "acme-payments-deploy",
    }
    if os.environ.get("PAYMENTS_DB_SSLROOTCERT"):
        kw["sslrootcert"] = os.environ["PAYMENTS_DB_SSLROOTCERT"]
    return kw


def table_parts() -> list[str]:
    parts = os.environ.get("PAYMENTS_DB_TABLE", "customers").lower().split(".")
    if not (1 <= len(parts) <= 2) or not all(IDENT_RE.match(p) for p in parts):
        raise SystemExit(_cfg_error("PAYMENTS_DB_TABLE is not a valid [schema.]table name"))
    return parts


def _cfg_error(msg: str) -> int:
    log.error("config: %s", msg)
    return 2


def import_driver():
    """Prefer psycopg (v3), fall back to psycopg2."""
    try:
        import psycopg as drv
        from psycopg import sql
        return drv, sql
    except ImportError:
        pass
    try:
        import psycopg2 as drv
        from psycopg2 import sql
        return drv, sql
    except ImportError:
        raise SystemExit(_cfg_error("no PostgreSQL driver installed (pip install 'psycopg[binary]')"))


def db_error(exc: Exception) -> int:
    code = getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None) or "n/a"
    log.error("database error: %s (sqlstate=%s)", type(exc).__name__, code)
    return 3


def run(cols: list[str], rows: list[tuple], execute: bool) -> int:
    settings = db_settings()
    if settings is None:
        if execute:
            return _cfg_error("--execute needs PAYMENTS_DB_* environment variables")
        log.info("dry run (offline): no PAYMENTS_DB_* settings; csv validated, would upsert %d row(s)", len(rows))
        return 0

    drv, sql = import_driver()
    table = sql.Identifier(*table_parts())
    ids = [r[cols.index(KEY)] for r in rows]

    try:
        conn = drv.connect(**settings)
    except Exception as exc:  # noqa: BLE001 - logged without message on purpose
        return db_error(exc)

    try:
        with conn.cursor() as cur:
            if not execute:
                # First statement of the transaction: the dry run cannot write even by accident.
                cur.execute("SET TRANSACTION READ ONLY")
            cur.execute("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            ssl_row = cur.fetchone()
            if not ssl_row or ssl_row[0] is not True:
                log.error("connection is not using SSL; aborting")
                return 2

            # Schema check: every CSV column must exist in the target table.
            parts = table_parts()
            schema, name = (parts[0], parts[1]) if len(parts) == 2 else (None, parts[0])
            cur.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = %s AND table_schema = COALESCE(%s, current_schema())",
                (name, schema),
            )
            db_cols = {r[0] for r in cur.fetchall()}
            if not db_cols:
                log.error("target table not found")
                return 2
            missing = [c for c in cols if c not in db_cols]
            if missing:
                log.error("%d csv column(s) do not exist in target table", len(missing))
                return 1

            cur.execute(
                sql.SQL("SELECT count(*) FROM {} WHERE {}::text = ANY(%s)").format(table, sql.Identifier(KEY)),
                (ids,),
            )
            existing = cur.fetchone()[0]
            log.info("plan: rows=%d would_update=%d would_insert=%d", len(rows), existing, len(rows) - existing)

            if not execute:
                conn.rollback()
                log.info("dry run complete: no changes written (pass --execute to apply)")
                return 0

            non_key = [c for c in cols if c != KEY]
            conflict = (
                sql.SQL("DO UPDATE SET ") + sql.SQL(", ").join(
                    sql.SQL("{0} = EXCLUDED.{0}").format(sql.Identifier(c)) for c in non_key)
                if non_key else sql.SQL("DO NOTHING")
            )
            inserted = updated = 0
            for start in range(0, len(rows), BATCH_SIZE):
                batch = rows[start:start + BATCH_SIZE]
                row_tpl = sql.SQL("(") + sql.SQL(", ").join(sql.Placeholder() * len(cols)) + sql.SQL(")")
                stmt = sql.SQL("INSERT INTO {} ({}) VALUES {} ON CONFLICT ({}) {} RETURNING (xmax = 0)").format(
                    table,
                    sql.SQL(", ").join(map(sql.Identifier, cols)),
                    sql.SQL(", ").join([row_tpl] * len(batch)),
                    sql.Identifier(KEY),
                    conflict,
                )
                cur.execute(stmt, [v for r in batch for v in r])
                batch_inserted = sum(1 for r in cur.fetchall() if r[0])
                inserted += batch_inserted
                updated += len(batch) - batch_inserted  # DO NOTHING rows count as "updated" (already present)
            conn.commit()
            log.info("execute complete: inserted=%d updated=%d total=%d", inserted, updated, inserted + updated)
            return 0
    except Exception as exc:  # noqa: BLE001
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        return db_error(exc)
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Upsert customers.csv into the payments DB (dry run by default).")
    ap.add_argument("--csv", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "customers.csv"))
    ap.add_argument("--execute", action="store_true", help="actually write to the database")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    log.info("mode=%s", "EXECUTE" if args.execute else "dry-run")
    try:
        cols, rows = load_csv(args.csv)
    except ValidationError as exc:
        log.error("validation failed: %s", exc)
        return 1
    except (UnicodeDecodeError, csv.Error) as exc:
        log.error("validation failed: unreadable csv (%s)", type(exc).__name__)
        return 1
    return run(cols, rows, args.execute)


if __name__ == "__main__":
    sys.exit(main())
