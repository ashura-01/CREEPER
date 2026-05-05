"""
modules/exporter.py
Writes finished reports to disk in JSON, CSV, and/or SQLite formats.
Imported by the orchestrator after a crawl completes.
"""

from __future__ import annotations

import csv
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

from rich.console import Console

logger  = logging.getLogger("CREEPER.exporter")
console = Console()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _stem(target: str) -> str:
    ts     = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    domain = urlparse(target).netloc.replace(".", "_")
    return f"CREEPER_{domain}_{ts}"


def _jdump(v) -> str:
    return json.dumps(v, default=str)


# ── JSON ──────────────────────────────────────────────────────────────────────

def export_json(report: Dict, out_dir: Path) -> None:
    path = out_dir / f"{_stem(report['target'])}.json"
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    console.print(f"[green]✓ JSON:[/green] {path}")


# ── CSV ───────────────────────────────────────────────────────────────────────

_PAGE_KEYS = [
    "url", "title", "status_code", "response_time_ms",
    "emails", "phones", "api_endpoints", "matched_patterns",
]

def export_csv(report: Dict, out_dir: Path) -> None:
    stem = _stem(report["target"])

    # Pages CSV
    pages_path = out_dir / f"{stem}_pages.csv"
    if report.get("pages"):
        with open(pages_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=_PAGE_KEYS, extrasaction="ignore")
            writer.writeheader()
            for p in report["pages"]:
                row = {
                    k: (_jdump(p[k]) if isinstance(p.get(k), list) else p.get(k, ""))
                    for k in _PAGE_KEYS
                }
                writer.writerow(row)
        console.print(f"[green]✓ CSV pages:[/green] {pages_path}")

    # Regex hits CSV
    hits = report.get("regex_matched_urls", [])
    if hits:
        hits_path = out_dir / f"{stem}_regex_hits.csv"
        with open(hits_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["url", "title", "matched_patterns", "match_details"]
            )
            writer.writeheader()
            for hit in hits:
                writer.writerow({
                    "url":              hit["url"],
                    "title":            hit["title"],
                    "matched_patterns": "|".join(hit["matched_patterns"]),
                    "match_details":    _jdump(hit["matches"]),
                })
        console.print(f"[green]✓ CSV regex hits:[/green] {hits_path}")

    # Forms without CSRF
    bad_forms = report.get("forms_without_csrf", [])
    if bad_forms:
        forms_path = out_dir / f"{stem}_forms_no_csrf.csv"
        with open(forms_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["action", "method", "enctype", "input_count"]
            )
            writer.writeheader()
            for frm in bad_forms:
                writer.writerow({
                    "action":      frm.get("action", ""),
                    "method":      frm.get("method", ""),
                    "enctype":     frm.get("enctype", ""),
                    "input_count": frm.get("input_count", 0),
                })
        console.print(f"[green]✓ CSV forms (no CSRF):[/green] {forms_path}")


# ── SQLite ────────────────────────────────────────────────────────────────────

_CREATE_PAGES = """
CREATE TABLE IF NOT EXISTS pages (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    url                       TEXT,
    title                     TEXT,
    status_code               INTEGER,
    response_time_ms          REAL,
    rendered                  INTEGER,
    waf_blocked               INTEGER,
    emails                    TEXT,
    phones                    TEXT,
    forms                     TEXT,
    api_endpoints             TEXT,
    js_variables              TEXT,
    comments                  TEXT,
    subdomains                TEXT,
    matched_patterns          TEXT,
    cms                       TEXT,
    waf                       TEXT,
    cdn                       TEXT,
    server                    TEXT,
    missing_security_headers  TEXT
)"""

_CREATE_REGEX = """
CREATE TABLE IF NOT EXISTS regex_matches (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT,
    title       TEXT,
    pattern     TEXT,
    match_text  TEXT,
    match_count INTEGER,
    context     TEXT
)"""

_CREATE_META  = "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
_CREATE_FORMS = """
CREATE TABLE IF NOT EXISTS forms (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    page_url        TEXT,
    action          TEXT,
    method          TEXT,
    enctype         TEXT,
    input_count     INTEGER,
    has_password    INTEGER,
    has_file_upload INTEGER,
    has_csrf_token  INTEGER
)"""


def export_sqlite(report: Dict, out_dir: Path) -> None:
    path = out_dir / f"{_stem(report['target'])}.db"
    conn = sqlite3.connect(path)
    cur  = conn.cursor()

    for ddl in (_CREATE_PAGES, _CREATE_REGEX, _CREATE_META, _CREATE_FORMS):
        cur.execute(ddl)

    # Meta table
    meta_rows = [
        ("target",               report["target"]),
        ("scraped_at",           report["scraped_at"]),
        ("total_pages",          str(report["total_pages"])),
        ("avg_response_time_ms", str(report["avg_response_time_ms"])),
        ("regex_patterns",       _jdump(report["regex_patterns_used"])),
        ("regex_total_hits",     str(report["regex_total_hits"])),
        ("emails",               _jdump(report["emails"])),
        ("phones",               _jdump(report["phones"])),
        ("subdomains",           _jdump(report["subdomains"])),
        ("api_endpoints",        _jdump(report["api_endpoints"])),
        ("waf_signals",          str(report.get("waf_signals_detected", 0))),
    ]
    cur.executemany("INSERT OR REPLACE INTO meta VALUES (?, ?)", meta_rows)

    # Pages
    for p in report.get("pages", []):
        tech = p.get("tech", {})
        cur.execute(
            """INSERT INTO pages
               (url, title, status_code, response_time_ms, rendered, waf_blocked,
                emails, phones, forms, api_endpoints, js_variables,
                comments, subdomains, matched_patterns,
                cms, waf, cdn, server, missing_security_headers)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                p["url"], p["title"], p["status_code"],
                p["response_time_ms"], int(p.get("rendered", False)),
                int(p.get("waf_blocked", False)),
                _jdump(p.get("emails", [])),
                _jdump(p.get("phones", [])),
                _jdump(p.get("forms", [])),
                _jdump(p.get("api_endpoints", [])),
                _jdump(p.get("js_variables", [])),
                _jdump(p.get("comments", [])),
                _jdump(p.get("subdomains", [])),
                _jdump(p.get("matched_patterns", [])),
                tech.get("cms", ""), tech.get("waf", ""),
                tech.get("cdn", ""), tech.get("server", ""),
                _jdump(tech.get("missing_security_headers", [])),
            ),
        )
        # Forms sub-table
        for frm in p.get("forms", []):
            cur.execute(
                """INSERT INTO forms
                   (page_url, action, method, enctype, input_count,
                    has_password, has_file_upload, has_csrf_token)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    p["url"],
                    frm.get("action", ""),
                    frm.get("method", ""),
                    frm.get("enctype", ""),
                    frm.get("input_count", 0),
                    int(frm.get("has_password", False)),
                    int(frm.get("has_file_upload", False)),
                    int(frm.get("has_csrf_token", False)),
                ),
            )

    # Regex matches
    for hit in report.get("regex_matched_urls", []):
        for m in hit.get("matches", []):
            cur.execute(
                """INSERT INTO regex_matches
                   (url, title, pattern, match_text, match_count, context)
                   VALUES (?,?,?,?,?,?)""",
                (
                    hit["url"], hit["title"],
                    m["pattern"], m["match_text"],
                    m["match_count"], m["context"],
                ),
            )

    conn.commit()
    conn.close()
    console.print(f"[green]✓ SQLite:[/green] {path}")


# ── Dispatcher ────────────────────────────────────────────────────────────────

def export(report: Dict, output_dir: str, formats: List[str]) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    for fmt in formats:
        fmt = fmt.lower().strip()
        if fmt == "json":
            export_json(report, out)
        elif fmt == "csv":
            export_csv(report, out)
        elif fmt == "sqlite":
            export_sqlite(report, out)
        else:
            logger.warning("Unknown export format ignored: %s", fmt)
