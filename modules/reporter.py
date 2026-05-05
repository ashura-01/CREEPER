"""
modules/reporter.py
Two responsibilities:
  1. build_report()  — aggregates per-page ScrapedPage objects into one flat dict
  2. format_report() — renders the dict to the terminal using Rich
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime
from typing import Dict, List, Set

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import ScrapedPage

logger  = logging.getLogger("CREEPER.reporter")
console = Console()


# ── Report builder ─────────────────────────────────────────────────────────────

def build_report(
    start_url: str,
    results: List[ScrapedPage],
    regex_patterns: List[str],
    regex_errors:   List[str],
) -> Dict:
    all_emails:        Set[str] = set()
    all_phones:        Set[str] = set()
    all_forms:         List[Dict] = []
    all_comments:      List[str]  = []
    all_subdomains:    Set[str] = set()
    all_api_endpoints: Set[str] = set()
    all_js_vars:       Set[str] = set()
    all_external:      Set[str] = set()
    pages_by_status:   Dict[int, int] = {}
    tech_summary:      Dict = {}
    response_times:    List[float] = []
    waf_signal_count:  int = 0

    regex_hit_urls:    List[Dict] = []
    pattern_hit_count: Dict[str, int] = {}

    for page in results:
        all_emails.update(page.emails)
        all_phones.update(page.phones)
        all_forms.extend(page.forms)
        all_comments.extend(page.comments)
        all_subdomains.update(page.subdomains)
        all_api_endpoints.update(page.api_endpoints)
        all_js_vars.update(page.js_variables)
        all_external.update(page.external_links)
        response_times.append(page.response_time_ms)
        pages_by_status[page.status_code] = (
            pages_by_status.get(page.status_code, 0) + 1
        )
        if page.waf_blocked:
            waf_signal_count += 1

        # Regex aggregation
        if page.matched_patterns:
            regex_hit_urls.append({
                "url":              page.url,
                "title":            page.title,
                "matched_patterns": page.matched_patterns,
                "matches": [
                    {
                        "pattern":     m.pattern,
                        "match_text":  m.match_text,
                        "match_count": m.match_count,
                        "context":     m.context,
                    }
                    for m in page.regex_matches
                ],
            })
            for pat in page.matched_patterns:
                pattern_hit_count[pat] = pattern_hit_count.get(pat, 0) + 1

        # Tech fingerprint — merge across pages
        t = page.tech
        if t.cms        and not tech_summary.get("cms"):        tech_summary["cms"]        = t.cms
        if t.waf        and not tech_summary.get("waf"):        tech_summary["waf"]        = t.waf
        if t.cdn        and not tech_summary.get("cdn"):        tech_summary["cdn"]        = t.cdn
        if t.server     and not tech_summary.get("server"):     tech_summary["server"]     = t.server
        if t.powered_by and not tech_summary.get("powered_by"): tech_summary["powered_by"] = t.powered_by

        if t.frameworks:
            fw = tech_summary.setdefault("frameworks", set())
            fw.update(t.frameworks)
        if t.missing_security_headers:
            ms = tech_summary.setdefault("missing_security_headers", set())
            ms.update(t.missing_security_headers)
        if t.security_headers:
            sh = tech_summary.setdefault("security_headers", {})
            sh.update(t.security_headers)

    # Convert sets to sorted lists for JSON serialisation
    for key in ("frameworks", "missing_security_headers"):
        if key in tech_summary and isinstance(tech_summary[key], set):
            tech_summary[key] = sorted(tech_summary[key])

    avg_rt = round(sum(response_times) / len(response_times), 1) if response_times else 0

    forms_with_password  = [f for f in all_forms if f.get("has_password")]
    forms_with_upload    = [f for f in all_forms if f.get("has_file_upload")]
    forms_without_csrf   = [f for f in all_forms if not f.get("has_csrf_token")]

    return {
        "target":                  start_url,
        "scraped_at":              datetime.utcnow().isoformat() + "Z",
        "total_pages":             len(results),
        "avg_response_time_ms":    avg_rt,
        "waf_signals_detected":    waf_signal_count,
        # Regex
        "regex_patterns_used":     regex_patterns,
        "regex_pattern_errors":    regex_errors,
        "regex_matched_urls":      regex_hit_urls,
        "regex_total_hits":        len(regex_hit_urls),
        "regex_pattern_hit_count": pattern_hit_count,
        # OSINT
        "emails":              sorted(all_emails),
        "phones":              sorted(all_phones),
        "forms":               all_forms,
        "forms_with_password": forms_with_password,
        "forms_with_upload":   forms_with_upload,
        "forms_without_csrf":  forms_without_csrf,
        "comments":            all_comments,
        "subdomains":          sorted(all_subdomains),
        "api_endpoints":       sorted(all_api_endpoints),
        "js_sensitive_vars":   sorted(all_js_vars),
        "external_links":      sorted(all_external)[:300],
        "pages_by_status":     pages_by_status,
        "tech":                tech_summary,
        "pages":               [asdict(p) for p in results],
    }


# ── Rich terminal display ──────────────────────────────────────────────────────

def format_report(report: Dict) -> None:
    tech       = report.get("tech", {})
    regex_hits = report.get("regex_matched_urls", [])

    # ── Summary panel ─────────────────────────────────────────────────────────
    hdr = Text()
    rows = [
        ("Target",               report.get("target", "?"),                           "bold cyan"),
        ("Scraped at",           report.get("scraped_at", "?"),                       "white"),
        ("Pages crawled",        str(report.get("total_pages", 0)),                   "bold green"),
        ("Avg response time",    f"{report.get('avg_response_time_ms', 0)} ms",       "white"),
        ("WAF signals",          str(report.get("waf_signals_detected", 0)),          "bold yellow"),
        ("Regex patterns",       str(len(report.get("regex_patterns_used", []))),     "bold magenta"),
        ("Regex hits",           str(report.get("regex_total_hits", 0)),              "bold red"),
        ("Emails",               str(len(report.get("emails", []))),                  "bold yellow"),
        ("Phones",               str(len(report.get("phones", []))),                  "bold yellow"),
        ("Forms (total)",        str(len(report.get("forms", []))),                   "bold magenta"),
        ("Forms w/o CSRF",       str(len(report.get("forms_without_csrf", []))),      "bold red"),
        ("API endpoints",        str(len(report.get("api_endpoints", []))),           "bold red"),
        ("JS sensitive vars",    str(len(report.get("js_sensitive_vars", []))),       "bold red"),
        ("Subdomains",           str(len(report.get("subdomains", []))),              "bold blue"),
    ]
    for label, value, style in rows:
        hdr.append(f"  {label:<22}", style="dim")
        hdr.append(f"{value}\n", style=style)

    console.print(Panel(
        hdr,
        title="[bold cyan]🕷  CREEPER v3.0 — Recon Report[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
    ))

    # ── Regex hits ────────────────────────────────────────────────────────────
    if regex_hits:
        console.print(f"\n[bold red]🎯 Regex Hits — {len(regex_hits)} URL(s)[/bold red]")
        pat_counts = report.get("regex_pattern_hit_count", {})
        if pat_counts:
            console.print("  [dim]Pattern hit count:[/dim]")
            for pat, cnt in sorted(pat_counts.items(), key=lambda x: -x[1]):
                console.print(f"    [magenta]{pat}[/magenta]  →  [yellow]{cnt}[/yellow] page(s)")
        console.print()
        for i, hit in enumerate(regex_hits, 1):
            pats = ", ".join(f"[magenta]{p}[/magenta]" for p in hit["matched_patterns"])
            console.print(f"  [dim]{i:3}.[/dim] [cyan]{hit['url']}[/cyan]")
            console.print(f"        [dim]Title:[/dim] {hit['title']}")
            console.print(f"        [dim]Patterns:[/dim] {pats}")
            for m in hit["matches"][:3]:
                console.print(
                    f"        [dim]Match:[/dim] [green]{m['match_text'][:80]}[/green]"
                    f"  [dim]({m['match_count']}×)[/dim]"
                )
            console.print()
    elif report.get("regex_patterns_used"):
        console.print("\n[dim]No pages matched the supplied regex patterns.[/dim]")

    # ── Tech fingerprint ──────────────────────────────────────────────────────
    if tech:
        console.print("\n[bold white]🔍 Technology Fingerprint[/bold white]")
        tbl = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        for label, key, color in [
            ("Server",     "server",     "cyan"),
            ("Powered By", "powered_by", "cyan"),
            ("CMS",        "cms",        "green"),
            ("WAF",        "waf",        "red"),
            ("CDN",        "cdn",        "blue"),
            ("Frameworks", "frameworks", "yellow"),
        ]:
            raw = tech.get(key, "")
            val = ", ".join(raw) if isinstance(raw, list) else (raw or "—")
            tbl.add_row(f"  [dim]{label}[/dim]", f"[{color}]{val}[/{color}]")
        console.print(tbl)
        missing = tech.get("missing_security_headers", [])
        if missing:
            console.print(f"  [red]⚠ Missing headers:[/red] {', '.join(missing)}")

    # ── Emails ────────────────────────────────────────────────────────────────
    if emails := report.get("emails", []):
        console.print("\n[bold yellow]📧 Emails[/bold yellow]")
        for e in emails[:50]:
            console.print(f"  [cyan]✉[/cyan]  {e}")
        if len(emails) > 50:
            console.print(f"  [dim]… and {len(emails)-50} more[/dim]")

    # ── Phones ────────────────────────────────────────────────────────────────
    if phones := report.get("phones", []):
        console.print("\n[bold yellow]📞 Phones[/bold yellow]")
        for p in phones[:20]:
            console.print(f"  [cyan]☏[/cyan]  {p}")

    # ── Subdomains ────────────────────────────────────────────────────────────
    if subs := report.get("subdomains", []):
        console.print("\n[bold blue]🌐 Subdomains[/bold blue]")
        for s in subs[:30]:
            console.print(f"  [dim]→[/dim] {s}")

    # ── API endpoints ─────────────────────────────────────────────────────────
    if apis := report.get("api_endpoints", []):
        console.print("\n[bold red]🔗 API Endpoints[/bold red]")
        for ep in apis[:30]:
            console.print(f"  [red]›[/red] {ep}")

    # ── JS sensitive vars ─────────────────────────────────────────────────────
    if js_vars := report.get("js_sensitive_vars", []):
        console.print("\n[bold red]⚠  Sensitive JS Vars / Secrets[/bold red]")
        for v in js_vars[:20]:
            console.print(f"  [red]![/red] {v[:120]}")

    # ── Forms attack surface ──────────────────────────────────────────────────
    if forms := report.get("forms", []):
        console.print("\n[bold magenta]📝 Forms — Attack Surface[/bold magenta]")
        for i, frm in enumerate(forms[:20], 1):
            flags = []
            if frm.get("has_password"):    flags.append("[red]PASSWORD[/red]")
            if frm.get("has_file_upload"): flags.append("[yellow]UPLOAD[/yellow]")
            if not frm.get("has_csrf_token"): flags.append("[red]NO-CSRF[/red]")
            console.print(
                f"\n  [dim]{i}.[/dim] [yellow]{frm['method']}[/yellow]"
                f" → [cyan]{frm['action'][:72]}[/cyan]  {' '.join(flags)}"
            )
            names = [inp["name"] for inp in frm.get("inputs", []) if inp.get("name")]
            if names:
                console.print(f"     [dim]Fields:[/dim] {', '.join(names[:10])}")

    # ── Comments ──────────────────────────────────────────────────────────────
    if comments := report.get("comments", []):
        console.print("\n[bold green]💬 HTML Comments[/bold green]")
        for c in comments[:10]:
            console.print(f"  [dim]»[/dim] {c[:120]}")

    # ── Status code distribution ──────────────────────────────────────────────
    if pbs := report.get("pages_by_status", {}):
        console.print("\n[bold blue]📄 Pages by Status[/bold blue]")
        for status, count in sorted(pbs.items()):
            color = "green" if status == 200 else "yellow" if 300 <= status < 400 else "red"
            console.print(f"  [{color}]{status}[/{color}]  {count} page(s)")

    console.print()
