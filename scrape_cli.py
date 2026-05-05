"""
CREEPER/scrape_cli.py
CLI entry point — bug-hunting focused recon scraper.
"""

import argparse
import json
import sys

from rich.console import Console

from modules.orchestrator import AsyncOSINTScraper
from modules.reporter import format_report

try:
    from playwright.async_api import async_playwright  # noqa
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

console = Console()


def main() -> None:
    p = argparse.ArgumentParser(
        description="CREEPER v3 — Stealth Bug-Hunt Recon Crawler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES
────────
  # Basic crawl
  python scrape_cli.py https://target.com

  # Hunt for exposed secrets / API keys
  python scrape_cli.py https://target.com -d 3 -p 150 \\
      --regex "api_key\\s*=" "secret\\s*=" "password\\s*=" "AKIA[0-9A-Z]{16}"

  # Only collect pages that matched a pattern (match-only mode)
  python scrape_cli.py https://target.com --regex "/admin" "/debug" --match-only

  # Authenticated crawl with session cookie
  python scrape_cli.py https://target.com --header "Cookie=session=abc123" \\
      --header "Authorization=Bearer eyJ..."

  # Full recon: JS render + all exports + slow/stealthy
  python scrape_cli.py https://target.com -d 4 -p 300 --js \\
      --delay-min 2.0 --delay-max 5.0 -c 3 \\
      --export json csv sqlite
""",
    )

    p.add_argument("url",            help="Target URL")
    p.add_argument("-d", "--depth",  type=int,   default=2,    help="Max crawl depth (default 2)")
    p.add_argument("-p", "--pages",  type=int,   default=50,   help="Max pages (default 50)")
    p.add_argument("-c", "--concurrency", type=int, default=5, help="Parallel workers (default 5, max 20)")
    p.add_argument("--delay-min",    type=float, default=1.0,  help="Min per-domain delay seconds (default 1.0)")
    p.add_argument("--delay-max",    type=float, default=3.0,  help="Max per-domain delay seconds (default 3.0)")
    p.add_argument("--timeout",      type=int,   default=20,   help="Request timeout seconds (default 20)")
    p.add_argument("--js",           action="store_true",      help="Enable Playwright JS rendering")
    p.add_argument("--no-robots",    action="store_true",      help="Ignore robots.txt")
    p.add_argument("--no-ssl-verify",action="store_true",      help="Disable SSL certificate verification")
    p.add_argument("--match-only",   action="store_true",      help="Only store pages where a regex pattern matched")
    p.add_argument("--regex", "-r",  nargs="+", metavar="PAT", default=[],
                   help="Python regex patterns to hunt. Pages matching ANY pattern are flagged.")
    p.add_argument("--header",       nargs="+", metavar="K=V", default=[],
                   help="Custom request headers (e.g. Cookie=session=abc  Authorization=Bearer ...)")
    p.add_argument("--export",       nargs="+", choices=["json","csv","sqlite"], default=["json"],
                   help="Export formats (default: json)")
    p.add_argument("-o","--output",  default=".", help="Output directory (default: current dir)")
    p.add_argument("--json-only",    action="store_true",      help="Print JSON report to stdout and exit")

    args = p.parse_args()

    if args.js and not PLAYWRIGHT_AVAILABLE:
        console.print("[red]Playwright not installed. Run:[/red]  pip install playwright && playwright install chromium")
        sys.exit(1)

    # Parse custom headers
    custom_headers = {}
    for kv in args.header:
        if "=" in kv:
            k, _, v = kv.partition("=")
            custom_headers[k.strip()] = v.strip()

    # Banner
    console.print(f"\n[bold cyan]🕷  CREEPER v3[/bold cyan] — [cyan]{args.url}[/cyan]")
    console.print(
        f"[dim]depth:{args.depth}  pages:{args.pages}  workers:{args.concurrency}  "
        f"delay:{args.delay_min}–{args.delay_max}s  timeout:{args.timeout}s  "
        f"js:{args.js}  export:{', '.join(args.export)}[/dim]"
    )
    if args.regex:
        console.print(f"[dim]Patterns ({len(args.regex)}): {' | '.join(args.regex)}[/dim]")
    if custom_headers:
        console.print(f"[dim]Custom headers: {list(custom_headers.keys())}[/dim]")
    console.print()

    scraper = AsyncOSINTScraper(
        concurrency=args.concurrency,
        delay_range=(args.delay_min, args.delay_max),
        timeout=args.timeout,
        use_playwright=args.js,
        respect_robots=not args.no_robots,
        verify_ssl=not args.no_ssl_verify,
        regex_patterns=args.regex,
        regex_match_only=args.match_only,
        custom_headers=custom_headers,
    )

    report = scraper.scrape(
        start_url=args.url,
        max_depth=args.depth,
        max_pages=args.pages,
        output_dir=args.output,
        export_formats=args.export,
    )

    if args.json_only:
        print(json.dumps(report, indent=2, default=str))
        return

    format_report(report)

    # Print matched URLs at the end — copy-paste ready
    if report.get("regex_matched_urls"):
        console.print("\n[bold cyan]━━━ MATCHED URLs (copy-paste ready) ━━━[/bold cyan]")
        for hit in report["regex_matched_urls"]:
            console.print(hit["url"])
        console.print()


if __name__ == "__main__":
    main()
