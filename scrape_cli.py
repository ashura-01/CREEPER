"""
CREEPER/scrape_cli.py
CLI entry point for the Async OSINT Web Scraper — with Regex Pattern support
"""

import argparse
import sys
from modules.web_scraper import AsyncOSINTScraper, format_scraper, PLAYWRIGHT_AVAILABLE
from rich.console import Console

console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="CREEPER — Async OSINT Web Scraper with Regex URL Matching",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES
────────
  # Basic crawl
  python scrape_cli.py https://example.com

  # Find LinkedIn profiles matching cybersecurity keywords
  python scrape_cli.py https://linkedin.com/search/results/people/?keywords=security -d 2 -p 100 \\
      --regex "pentester" "CTF player" "cyber security" "bug bounty" "red team"

  # Only return pages that matched the regex (ignore non-matching pages)
  python scrape_cli.py https://example.com --regex "admin" "login" --match-only

  # Full OSINT crawl with JS rendering and multiple export formats
  python scrape_cli.py https://target.com -d 3 -p 200 --js --export json csv sqlite \\
      --regex "api_key\\s*=" "password\\s*=" "secret\\s*="
        """,
    )

    parser.add_argument("url", help="Target URL to scrape")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Max crawl depth")
    parser.add_argument(
        "-p", "--pages", type=int, default=50, help="Max pages to crawl"
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=5, help="Async workers"
    )
    parser.add_argument(
        "--delay-min", type=float, default=0.5, help="Min delay between requests (s)"
    )
    parser.add_argument(
        "--delay-max", type=float, default=2.0, help="Max delay between requests (s)"
    )
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout (s)")
    parser.add_argument("--no-robots", action="store_true", help="Ignore robots.txt")
    parser.add_argument(
        "--no-ssl-verify", action="store_true", help="Disable SSL verification"
    )
    parser.add_argument(
        "--js",
        action="store_true",
        help="Enable Playwright JS rendering for dynamic pages"
        + ("" if PLAYWRIGHT_AVAILABLE else " [NOT INSTALLED]"),
    )
    parser.add_argument(
        "--regex",
        "-r",
        nargs="+",
        metavar="PATTERN",
        default=[],
        help="One or more regex patterns. Pages matching ANY pattern are flagged and their URLs returned. "
        'Example: --regex "pentester" "CTF" "bug bounty"',
    )
    parser.add_argument(
        "--match-only",
        action="store_true",
        help="Only include pages in results where at least one regex pattern matched. "
        "Useful for targeted searches like finding specific profiles.",
    )
    parser.add_argument(
        "--export",
        nargs="+",
        choices=["json", "csv", "sqlite"],
        default=["json"],
        help="Export formats",
    )
    parser.add_argument(
        "-o", "--output", default=".", help="Output directory for exports"
    )

    args = parser.parse_args()

    if args.js and not PLAYWRIGHT_AVAILABLE:
        console.print(
            "[red]Playwright is not installed. Run: pip install playwright && playwright install chromium[/red]"
        )
        sys.exit(1)

    console.print(
        f"\n[bold cyan]CREEPER OSINT Scraper[/bold cyan] — targeting [cyan]{args.url}[/cyan]"
    )
    console.print(
        f"[dim]Depth: {args.depth}  |  Max pages: {args.pages}  |  Concurrency: {args.concurrency}  |"
        f"  JS render: {args.js}  |  Export: {', '.join(args.export)}[/dim]"
    )
    if args.regex:
        console.print(
            f"[dim]Regex patterns ({len(args.regex)}): {' | '.join(args.regex)}[/dim]"
        )
        if args.match_only:
            console.print(
                "[dim]Mode: match-only (non-matching pages will be discarded)[/dim]"
            )
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
    )

    report = scraper.scrape(
        start_url=args.url,
        max_depth=args.depth,
        max_pages=args.pages,
        output_dir=args.output,
        export_formats=args.export,
    )

    format_scraper(report)

    # Print a clean URL list at the very end if we had regex matches
    if report.get("regex_matched_urls"):
        console.print(
            "\n[bold cyan]━━━ MATCHED URLS (copy-paste ready) ━━━[/bold cyan]"
        )
        for hit in report["regex_matched_urls"]:
            console.print(hit["url"])
        console.print()


if __name__ == "__main__":
    main()
