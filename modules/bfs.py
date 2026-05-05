"""
modules/bfs.py
Breadth-first-search crawler.
Pulls URLs from an asyncio.Queue, respects domain scope, depth and page caps,
and delegates fetching to the Spider passed in at construction time.

Bug-fixes vs original:
  1. Race on startup — workers must NOT exit when in_flight==0 if they haven't
     tried to pull from the queue yet.  Fixed with a sentinel-based shutdown:
     after all real work is done the orchestrator pushes N sentinel NONEs, one
     per worker, so each worker exits cleanly exactly once.
  2. www-redirect domain drift — base_domain is expanded to accept both
     "example.com" and "www.example.com" so a redirect to www. doesn't orphan
     every discovered link.
  3. queue.task_done() without queue.join() was a no-op; replaced with the
     sentinel pattern which is simpler and correct.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Optional, Set, Tuple
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

if TYPE_CHECKING:
    from .spider import Spider

logger  = logging.getLogger("CREEPER.bfs")
console = Console()

# Sentinel placed on the queue to tell a worker to stop
_DONE = None


def _accepted_domains(start_url: str) -> Set[str]:
    """
    Return the set of netloc values we consider "same domain".
    Handles the common case where the server redirects bare → www or vice-versa.
    """
    netloc = urlparse(start_url).netloc.lower()
    bare   = netloc.removeprefix("www.")
    return {bare, f"www.{bare}"}


class BFSCrawler:
    """
    Concurrent BFS over a single domain.

    Usage:
        crawler = BFSCrawler(spider, concurrency=5)
        await crawler.run(start_url, max_depth, max_pages)
        # spider.results now contains all ScrapedPage objects
    """

    def __init__(self, spider: "Spider", concurrency: int = 5):
        self._spider      = spider
        self._concurrency = max(1, concurrency)

    # ── Entry point ───────────────────────────────────────────────────────────

    async def run(self, start_url: str, max_depth: int, max_pages: int) -> None:
        accepted = _accepted_domains(start_url)
        logger.debug("BFS accepted domains: %s", accepted)

        # Unbounded queue — (url, depth) tuples plus _DONE sentinels
        queue: asyncio.Queue[Optional[Tuple[str, int]]] = asyncio.Queue()
        await queue.put((start_url, 0))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("[cyan]Crawling…", total=max_pages)

            # ── Shared counter (asyncio is single-threaded so no lock needed) ─
            pending = [1]   # items currently in queue + in processing

            def enqueue(url: str, depth: int) -> None:
                """Put a URL on the queue and increment the pending counter."""
                pending[0] += 1
                queue.put_nowait((url, depth))

            def done_one() -> None:
                """Decrement pending; if zero push sentinels to stop all workers."""
                pending[0] -= 1
                if pending[0] == 0:
                    for _ in range(self._concurrency):
                        queue.put_nowait(_DONE)

            async def process(url: str, depth: int) -> None:
                spider = self._spider
                netloc = urlparse(url).netloc.lower()

                # ── Skip-reason logging so we can diagnose silently dropped pages ──
                if url in spider.visited:
                    logger.debug("SKIP already-visited: %s", url)
                    return
                if len(spider.results) >= max_pages:
                    logger.debug("SKIP page-cap reached (%d): %s", max_pages, url)
                    return
                if depth > max_depth:
                    logger.debug("SKIP depth %d > max %d: %s", depth, max_depth, url)
                    return
                if netloc not in accepted:
                    logger.debug("SKIP domain %r not in %s: %s", netloc, accepted, url)
                    return
                if spider.is_disallowed(url):
                    logger.debug("SKIP robots disallowed: %s", url)
                    return

                spider.visited.add(url)
                progress.update(
                    task_id,
                    advance=1,
                    description=f"[cyan]Crawling:[/cyan] {url[:72]}",
                )

                page = await spider.fetch_page(url)
                if page is None:
                    logger.debug("SKIP fetch returned None: %s", url)
                    return

                logger.debug(
                    "FETCHED status=%d links=%d: %s",
                    page.status_code, len(page.links), url
                )

                # In match-only mode still crawl deeper but don't store the page
                store = True
                if spider.regex_match_only and spider.regex_engine.is_valid():
                    if not page.matched_patterns:
                        store = False

                if store:
                    spider.results.append(page)

                # Enqueue child links regardless of store flag
                child_count = 0
                for link in page.links:
                    if link not in spider.visited:
                        enqueue(link, depth + 1)
                        child_count += 1
                logger.debug("ENQUEUED %d child links from: %s", child_count, url)

            async def worker() -> None:
                while True:
                    item = await queue.get()

                    if item is _DONE:
                        # Sentinel: forward it so other workers also exit, then stop
                        queue.put_nowait(_DONE)
                        break

                    url, depth = item
                    if len(self._spider.results) < max_pages:
                        try:
                            await asyncio.wait_for(process(url, depth), timeout=45)
                        except asyncio.TimeoutError:
                            logger.debug("Timeout processing %s", url)
                        except Exception as exc:
                            logger.debug("Worker error on %s: %s", url, exc)

                    done_one()

            # ── Launch workers ─────────────────────────────────────────────
            workers = [asyncio.create_task(worker()) for _ in range(self._concurrency)]
            try:
                await asyncio.wait_for(
                    asyncio.gather(*workers, return_exceptions=True),
                    timeout=3600,
                )
            except asyncio.TimeoutError:
                logger.warning("BFS hit 1-hour ceiling — cancelling workers")
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
