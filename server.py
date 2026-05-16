"""
CREEPER/server.py
FastAPI server — bridges the GUI to the async Python scraper.

Run:  uvicorn server:app --host 0.0.0.0 --port 5000 --reload
 or:  python server.py

GUI:  open http://localhost:5000

Install deps (if not already):
    pip install fastapi uvicorn[standard] python-multipart
"""

import logging
import uvicorn
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from modules.orchestrator import AsyncOSINTScraper

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(levelname)s] %(name)s — %(message)s",
)
logging.getLogger("aiohttp").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.INFO)

logger = logging.getLogger("CREEPER.server")

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="CREEPER v3",
    description="Bug-hunt recon crawler API",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

OUTPUT_DIR = Path("./output")
OUTPUT_DIR.mkdir(exist_ok=True)

# ── Request model ─────────────────────────────────────────────────────────────

class ScrapeRequest(BaseModel):
    url:             str
    max_depth:       int             = Field(2,    ge=1, le=10)
    max_pages:       int             = Field(50,   ge=1, le=1000)
    concurrency:     int             = Field(5,    ge=1, le=20)
    delay_min:       float           = Field(1.0,  ge=0.0)
    delay_max:       float           = Field(3.0,  ge=0.0)
    timeout:         int             = Field(20,   ge=5,  le=120)
    use_js:          bool            = False
    respect_robots:  bool            = True
    verify_ssl:      bool            = True
    match_only:      bool            = False
    ninja_mode:      bool            = False
    regex_patterns:  List[str]       = Field(default_factory=list)
    export_formats:  List[str]       = Field(default_factory=lambda: ["json"])
    custom_headers:  Dict[str, str]  = Field(default_factory=dict)
    proxies:         List[str]       = Field(default_factory=list)

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse("CREEPER_scraper_gui.html")


@app.get("/api/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "version": "3.0"}


@app.post("/api/scrape")
async def api_scrape(body: ScrapeRequest) -> JSONResponse:
    """
    Run a full recon crawl. Awaits the async engine directly — no
    asyncio.run() wrapper needed because FastAPI runs in an async context.
    """
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="url is required")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    logger.info("Scrape request: %s  depth=%d pages=%d", url, body.max_depth, body.max_pages)

    try:
        scraper = AsyncOSINTScraper(
            concurrency=body.concurrency,
            delay_range=(body.delay_min, body.delay_max),
            timeout=body.timeout,
            use_playwright=body.use_js,
            respect_robots=body.respect_robots,
            verify_ssl=body.verify_ssl,
            regex_patterns=body.regex_patterns,
            regex_match_only=body.match_only,
            custom_headers=body.custom_headers,
            proxies=body.proxies,
            ninja_mode=body.ninja_mode,
        )

        # Call _run directly — FastAPI is already in an async event loop
        report = await scraper._run(
            start_url=url,
            max_depth=body.max_depth,
            max_pages=body.max_pages,
            output_dir=str(OUTPUT_DIR),
            export_formats=body.export_formats,
        )

        return JSONResponse(content=report)

    except Exception as exc:
        logger.exception("Scrape failed for %s", url)
        raise HTTPException(status_code=500, detail=str(exc))


# ── Static files (JS, CSS etc the GUI loads) ──────────────────────────────────
# Mount AFTER explicit routes so /api/* and / are not swallowed.

app.mount("/", StaticFiles(directory=".", html=False), name="static")


# ── Dev entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🕷  CREEPER v3 — http://localhost:5000\n")
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=5000,
        reload=True,         # auto-reload on file changes during dev
        log_level="info",
    )