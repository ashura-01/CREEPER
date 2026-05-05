"""
CREEPER/server.py
Lightweight Flask API server — bridges the GUI to the Python scraper.
Run:  python server.py
GUI:  open http://localhost:5000
"""

import json
import logging
import threading
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from modules.orchestrator import AsyncOSINTScraper

logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] %(name)s — %(message)s")
logging.getLogger("aiohttp").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("werkzeug").setLevel(logging.INFO)
logger = logging.getLogger("CREEPER.server")

app = Flask(__name__, static_folder=".")
CORS(app)

OUTPUT_DIR = Path("./output")
OUTPUT_DIR.mkdir(exist_ok=True)

# Track running jobs {job_id: {"status", "report", "error"}}
_jobs: dict = {}
_lock = threading.Lock()


@app.route("/")
def index():
    return send_from_directory(".", "CREEPER_scraper_gui.html")


@app.route("/api/scrape", methods=["POST"])
def api_scrape():
    """
    Synchronous scrape endpoint (blocks until complete).
    Body JSON keys:
        url, max_depth, max_pages, concurrency,
        delay_min, delay_max, timeout,
        use_js, respect_robots, verify_ssl, match_only,
        regex_patterns, export_formats, custom_headers
    """
    data = request.get_json(force=True) or {}

    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    fmts = data.get("export_formats") or ["json"]

    try:
        scraper = AsyncOSINTScraper(
            concurrency=int(data.get("concurrency", 5)),
            delay_range=(
                float(data.get("delay_min", 1.0)),
                float(data.get("delay_max", 3.0)),
            ),
            timeout=int(data.get("timeout", 20)),
            use_playwright=bool(data.get("use_js", False)),
            respect_robots=bool(data.get("respect_robots", True)),
            verify_ssl=bool(data.get("verify_ssl", True)),
            regex_patterns=data.get("regex_patterns") or [],
            regex_match_only=bool(data.get("match_only", False)),
            custom_headers=data.get("custom_headers") or {},
            proxies=data.get("proxies") or [],
            ninja_mode=bool(data.get("ninja_mode", False)),
        )
        report = scraper.scrape(
            start_url=url,
            max_depth=int(data.get("max_depth", 2)),
            max_pages=int(data.get("max_pages", 50)),
            output_dir=str(OUTPUT_DIR),
            export_formats=fmts,
        )
        return jsonify(report)
    except Exception as exc:
        logger.exception("Scrape failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": "3.0"})


if __name__ == "__main__":
    print("\n🕷  CREEPER v3 server — http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
