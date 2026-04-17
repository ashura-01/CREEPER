"""
CREEPER/server.py
Optional Flask API server — connects the GUI to the Python scraper.

Usage:
    pip install flask
    python server.py
    Open http://localhost:5000 in your browser.
"""

import json
import sys
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory

# Make sure modules/ is importable
sys.path.insert(0, str(Path(__file__).parent))

from modules.web_scraper import AsyncOSINTScraper

app = Flask(__name__, static_folder=".", static_url_path="")


@app.route("/")
def index():
    return send_from_directory(".", "CREEPER_scraper_gui.html")


@app.route("/api/scrape", methods=["POST"])
def scrape():
    data = request.get_json(force=True) or {}

    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scraper = AsyncOSINTScraper(
        concurrency=int(data.get("concurrency", 5)),
        delay_range=(
            float(data.get("delay_min", 0.5)),
            float(data.get("delay_max", 2.0)),
        ),
        timeout=int(data.get("timeout", 15)),
        use_playwright=bool(data.get("use_js", False)),
        respect_robots=bool(data.get("respect_robots", True)),
        verify_ssl=bool(data.get("verify_ssl", True)),
        regex_patterns=data.get("regex_patterns", []),
        regex_match_only=bool(data.get("match_only", False)),
    )

    try:
        report = scraper.scrape(
            start_url=url,
            max_depth=int(data.get("max_depth", 2)),
            max_pages=int(data.get("max_pages", 50)),
            output_dir=data.get("output_dir", "./output"),
            export_formats=data.get("export_formats", ["json"]),
        )
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("\n  🕷️  CREEPER OSINT Scraper Server")
    print("  ─────────────────────────────────")
    print("  GUI  →  http://localhost:5000")
    print("  API  →  http://localhost:5000/api/scrape\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
