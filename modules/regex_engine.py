"""
modules/regex_engine.py
User-supplied regex pattern compilation and page matching.
Returns match objects with context snippets for the results panel.
"""

from __future__ import annotations

import re
import logging
from typing import List, Tuple

from .models import RegexMatch

logger = logging.getLogger("CREEPER.regex")


class RegexEngine:
    """
    Compile and apply multiple user-supplied regex patterns against page content.

    Searches both stripped page text AND raw HTML so patterns can target
    either visible content or markup (e.g. hidden inputs, comments, data-*).
    """

    def __init__(self, patterns: List[str], flags: int = re.IGNORECASE):
        self.raw_patterns = list(patterns)
        self.compiled: List[Tuple[str, re.Pattern]] = []
        self.errors:   List[str] = []

        for pat in patterns:
            pat = pat.strip()
            if not pat:
                continue
            try:
                self.compiled.append((pat, re.compile(pat, flags)))
            except re.error as exc:
                self.errors.append(f"Invalid regex '{pat}': {exc}")
                logger.warning("Invalid regex pattern ignored: %s — %s", pat, exc)

    # ── Public API ────────────────────────────────────────────────────────────

    def match_page(
        self, page_text: str, html: str
    ) -> Tuple[List[RegexMatch], List[str]]:
        """
        Run every compiled pattern against visible text and raw HTML.

        Returns:
            matches        – list of RegexMatch (one per fired pattern)
            fired_patterns – list of pattern strings that matched
        """
        matches:        List[RegexMatch] = []
        fired_patterns: List[str]        = []

        sources = [("text", page_text), ("html", html)]

        for pat_str, compiled in self.compiled:
            best:        RegexMatch | None = None
            total_count: int               = 0

            for source_name, source in sources:
                found = list(compiled.finditer(source))
                if not found:
                    continue

                total_count += len(found)

                if best is None:
                    m     = found[0]
                    start = max(0, m.start() - 80)
                    end   = min(len(source), m.end() + 80)
                    ctx   = source[start:end]

                    if source_name == "html":
                        # Strip tags so context is readable
                        ctx = re.sub(r"<[^>]+>", " ", ctx)
                        ctx = re.sub(r"\s+", " ", ctx).strip()

                    best = RegexMatch(
                        pattern=pat_str,
                        match_text=m.group(0)[:300],
                        match_count=0,          # filled in below
                        context=ctx[:300],
                    )

            if best is not None:
                best.match_count = total_count
                matches.append(best)
                fired_patterns.append(pat_str)

        return matches, fired_patterns

    # ── Helpers ───────────────────────────────────────────────────────────────

    def is_valid(self) -> bool:
        return bool(self.compiled)

    @property
    def pattern_count(self) -> int:
        return len(self.compiled)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"RegexEngine(patterns={self.pattern_count}, "
            f"errors={len(self.errors)})"
        )
