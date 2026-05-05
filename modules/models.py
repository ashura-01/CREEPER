"""
modules/models.py
Shared dataclasses for CREEPER.  Every other module imports from here —
nothing else imports from each other to keep deps one-directional.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict


# ── Regex engine output ───────────────────────────────────────────────────────

@dataclass
class RegexMatch:
    """One regex pattern match found on a page."""
    pattern:     str   # the pattern string
    match_text:  str   # actual matched text (≤300 chars)
    match_count: int   # total hits on this page
    context:     str   # surrounding snippet (≤300 chars)


# ── Tech fingerprint ──────────────────────────────────────────────────────────

@dataclass
class TechFingerprint:
    server:                   str        = ""
    powered_by:               str        = ""
    frameworks:               List[str]  = field(default_factory=list)
    cms:                      str        = ""
    cdn:                      str        = ""
    waf:                      str        = ""
    cookies:                  List[str]  = field(default_factory=list)
    security_headers:         Dict[str, str] = field(default_factory=dict)
    missing_security_headers: List[str]  = field(default_factory=list)


# ── Scraped page (one crawled URL) ────────────────────────────────────────────

@dataclass
class ScrapedPage:
    url:              str
    title:            str
    status_code:      int
    content_type:     str
    text_preview:     str
    response_time_ms: float       = 0.0
    links:            List[str]   = field(default_factory=list)
    external_links:   List[str]   = field(default_factory=list)
    emails:           List[str]   = field(default_factory=list)
    phones:           List[str]   = field(default_factory=list)
    forms:            List[Dict]  = field(default_factory=list)
    scripts:          List[str]   = field(default_factory=list)
    comments:         List[str]   = field(default_factory=list)
    meta:             Dict[str, str] = field(default_factory=dict)
    subdomains:       List[str]   = field(default_factory=list)
    api_endpoints:    List[str]   = field(default_factory=list)
    js_variables:     List[str]   = field(default_factory=list)
    tech:             TechFingerprint = field(default_factory=TechFingerprint)
    rendered:         bool        = False
    waf_blocked:      bool        = False
    regex_matches:    List[RegexMatch] = field(default_factory=list)
    matched_patterns: List[str]   = field(default_factory=list)
