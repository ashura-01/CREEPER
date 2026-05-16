"""
modules/models.py
Shared dataclasses for CREEPER.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class RegexMatch:
    pattern:     str
    match_text:  str
    match_count: int
    context:     str


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


@dataclass
class Parameter:
    """A URL query parameter found during crawl."""
    name:     str
    value:    str
    url:      str
    method:   str = "GET"   # GET from URL, POST from form


@dataclass
class JSFile:
    """A fetched and parsed JavaScript file."""
    url:          str
    size_bytes:   int       = 0
    endpoints:    List[str] = field(default_factory=list)
    secrets:      List[str] = field(default_factory=list)
    subdomains:   List[str] = field(default_factory=list)
    sourcemaps:   List[str] = field(default_factory=list)
    framework_hints: List[str] = field(default_factory=list)
    error:        str       = ""


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
    parameters:       List[Dict]  = field(default_factory=list)   # NEW
    js_files:         List[str]   = field(default_factory=list)   # NEW — parsed JS URLs
    sourcemaps:       List[str]   = field(default_factory=list)   # NEW
    tech:             TechFingerprint = field(default_factory=TechFingerprint)
    rendered:         bool        = False
    waf_blocked:      bool        = False
    regex_matches:    List[RegexMatch] = field(default_factory=list)
    matched_patterns: List[str]   = field(default_factory=list)