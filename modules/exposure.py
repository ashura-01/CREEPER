"""
modules/exposure.py
Sensitive path prober — checks for exposed files/directories that should never
be publicly accessible. Designed for authorized bug bounty / pen-test recon.

Runs HEAD (falling back to GET) requests concurrently against a wordlist of
known-sensitive paths. Returns ExposureHit objects with severity, category,
and response metadata.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import aiohttp
from aiohttp import ClientSession, ClientTimeout

logger = logging.getLogger("CREEPER.exposure")

# ── Severity levels ────────────────────────────────────────────────────────────
CRIT   = "critical"
HIGH   = "high"
MED    = "medium"
LOW    = "low"
INFO   = "info"

# ── Probe wordlist ─────────────────────────────────────────────────────────────
# Format: (path, severity, category, description)
PROBE_PATHS: List[tuple] = [
    # ── Git / VCS ──────────────────────────────────────────────────────────────
    ("/.git/HEAD",                  CRIT,  "VCS",      "Git repo HEAD ref — source code may be recoverable"),
    ("/.git/config",                CRIT,  "VCS",      "Git config — may leak remote URLs and credentials"),
    ("/.git/COMMIT_EDITMSG",        HIGH,  "VCS",      "Git commit message exposed"),
    ("/.git/logs/HEAD",             HIGH,  "VCS",      "Git commit log exposed"),
    ("/.git/refs/heads/main",       HIGH,  "VCS",      "Git main branch ref exposed"),
    ("/.git/refs/heads/master",     HIGH,  "VCS",      "Git master branch ref exposed"),
    ("/.svn/entries",               CRIT,  "VCS",      "SVN repository entries exposed"),
    ("/.svn/wc.db",                 CRIT,  "VCS",      "SVN working copy database exposed"),
    ("/.hg/store/00manifest.i",     HIGH,  "VCS",      "Mercurial repository exposed"),

    # ── Environment / secrets ──────────────────────────────────────────────────
    ("/.env",                       CRIT,  "Secrets",  ".env file — likely contains DB creds, API keys"),
    ("/.env.local",                 CRIT,  "Secrets",  ".env.local — local override secrets"),
    ("/.env.production",            CRIT,  "Secrets",  ".env.production — production secrets"),
    ("/.env.backup",                CRIT,  "Secrets",  ".env.backup — backup env file"),
    ("/.env.old",                   CRIT,  "Secrets",  ".env.old — old secrets file"),
    ("/.env.example",               LOW,   "Secrets",  ".env.example — may reveal secret key names"),
    ("/config.env",                 CRIT,  "Secrets",  "config.env — environment config"),
    ("/secrets.yml",                CRIT,  "Secrets",  "secrets.yml — YAML secrets file"),
    ("/secrets.yaml",               CRIT,  "Secrets",  "secrets.yaml — YAML secrets file"),
    ("/credentials.json",           CRIT,  "Secrets",  "credentials.json — service account or API creds"),
    ("/service-account.json",       CRIT,  "Secrets",  "Google service account key"),
    ("/.aws/credentials",           CRIT,  "Secrets",  "AWS credentials file"),
    ("/aws.json",                   CRIT,  "Secrets",  "AWS config JSON"),

    # ── Config files ───────────────────────────────────────────────────────────
    ("/config.php",                 HIGH,  "Config",   "PHP config — may contain DB creds"),
    ("/config.inc.php",             HIGH,  "Config",   "PHP include config"),
    ("/wp-config.php",              CRIT,  "Config",   "WordPress config — DB creds"),
    ("/wp-config.php.bak",          CRIT,  "Config",   "WordPress config backup"),
    ("/LocalSettings.php",          HIGH,  "Config",   "MediaWiki settings"),
    ("/configuration.php",          HIGH,  "Config",   "Joomla config"),
    ("/app/etc/local.xml",          HIGH,  "Config",   "Magento local config"),
    ("/config/database.yml",        HIGH,  "Config",   "Rails database config"),
    ("/database.yml",               HIGH,  "Config",   "Database YAML config"),
    ("/application.yml",            HIGH,  "Config",   "Application config YAML"),
    ("/application.properties",     HIGH,  "Config",   "Java application properties"),
    ("/settings.py",                HIGH,  "Config",   "Django settings — may have SECRET_KEY"),
    ("/web.config",                 MED,   "Config",   "IIS web.config — may expose internals"),
    ("/.htaccess",                  LOW,   "Config",   ".htaccess — Apache config rules"),
    ("/nginx.conf",                 MED,   "Config",   "nginx config exposed"),
    ("/docker-compose.yml",         HIGH,  "Config",   "Docker compose — infra layout + secrets"),
    ("/docker-compose.yaml",        HIGH,  "Config",   "Docker compose YAML"),
    ("/.dockerenv",                 INFO,  "Config",   "Docker environment marker"),
    ("/Dockerfile",                 MED,   "Config",   "Dockerfile — reveals build process"),
    ("/Makefile",                   LOW,   "Config",   "Makefile — build commands"),

    # ── Backup / archive files ─────────────────────────────────────────────────
    ("/backup.zip",                 CRIT,  "Backup",   "Site backup archive"),
    ("/backup.tar.gz",              CRIT,  "Backup",   "Site backup tarball"),
    ("/backup.sql",                 CRIT,  "Backup",   "Raw SQL database dump"),
    ("/backup.sql.gz",              CRIT,  "Backup",   "Compressed SQL dump"),
    ("/db.sql",                     CRIT,  "Backup",   "Database SQL dump"),
    ("/dump.sql",                   CRIT,  "Backup",   "Database dump"),
    ("/database.sql",               CRIT,  "Backup",   "Database SQL backup"),
    ("/site.tar.gz",                CRIT,  "Backup",   "Full site backup"),
    ("/www.zip",                    CRIT,  "Backup",   "Web root archive"),
    ("/htdocs.zip",                 CRIT,  "Backup",   "htdocs archive"),
    ("/public_html.zip",            CRIT,  "Backup",   "public_html archive"),
    ("/old.zip",                    HIGH,  "Backup",   "Old version backup"),
    ("/archive.zip",                HIGH,  "Backup",   "Archive ZIP"),
    ("/backup/",                    HIGH,  "Backup",   "Backup directory listable"),

    # ── Log files ──────────────────────────────────────────────────────────────
    ("/error.log",                  HIGH,  "Logs",     "Error log — stack traces, paths, creds"),
    ("/access.log",                 HIGH,  "Logs",     "Access log — user activity, IPs"),
    ("/debug.log",                  HIGH,  "Logs",     "Debug log — internal application state"),
    ("/logs/error.log",             HIGH,  "Logs",     "Logs directory error log"),
    ("/storage/logs/laravel.log",   HIGH,  "Logs",     "Laravel application log"),
    ("/var/log/nginx/error.log",    HIGH,  "Logs",     "Nginx error log"),
    ("/php_errors.log",             HIGH,  "Logs",     "PHP error log"),

    # ── Admin / sensitive panels ───────────────────────────────────────────────
    ("/wp-admin/",                  MED,   "Admin",    "WordPress admin panel"),
    ("/wp-login.php",               MED,   "Admin",    "WordPress login page"),
    ("/admin/",                     MED,   "Admin",    "Admin directory"),
    ("/administrator/",             MED,   "Admin",    "Joomla admin panel"),
    ("/phpmyadmin/",                HIGH,  "Admin",    "phpMyAdmin — direct DB access"),
    ("/pma/",                       HIGH,  "Admin",    "phpMyAdmin alias"),
    ("/adminer.php",                HIGH,  "Admin",    "Adminer DB manager"),
    ("/adminer/",                   HIGH,  "Admin",    "Adminer directory"),
    ("/cpanel/",                    HIGH,  "Admin",    "cPanel hosting panel"),
    ("/webmail/",                   MED,   "Admin",    "Webmail interface"),
    ("/jenkins/",                   HIGH,  "Admin",    "Jenkins CI panel"),
    ("/solr/",                      HIGH,  "Admin",    "Apache Solr admin"),
    ("/kibana/",                    HIGH,  "Admin",    "Kibana dashboard"),
    ("/grafana/",                   MED,   "Admin",    "Grafana dashboard"),

    # ── Debug / development endpoints ─────────────────────────────────────────
    ("/debug",                      MED,   "Debug",    "Debug endpoint"),
    ("/debug/",                     MED,   "Debug",    "Debug directory"),
    ("/_profiler/",                 HIGH,  "Debug",    "Symfony profiler — internal app info"),
    ("/__debug__/",                 HIGH,  "Debug",    "Django debug toolbar"),
    ("/telescope",                  HIGH,  "Debug",    "Laravel Telescope debugger"),
    ("/telescope/requests",         HIGH,  "Debug",    "Laravel Telescope requests log"),
    ("/horizon",                    HIGH,  "Debug",    "Laravel Horizon queue monitor"),
    ("/_debugbar/",                 HIGH,  "Debug",    "PHP DebugBar"),
    ("/info.php",                   HIGH,  "Debug",    "phpinfo() — full server/PHP config"),
    ("/phpinfo.php",                HIGH,  "Debug",    "phpinfo() alternate"),
    ("/test.php",                   MED,   "Debug",    "Test PHP file"),
    ("/server-info",                MED,   "Debug",    "Apache server-info"),
    ("/server-status",              MED,   "Debug",    "Apache server-status"),

    # ── API / metadata ─────────────────────────────────────────────────────────
    ("/api/",                       INFO,  "API",      "API root"),
    ("/api/v1/",                    INFO,  "API",      "API v1 root"),
    ("/api/v2/",                    INFO,  "API",      "API v2 root"),
    ("/graphql",                    MED,   "API",      "GraphQL endpoint (introspection risk)"),
    ("/graphiql",                   HIGH,  "API",      "GraphiQL IDE exposed — introspection enabled"),
    ("/swagger",                    MED,   "API",      "Swagger UI — full API schema"),
    ("/swagger-ui.html",            MED,   "API",      "Swagger UI HTML"),
    ("/api-docs",                   MED,   "API",      "API documentation"),
    ("/openapi.json",               MED,   "API",      "OpenAPI spec — full API schema"),
    ("/openapi.yaml",               MED,   "API",      "OpenAPI YAML spec"),
    ("/.well-known/security.txt",   INFO,  "Meta",     "security.txt — responsible disclosure info"),
    ("/robots.txt",                 INFO,  "Meta",     "robots.txt — may reveal hidden paths"),
    ("/sitemap.xml",                INFO,  "Meta",     "Sitemap — full URL inventory"),
    ("/crossdomain.xml",            LOW,   "Meta",     "Flash crossdomain policy"),
    ("/clientaccesspolicy.xml",     LOW,   "Meta",     "Silverlight access policy"),

    # ── Cloud / infra metadata ─────────────────────────────────────────────────
    ("/latest/meta-data/",          CRIT,  "Cloud",    "AWS EC2 metadata endpoint (SSRF pivot)"),
    ("/metadata/v1/",               CRIT,  "Cloud",    "DigitalOcean metadata"),
    ("/.well-known/jwks.json",      LOW,   "Auth",     "JWT key set — useful for token analysis"),
    ("/.well-known/openid-configuration", LOW, "Auth", "OIDC config — auth server details"),

    # ── Source / editor artifacts ──────────────────────────────────────────────
    ("/composer.json",              MED,   "Source",   "PHP composer manifest — dependency list"),
    ("/composer.lock",              MED,   "Source",   "Composer lock — exact versions (CVE hunting)"),
    ("/package.json",               MED,   "Source",   "Node.js package manifest"),
    ("/package-lock.json",          MED,   "Source",   "npm lock file — exact versions"),
    ("/yarn.lock",                  LOW,   "Source",   "Yarn lock file"),
    ("/Gemfile",                    MED,   "Source",   "Ruby Gemfile — dependency list"),
    ("/Gemfile.lock",               MED,   "Source",   "Gemfile lock"),
    ("/requirements.txt",           MED,   "Source",   "Python requirements — library list"),
    ("/go.mod",                     LOW,   "Source",   "Go module file"),
    ("/.DS_Store",                  HIGH,  "Source",   ".DS_Store — macOS file index, reveals paths"),
    ("/Thumbs.db",                  LOW,   "Source",   "Windows Thumbs.db — directory metadata"),
    ("/.viminfo",                   MED,   "Source",   "Vim history — recently edited files"),
    ("/.bash_history",              CRIT,  "Source",   "Bash history — commands run on server"),
    ("/.ssh/id_rsa",                CRIT,  "Source",   "SSH private key"),
    ("/.ssh/authorized_keys",       HIGH,  "Source",   "SSH authorized keys"),
    ("/id_rsa",                     CRIT,  "Source",   "SSH private key in web root"),
]

# Status codes that mean "found something"
HIT_STATUSES = {200, 201, 204, 206, 301, 302, 307, 308, 401, 403}
# 401/403 = exists but auth-protected — still worth flagging
SOFT_HIT_STATUSES = {401, 403}


@dataclass
class ExposureHit:
    path:        str
    full_url:    str
    status:      int
    severity:    str
    category:    str
    description: str
    size:        int   = 0
    redirect_to: str   = ""
    soft:        bool  = False   # True = 401/403 (exists but blocked)


async def probe_paths(
    base_url:    str,
    session:     ClientSession,
    semaphore:   asyncio.Semaphore,
    concurrency: int = 10,
    timeout:     int = 8,
    custom_headers: Optional[Dict[str, str]] = None,
) -> List[ExposureHit]:
    """
    Fire HEAD (fallback GET) requests for all PROBE_PATHS against base_url.
    Returns only hits (paths that respond with an interesting status code).
    """
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        "Accept":     "*/*",
        **(custom_headers or {}),
    }
    to = ClientTimeout(total=timeout, connect=5)
    hits: List[ExposureHit] = []
    probe_sem = asyncio.Semaphore(concurrency)

    async def probe_one(path: str, severity: str, category: str, desc: str) -> None:
        url = origin + path
        async with probe_sem:
            for method in ("HEAD", "GET"):
                try:
                    async with session.request(
                        method, url,
                        headers=headers,
                        allow_redirects=False,
                        timeout=to,
                        ssl=False,
                    ) as resp:
                        status = resp.status
                        if status not in HIT_STATUSES:
                            return
                        size     = int(resp.headers.get("content-length", 0))
                        redirect = resp.headers.get("location", "")
                        soft     = status in SOFT_HIT_STATUSES
                        hits.append(ExposureHit(
                            path=path, full_url=url, status=status,
                            severity=severity, category=category,
                            description=desc, size=size,
                            redirect_to=redirect, soft=soft,
                        ))
                        logger.info("[EXPOSURE] %d %s  %s", status, severity.upper(), url)
                        return
                except Exception:
                    return   # timeout / connection error — path doesn't exist

    await asyncio.gather(*[
        probe_one(path, sev, cat, desc)
        for path, sev, cat, desc in PROBE_PATHS
    ])

    # Sort by severity
    ORDER = {CRIT: 0, HIGH: 1, MED: 2, LOW: 3, INFO: 4}
    hits.sort(key=lambda h: (ORDER.get(h.severity, 9), h.path))
    return hits