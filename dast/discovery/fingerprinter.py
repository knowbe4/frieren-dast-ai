"""
Tech stack fingerprinter — zero extra requests.

Primary: Wappalyzer (wappalyzer>=2.0.0) — ~3000 technology signatures, runs
offline against proxy-captured response data (url + headers + html body).

Fallback: manual regex rules for DB errors, ORM traces, WAF headers, CDN
markers and anything Wappalyzer's categories don't expose directly.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Dict, List, Optional

from dast.discovery.models import TechStack
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry

logger = get_logger(__name__)

# ── Wappalyzer category → TechStack field mapping ─────────────────────────

_WAPP_FRAMEWORK_CATS = {
    "Web frameworks", "JavaScript frameworks", "Web application frameworks",
}
_WAPP_LANG_CATS = {"Programming languages"}
_WAPP_DB_CATS = {"Databases", "NoSQL databases", "Search engines"}
_WAPP_CMS_CATS = {"CMS", "Blogs", "Ecommerce"}
_WAPP_TEMPLATE_CATS = {"Templating engines", "UI frameworks"}
_WAPP_WAF_CATS = {"Security", "CDN"}
_WAPP_SERVER_CATS = {"Web servers", "Reverse proxies"}

# Technologies whose categories aren't reliable for our purposes — skip
_WAPP_SKIP = {"jQuery", "Bootstrap", "Font Awesome", "Google Analytics", "Google Tag Manager"}


def _run_wappalyzer(entry: "ProxyEntry") -> Dict[str, dict]:
    """
    Run Wappalyzer in fast (offline) mode against proxy-captured data.
    Returns the raw {tech_name: {categories, confidence, version}} dict,
    or {} on any error (missing package, parse failure, etc.).
    """
    try:
        from wappalyzer.core.analyzer import analyze_from_response

        class _Resp:
            url = entry.url
            text = (entry.response_body or b"").decode("utf-8", errors="replace")[:65536]
            headers = {k.lower(): v for k, v in entry.response_headers.items()}
            cookies = type("_C", (), {"get_dict": lambda self: {}})()

        return analyze_from_response(_Resp(), "fast") or {}
    except Exception as exc:
        logger.debug("Wappalyzer fingerprint failed", error=str(exc))
        return {}


def _wappalyzer_to_techstack(wapp: Dict[str, dict]) -> Optional[TechStack]:
    """Translate Wappalyzer result dict into a TechStack."""
    if not wapp:
        return None

    framework: Optional[str] = None
    language: Optional[str] = None
    template_engine: Optional[str] = None
    cms: Optional[str] = None
    db_hints: List[str] = []
    waf_hints: List[str] = []
    server: Optional[str] = None

    for name, data in wapp.items():
        if name in _WAPP_SKIP:
            continue
        cats = set(data.get("categories", []))
        conf = data.get("confidence", 0)
        if conf < 50:
            continue

        if cats & _WAPP_CMS_CATS:
            if cms is None:
                cms = name
        elif cats & _WAPP_TEMPLATE_CATS:
            if template_engine is None:
                template_engine = name
        elif cats & _WAPP_FRAMEWORK_CATS:
            if framework is None:
                framework = name
        elif cats & _WAPP_LANG_CATS:
            if language is None:
                language = name
        elif cats & _WAPP_DB_CATS:
            if name not in db_hints:
                db_hints.append(name)
        elif cats & _WAPP_WAF_CATS:
            if name not in waf_hints:
                waf_hints.append(name)
        elif cats & _WAPP_SERVER_CATS:
            if server is None:
                server = name

    if not any([framework, language, template_engine, cms, db_hints, waf_hints, server]):
        return None

    return TechStack(
        framework=framework,
        language=language,
        server=server,
        template_engine=template_engine,
        cms=cms,
        database_hints=db_hints,
        waf_hints=waf_hints,
    )


# ── framework detection rules ──────────────────────────────────────────────
# Each entry: (pattern, framework, language)
# Checked against: headers dict (lowercased) + first 4KB of response body

_FRAMEWORK_RULES: List[tuple] = [
    # Header-based
    (re.compile(r"x-powered-by:\s*express", re.I),       "Express",    "JavaScript"),
    (re.compile(r"x-powered-by:\s*php",     re.I),       "PHP",        "PHP"),
    (re.compile(r"x-powered-by:\s*asp\.net",re.I),       "ASP.NET",    "C#"),
    (re.compile(r"x-powered-by:\s*next\.js",re.I),       "Next.js",    "JavaScript"),
    (re.compile(r"x-generator:\s*gatsby",   re.I),       "Gatsby",     "JavaScript"),

    # Django
    (re.compile(r"csrfmiddlewaretoken", re.I),            "Django",     "Python"),
    (re.compile(r"django\.core\.exceptions", re.I),       "Django",     "Python"),
    (re.compile(r"wsgi\.errors", re.I),                   "Django",     "Python"),

    # Flask
    (re.compile(r"werkzeug", re.I),                       "Flask",      "Python"),
    (re.compile(r"flask\.debugger", re.I),                "Flask",      "Python"),

    # FastAPI / Starlette
    (re.compile(r"fastapi", re.I),                        "FastAPI",    "Python"),
    (re.compile(r"starlette", re.I),                      "FastAPI",    "Python"),

    # Rails
    (re.compile(r"x-runtime:\s*[\d.]+",     re.I),       "Rails",      "Ruby"),
    (re.compile(r"activerecord", re.I),                   "Rails",      "Ruby"),
    (re.compile(r"actioncontroller", re.I),               "Rails",      "Ruby"),
    (re.compile(r"rails.*error", re.I),                   "Rails",      "Ruby"),

    # Spring / Java
    (re.compile(r"x-application-context", re.I),          "Spring",     "Java"),
    (re.compile(r"org\.springframework",   re.I),          "Spring",     "Java"),
    (re.compile(r"java\.lang\.",           re.I),          "Spring",     "Java"),
    (re.compile(r"javax\.servlet",        re.I),           "Spring",     "Java"),
    (re.compile(r"org\.hibernate",        re.I),           "Spring",     "Java"),

    # Laravel
    (re.compile(r"laravel_session",       re.I),           "Laravel",    "PHP"),
    (re.compile(r"illuminate\\",          re.I),           "Laravel",    "PHP"),

    # NestJS
    (re.compile(r"nest(js|application)", re.I),            "NestJS",     "JavaScript"),

    # Express (body fallback)
    (re.compile(r"cannot (get|post) /",   re.I),           "Express",    "JavaScript"),

    # ASP.NET
    (re.compile(r"__viewstate",           re.I),           "ASP.NET",    "C#"),
    (re.compile(r"aspnetcore",            re.I),           "ASP.NET Core","C#"),

    # Go
    (re.compile(r"gorilla/mux",           re.I),           "Gorilla Mux","Go"),
    (re.compile(r"gin-gonic",             re.I),           "Gin",        "Go"),
    (re.compile(r"fiber/v\d",             re.I),           "Fiber",      "Go"),

    # Rust
    (re.compile(r"actix-web",             re.I),           "Actix",      "Rust"),
    (re.compile(r"x-powered-by:\s*axum",  re.I),           "Axum",       "Rust"),

    # Elixir / Phoenix
    (re.compile(r"x-powered-by:\s*phx|phoenix.*framework", re.I), "Phoenix", "Elixir"),

    # Symfony
    (re.compile(r"x-debug-token|x-symfony-profiler", re.I), "Symfony",  "PHP"),

    # Nuxt / Vue SSR
    (re.compile(r"x-powered-by:\s*nuxt",  re.I),           "Nuxt",       "JavaScript"),
    (re.compile(r"__nuxt",                re.I),           "Nuxt",       "JavaScript"),

    # Remix / Next fallback
    (re.compile(r"__remix",               re.I),           "Remix",      "JavaScript"),

    # Quarkus / Micronaut
    (re.compile(r"quarkus",               re.I),           "Quarkus",    "Java"),
    (re.compile(r"micronaut",             re.I),           "Micronaut",  "Java"),
]

# Template engine detection rules — (pattern, engine_name)
_TEMPLATE_RULES: List[tuple] = [
    # Jinja2 / Nunjucks (Python / JS)
    (re.compile(r"\{\{[^}]+\}\}|{%-?\s*(block|extends|include|for|if)\b", re.I), "Jinja2/Nunjucks"),
    # Twig (PHP)
    (re.compile(r"\{%-?\s*(block|extends|include|for|if)\b.*%\}", re.I), "Twig"),
    # Handlebars / Mustache
    (re.compile(r"\{\{[#/^>!]", re.I), "Handlebars/Mustache"),
    # Thymeleaf (Java)
    (re.compile(r'th:(text|if|each|attr|href|src|action)\s*=', re.I), "Thymeleaf"),
    # FreeMarker (Java)
    (re.compile(r"<#(if|list|include|macro|assign)\b", re.I), "FreeMarker"),
    # Velocity (Java)
    (re.compile(r"#(set|if|foreach|include|parse|macro)\s*\(", re.I), "Velocity"),
    # Smarty (PHP)
    (re.compile(r"\{literal\}|\{section\s+name=|\{foreach\s+from=", re.I), "Smarty"),
    # ERB (Ruby)
    (re.compile(r"<%=?\s*.+?\s*%>", re.I), "ERB"),
    # Razor (ASP.NET)
    (re.compile(r"@(Html\.|Url\.|Model\.|ViewBag\.|RenderSection\()", re.I), "Razor"),
    # Pug / Jade (Node)
    (re.compile(r"doctype html\s*\nhtml\(", re.I), "Pug"),
    # JSP
    (re.compile(r"<%@\s*(page|taglib|include)\b|<jsp:", re.I), "JSP"),
]

# CMS detection rules — (pattern, cms_name)
_CMS_RULES: List[tuple] = [
    (re.compile(r"wp-content|wp-includes|wordpress|wp-json", re.I), "WordPress"),
    (re.compile(r"drupal|sites/default/files|drupal\.settings", re.I), "Drupal"),
    (re.compile(r"joomla|/components/com_|option=com_", re.I), "Joomla"),
    (re.compile(r"x-shopify-shop|shopify\.com/s/files|cdn\.shopify", re.I), "Shopify"),
    (re.compile(r"typo3|t3lib_|typolink", re.I), "TYPO3"),
    (re.compile(r"ghost/api|ghost-url", re.I), "Ghost"),
    (re.compile(r"x-magento|mage-|magento", re.I), "Magento"),
    (re.compile(r"contentful|content\.contentful\.com", re.I), "Contentful"),
    (re.compile(r"strapi|x-powered-by:\s*strapi", re.I), "Strapi"),
    (re.compile(r"sitecore|/-/media/|/-/jssmedia/", re.I), "Sitecore"),
    (re.compile(r"kentico|~/kentico/", re.I), "Kentico"),
    (re.compile(r"x-confluence-request-time|atlassian\.net", re.I), "Confluence"),
]

_SERVER_RE = re.compile(r"^(nginx|apache|iis|caddy|gunicorn|uvicorn|jetty|tomcat)[/\s]?[\d.]*", re.I)

_DB_HINTS: List[tuple] = [
    (re.compile(r"postgresql|pg_query|pgsql", re.I),    "PostgreSQL"),
    (re.compile(r"mysql|MariaDB",              re.I),    "MySQL"),
    (re.compile(r"sqlite",                     re.I),    "SQLite"),
    (re.compile(r"microsoft sql server|mssql|sqlserver", re.I), "MSSQL"),
    (re.compile(r"oracle.*ora-\d{5}",          re.I),    "Oracle"),
    (re.compile(r"mongodb|mongoose",           re.I),    "MongoDB"),
    (re.compile(r"redis",                      re.I),    "Redis"),
    (re.compile(r"elasticsearch",              re.I),    "Elasticsearch"),
    (re.compile(r"cassandra",                  re.I),    "Cassandra"),
]

_ORM_HINTS: List[tuple] = [
    (re.compile(r"sqlalchemy",    re.I),  "SQLAlchemy"),
    (re.compile(r"activerecord",  re.I),  "ActiveRecord"),
    (re.compile(r"hibernate",     re.I),  "Hibernate"),
    (re.compile(r"typeorm",       re.I),  "TypeORM"),
    (re.compile(r"sequelize",     re.I),  "Sequelize"),
    (re.compile(r"prisma",        re.I),  "Prisma"),
    (re.compile(r"gorm",          re.I),  "GORM"),
    (re.compile(r"doctrine",      re.I),  "Doctrine"),
]

_WAF_HINTS: List[tuple] = [
    (re.compile(r"cloudflare",              re.I), "Cloudflare"),
    (re.compile(r"__cf_bm|cf-ray",          re.I), "Cloudflare"),
    (re.compile(r"x-sucuri-id",             re.I), "Sucuri"),
    (re.compile(r"x-amzn-requestid|awselb", re.I), "AWS WAF"),
    (re.compile(r"x-waf-|modsecurity",      re.I), "ModSecurity"),
    (re.compile(r"x-iinfo",                 re.I), "Incapsula"),
    (re.compile(r"x-cdn.*akamai|akamaighost",re.I),"Akamai"),
    (re.compile(r"fortigate|fortiwebcloud", re.I), "FortiWeb"),
]

_CDN_HINTS: List[tuple] = [
    (re.compile(r"cf-ray",                    re.I), "Cloudflare"),
    (re.compile(r"x-fastly",                  re.I), "Fastly"),
    (re.compile(r"x-akamai|akamaighost",      re.I), "Akamai"),
    (re.compile(r"x-amz-cf-id|cloudfront",    re.I), "CloudFront"),
]


def _header_blob(entry: "ProxyEntry") -> str:
    """Flatten all response headers into one searchable string."""
    lines = []
    for k, v in entry.response_headers.items():
        lines.append(f"{k}: {v}")
    return "\n".join(lines)


def _body_snippet(entry: "ProxyEntry") -> str:
    if not entry.response_body:
        return ""
    return entry.response_body[:4096].decode("utf-8", errors="replace")


def fingerprint(entry: "ProxyEntry") -> Optional[TechStack]:
    """
    Return a TechStack for the given entry, or None if nothing detected.
    Called per entry — results are merged into the host-level TechStack by DiscoveryEngine.

    Strategy:
      1. Wappalyzer (offline, fast mode) — ~3000 signatures, primary source
      2. Manual regex rules — fills gaps Wappalyzer misses (ORM traces, WAF
         headers, CDN markers, DB error messages in response body)
      3. Merge both results, preferring Wappalyzer where both fire
    """
    header_blob = _header_blob(entry)
    body = _body_snippet(entry)
    combined = header_blob + "\n" + body

    # ── 1. Wappalyzer ──────────────────────────────────────────────────────
    wapp_result = _run_wappalyzer(entry)
    wapp_stack = _wappalyzer_to_techstack(wapp_result)

    # ── 2. Manual regex rules (complement, not replace) ────────────────────
    framework: Optional[str] = wapp_stack.framework if wapp_stack else None
    language: Optional[str] = wapp_stack.language if wapp_stack else None
    server: Optional[str] = wapp_stack.server if wapp_stack else None
    template_engine: Optional[str] = wapp_stack.template_engine if wapp_stack else None
    cms: Optional[str] = wapp_stack.cms if wapp_stack else None
    db_hints: List[str] = list(wapp_stack.database_hints) if wapp_stack else []
    orm_hints: List[str] = []
    waf_hints: List[str] = list(wapp_stack.waf_hints) if wapp_stack else []
    cdn: Optional[str] = None

    # Framework + language fallback (when Wappalyzer missed it)
    if framework is None:
        for pattern, fw, lang in _FRAMEWORK_RULES:
            if pattern.search(combined):
                framework = fw
                language = lang
                break

    # Server header fallback
    if server is None:
        raw_server = entry.response_headers.get("server", "")
        if raw_server:
            m = _SERVER_RE.match(raw_server.strip())
            if m:
                server = raw_server.strip()[:64]

    # Template engine fallback (body only)
    if template_engine is None:
        for pattern, engine in _TEMPLATE_RULES:
            if pattern.search(body):
                template_engine = engine
                break

    # CMS fallback
    if cms is None:
        for pattern, c in _CMS_RULES:
            if pattern.search(combined):
                cms = c
                break

    # Database hints — manual rules catch error messages Wappalyzer misses
    for pattern, db in _DB_HINTS:
        if pattern.search(combined) and db not in db_hints:
            db_hints.append(db)

    # ORM hints (stack traces — Wappalyzer doesn't cover these)
    for pattern, orm in _ORM_HINTS:
        if pattern.search(combined) and orm not in orm_hints:
            orm_hints.append(orm)

    # WAF hints
    for pattern, waf in _WAF_HINTS:
        if pattern.search(combined) and waf not in waf_hints:
            waf_hints.append(waf)

    # CDN
    for pattern, c in _CDN_HINTS:
        if pattern.search(combined):
            cdn = c
            break

    if not any([framework, server, template_engine, cms, db_hints, orm_hints, waf_hints, cdn]):
        return None

    return TechStack(
        framework=framework,
        language=language,
        server=server,
        template_engine=template_engine,
        cms=cms,
        database_hints=db_hints,
        orm_hints=orm_hints,
        waf_hints=waf_hints,
        cdn=cdn,
    )


def merge_tech_stacks(existing: Optional[TechStack], new: Optional[TechStack]) -> Optional[TechStack]:
    """Merge a new fingerprint result into an existing TechStack (keeps first non-None value)."""
    if new is None:
        return existing
    if existing is None:
        return new

    return TechStack(
        framework=existing.framework or new.framework,
        language=existing.language or new.language,
        server=existing.server or new.server,
        template_engine=existing.template_engine or new.template_engine,
        cms=existing.cms or new.cms,
        database_hints=list({*existing.database_hints, *new.database_hints}),
        orm_hints=list({*existing.orm_hints, *new.orm_hints}),
        waf_hints=list({*existing.waf_hints, *new.waf_hints}),
        cdn=existing.cdn or new.cdn,
        extra={**existing.extra, **new.extra},
    )
