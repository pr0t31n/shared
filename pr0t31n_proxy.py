"""pr0t31n_proxy — shared SOCKS/HTTP proxy support for all pr0t31n tools.

Provides:
  build_proxy_url()       — construct proxy URL from config components
  write_proxychains_conf()— generate per-run proxychains4 config
  proxy_wrap_cmd()        — wrap a subprocess command with proxy support
  proxy_env()             — build HTTP_PROXY/HTTPS_PROXY env dict
  needs_proxychains()     — check if a tool needs proxychains wrapping
  builtin_shcheck()       — built-in security header check (replaces shcheck)
  builtin_whatweb()       — built-in tech fingerprinting (replaces whatweb)
  builtin_webanalyze()    — built-in Wappalyzer-style fingerprinting (replaces webanalyze)

Usage in a tool:
    import sys
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    try:
        import pr0t31n_proxy as _pp
    except ImportError:
        _pp = None
"""

import shutil
from pathlib import Path
from urllib.parse import urlparse


# ── Tool proxy support registry ──────────────────────────────────

TOOL_PROXY = {
    # ── Native SOCKS5 + HTTP proxy support (append flag) ──
    "nuclei":       {"flag": "-proxy",    "socks": True},
    "ffuf":         {"flag": "-x",        "socks": True},
    "gobuster":     {"flag": "--proxy",   "socks": True},
    "feroxbuster":  {"flag": "-p",        "socks": True},
    "katana":       {"flag": "-proxy",    "socks": True},
    "sqlmap":       {"flag": "--proxy",   "socks": True},
    "dalfox":       {"flag": "--proxy",   "socks": True},
    "wpscan":       {"flag": "--proxy",   "socks": True},
    "tlsx":         {"flag": "-proxy",    "socks": True},
    "dirsearch":    {"flag": "--proxy",   "socks": True},
    "commix":       {"flag": "--proxy",   "socks": True},
    "sstimap":      {"flag": "--proxy",   "socks": True},
    "curl":         {"flag": "-x",        "socks": True},
    "httpx":        {"flag": "-proxy",    "socks": True},
    "subfinder":    {"flag": "-proxy",    "socks": True},
    "dnsx":         {"flag": None,        "socks": False},  # DNS tool, no proxy
    "amass":        {"flag": None,        "socks": False},

    # ── HTTP proxy only (no SOCKS — wrap with proxychains for SOCKS) ──
    "nikto":        {"flag": "-useproxy", "socks": False, "http_flag": "-useproxy"},
    "whatweb":      {"flag": "--proxy",   "socks": False, "http_flag": "--proxy"},
    "shcheck":      {"flag": "--proxy",   "socks": False, "http_flag": "--proxy"},
    "testssl.sh":   {"flag": "--proxy",   "socks": False, "http_flag": "--proxy"},
    "testssl":      {"flag": "--proxy",   "socks": False, "http_flag": "--proxy"},
    "kiterunner":   {"flag": "--proxy",   "socks": False, "http_flag": "--proxy"},
    "kr":           {"flag": "--proxy",   "socks": False, "http_flag": "--proxy"},

    # ── No proxy support at all (always proxychains) ──
    "sslscan":      {"flag": None, "socks": False},
    "webanalyze":   {"flag": None, "socks": False},
    "shortscan":    {"flag": None, "socks": False},
    "toxicache":    {"flag": None, "socks": False},

    # ── Environment variable proxy (Python tools using requests) ──
    "arjun":        {"env": True, "socks": True},
    "jwt_tool":     {"env": True, "socks": True},
    "paramspider":  {"env": True, "socks": True},

    # ── Special handling ──
    "mitmdump":     {"special": "mitmdump"},
    "mitmproxy":    {"special": "mitmdump"},
    "zap.sh":       {"special": "zap"},

    # ── Offline / N/A — no network traffic ──
    "searchsploit": {"offline": True},
    "dig":          {"offline": True},
    "wc":           {"offline": True},
    "grep":         {"offline": True},
    "awk":          {"offline": True},
    "sed":          {"offline": True},
    "python3":      {"offline": True},
    "python":       {"offline": True},
}

# Tools that should be replaced with built-in Python when SOCKS proxy is active
BUILTIN_REPLACEMENTS = {"shcheck", "whatweb", "webanalyze"}


def build_proxy_url(proxy_addr, proxy_type="http", dns_over_proxy=False):
    """Build a full proxy URL from config components.

    Args:
        proxy_addr: "host:port" or "scheme://host:port" (scheme stripped + rebuilt)
        proxy_type: "http" | "https" | "socks4" | "socks5"
        dns_over_proxy: if True and socks5, use socks5h:// scheme

    Returns:
        Full URL like "socks5h://192.168.1.1:1080" or "" if no proxy
    """
    if not proxy_addr:
        return ""
    addr = proxy_addr.strip()
    for pfx in ("socks5h://", "socks5://", "socks4a://", "socks4://",
                "https://", "http://"):
        if addr.lower().startswith(pfx):
            addr = addr[len(pfx):]
            break
    addr = addr.rstrip("/")
    if not addr:
        return ""

    scheme_map = {
        "socks5": "socks5h" if dns_over_proxy else "socks5",
        "socks4": "socks4a" if dns_over_proxy else "socks4",
        "https":  "https",
        "http":   "http",
    }
    scheme = scheme_map.get(proxy_type, "http")
    return f"{scheme}://{addr}"


def is_socks(proxy_url):
    """Check if a proxy URL is SOCKS (not HTTP)."""
    if not proxy_url:
        return False
    return proxy_url.startswith(("socks5://", "socks5h://",
                                 "socks4://", "socks4a://"))


def _tool_name_from_cmd(cmd):
    """Extract tool name from a command list."""
    if not cmd:
        return None
    binary = Path(cmd[0]).name
    if binary in ("env", "sudo"):
        for c in cmd[1:]:
            if not c.startswith("-"):
                return Path(c).name
    return binary


def _tool_info(tool_name):
    """Look up tool proxy support info."""
    if not tool_name:
        return None
    name = Path(tool_name).name
    info = TOOL_PROXY.get(name)
    if info:
        return info
    stem = Path(name).stem
    return TOOL_PROXY.get(stem)


def needs_proxychains(tool_name, proxy_url):
    """Returns True if this tool needs proxychains4 wrapping for the given proxy."""
    if not proxy_url:
        return False
    info = _tool_info(tool_name)
    if not info:
        return is_socks(proxy_url)
    if info.get("offline") or info.get("special"):
        return False
    if info.get("env"):
        return False
    if is_socks(proxy_url) and not info.get("socks"):
        return True
    if not is_socks(proxy_url) and info.get("flag") is None:
        return True
    return False


def write_proxychains_conf(proxy_url, run_dir, dns_over_proxy=True):
    """Write a proxychains4.conf for wrapping tools that need it.

    Args:
        proxy_url: full URL like "socks5h://host:port"
        run_dir: directory to write the conf in
        dns_over_proxy: whether to add proxy_dns directive

    Returns:
        Path to the written conf file
    """
    if not proxy_url:
        return None

    parsed = urlparse(proxy_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 1080

    scheme = parsed.scheme.lower()
    pc_type_map = {
        "socks5h": "socks5", "socks5": "socks5",
        "socks4a": "socks4", "socks4": "socks4",
        "http": "http", "https": "http",
    }
    pc_type = pc_type_map.get(scheme, "socks5")

    lines = [
        "# Auto-generated by pr0t31n_proxy for this scan run",
        "strict_chain",
        "quiet_mode",
        "",
    ]
    if dns_over_proxy or scheme in ("socks5h", "socks4a"):
        lines.append("proxy_dns")
    lines.extend([
        "",
        "[ProxyList]",
        f"{pc_type} {host} {port}",
    ])
    username = parsed.username
    password = parsed.password
    if username:
        lines[-1] += f" {username}"
        if password:
            lines[-1] += f" {password}"
    lines.append("")

    conf_path = Path(run_dir) / "proxychains4.conf"
    conf_path.write_text("\n".join(lines))
    return conf_path


def proxy_wrap_cmd(cmd, proxy_url, tool_name=None, proxychains_conf=None):
    """Wrap a subprocess command with proxy support.

    Strategy:
      1. No proxy → return cmd unchanged
      2. Tool has native support → append proxy flag
      3. Tool is HTTP-only and proxy is SOCKS → proxychains4 wrap
      4. Tool has no proxy support → proxychains4 wrap
      5. Tool uses env vars → return cmd unchanged (use proxy_env() for env)
      6. Offline tools → return cmd unchanged

    Args:
        cmd: command list (list of strings)
        proxy_url: full proxy URL or ""
        tool_name: override tool detection (otherwise extracted from cmd[0])
        proxychains_conf: path to proxychains4.conf for wrapping

    Returns:
        Modified command list
    """
    if not proxy_url or not cmd:
        return list(cmd)

    name = tool_name or _tool_name_from_cmd(cmd)
    info = _tool_info(name)

    if not info:
        if proxychains_conf and is_socks(proxy_url):
            pc = shutil.which("proxychains4") or shutil.which("proxychains")
            if pc:
                return [pc, "-q", "-f", str(proxychains_conf)] + list(cmd)
        return list(cmd)

    if info.get("offline") or info.get("special"):
        return list(cmd)

    if info.get("env"):
        return list(cmd)

    result = list(cmd)

    if is_socks(proxy_url):
        if info.get("socks") and info.get("flag"):
            result.extend([info["flag"], proxy_url])
        elif proxychains_conf:
            pc = shutil.which("proxychains4") or shutil.which("proxychains")
            if pc:
                result = [pc, "-q", "-f", str(proxychains_conf)] + result
            elif info.get("http_flag"):
                pass
    else:
        flag = info.get("flag") or info.get("http_flag")
        if flag:
            result.extend([flag, proxy_url])
        elif proxychains_conf:
            pc = shutil.which("proxychains4") or shutil.which("proxychains")
            if pc:
                result = [pc, "-q", "-f", str(proxychains_conf)] + result

    return result


def proxy_env(proxy_url):
    """Build environment variables dict for tools that use HTTP_PROXY.

    Returns a dict to merge into os.environ for subprocess calls.
    """
    if not proxy_url:
        return {}
    return {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "ALL_PROXY": proxy_url,
    }


def mitmdump_proxy_args(proxy_url):
    """Build mitmdump arguments to chain through an upstream proxy.

    Returns a list of extra args to append to the mitmdump command,
    or an empty list if no proxy.
    """
    if not proxy_url:
        return []
    return ["--mode", f"upstream:{proxy_url}"]


# ── Built-in replacements for tools that cannot proxy ────────────

_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "present": "HSTS enabled",
        "missing": "Missing HSTS header — browsers will not enforce HTTPS",
    },
    "Content-Security-Policy": {
        "present": "CSP configured",
        "missing": "Missing Content-Security-Policy header",
    },
    "X-Frame-Options": {
        "present": "Clickjacking protection via X-Frame-Options",
        "missing": "Missing X-Frame-Options — vulnerable to clickjacking",
    },
    "X-Content-Type-Options": {
        "present": "MIME sniffing prevention enabled",
        "missing": "Missing X-Content-Type-Options: nosniff",
    },
    "X-XSS-Protection": {
        "present": "Legacy XSS filter enabled",
        "missing": "Missing X-XSS-Protection (legacy but expected)",
    },
    "Referrer-Policy": {
        "present": "Referrer-Policy configured",
        "missing": "Missing Referrer-Policy header",
    },
    "Permissions-Policy": {
        "present": "Permissions-Policy configured",
        "missing": "Missing Permissions-Policy header",
    },
    "Cross-Origin-Opener-Policy": {
        "present": "COOP configured",
        "missing": "Missing Cross-Origin-Opener-Policy",
    },
    "Cross-Origin-Resource-Policy": {
        "present": "CORP configured",
        "missing": "Missing Cross-Origin-Resource-Policy",
    },
    "Cross-Origin-Embedder-Policy": {
        "present": "COEP configured",
        "missing": "Missing Cross-Origin-Embedder-Policy",
    },
    "Cache-Control": {
        "present": "Cache-Control configured",
        "missing": "Missing Cache-Control header — responses may be cached",
    },
}

_DANGEROUS_HEADERS = {
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Drupal-Dynamic-Cache",
}

_WAPPALYZER_PATTERNS = {
    "X-Powered-By": {
        "Express": ("Express.js (Node.js)", "JavaScript framework"),
        "PHP": ("PHP", "Server-side language"),
        "ASP.NET": ("ASP.NET", "Web framework"),
        "Servlet": ("Java Servlet", "Java web framework"),
        "Django": ("Django", "Python framework"),
        "Flask": ("Flask", "Python framework"),
        "Rails": ("Ruby on Rails", "Ruby framework"),
        "Next.js": ("Next.js", "React framework"),
    },
    "Server": {
        "nginx": ("Nginx", "Web server"),
        "Apache": ("Apache HTTP Server", "Web server"),
        "Microsoft-IIS": ("Microsoft IIS", "Web server"),
        "LiteSpeed": ("LiteSpeed", "Web server"),
        "Caddy": ("Caddy", "Web server"),
        "gunicorn": ("Gunicorn", "Python WSGI server"),
        "uvicorn": ("Uvicorn", "Python ASGI server"),
        "Kestrel": ("Kestrel", "ASP.NET Core server"),
        "openresty": ("OpenResty", "Nginx + Lua"),
        "Tomcat": ("Apache Tomcat", "Java application server"),
        "Jetty": ("Eclipse Jetty", "Java HTTP server"),
        "CloudFront": ("Amazon CloudFront", "CDN"),
        "cloudflare": ("Cloudflare", "CDN / WAF"),
        "AkamaiGHost": ("Akamai", "CDN"),
    },
    "X-Generator": {
        "WordPress": ("WordPress", "CMS"),
        "Drupal": ("Drupal", "CMS"),
        "Joomla": ("Joomla", "CMS"),
    },
}


def builtin_shcheck(url, session=None):
    """Built-in security header check — replaces the external shcheck tool.

    Args:
        url: target URL
        session: requests.Session with proxy already configured

    Returns:
        dict with keys: url, present (list), missing (list), dangerous (list),
                        raw_headers (dict)
    """
    import requests
    sess = session or requests.Session()
    try:
        r = sess.get(url, timeout=15, verify=False, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e), "present": [], "missing": [],
                "dangerous": [], "raw_headers": {}}

    headers = {k.lower(): v for k, v in r.headers.items()}
    present, missing, dangerous = [], [], []

    for hdr, info in _SECURITY_HEADERS.items():
        if hdr.lower() in headers:
            present.append({"header": hdr, "value": headers[hdr.lower()],
                           "note": info["present"]})
        else:
            missing.append({"header": hdr, "note": info["missing"]})

    for hdr in _DANGEROUS_HEADERS:
        if hdr.lower() in headers:
            dangerous.append({"header": hdr, "value": headers[hdr.lower()],
                             "note": f"Information disclosure via {hdr}"})

    return {
        "url": url, "status_code": r.status_code,
        "present": present, "missing": missing, "dangerous": dangerous,
        "raw_headers": dict(r.headers),
    }


def builtin_whatweb(url, session=None):
    """Built-in technology fingerprinter — replaces the external whatweb tool.

    Checks response headers and body for technology signatures.

    Args:
        url: target URL
        session: requests.Session with proxy already configured

    Returns:
        dict with keys: url, technologies (list of dicts), headers (dict)
    """
    import requests
    sess = session or requests.Session()
    try:
        r = sess.get(url, timeout=15, verify=False, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e), "technologies": []}

    techs = []
    headers = {k: v for k, v in r.headers.items()}

    for hdr, patterns in _WAPPALYZER_PATTERNS.items():
        val = headers.get(hdr, "")
        for pattern, (name, category) in patterns.items():
            if pattern.lower() in val.lower():
                techs.append({"name": name, "category": category,
                             "source": f"{hdr}: {val}"})

    body = r.text[:50000] if r.text else ""

    body_sigs = [
        ("wp-content/", "WordPress", "CMS"),
        ("wp-includes/", "WordPress", "CMS"),
        ("/sites/default/files/", "Drupal", "CMS"),
        ("Joomla!", "Joomla", "CMS"),
        ("_next/static/", "Next.js", "JavaScript framework"),
        ("__nuxt", "Nuxt.js", "JavaScript framework"),
        ("ng-version=", "Angular", "JavaScript framework"),
        ("data-reactroot", "React", "JavaScript library"),
        ("__REACT_DEVTOOLS", "React", "JavaScript library"),
        ("vue.js", "Vue.js", "JavaScript framework"),
        ("ember-view", "Ember.js", "JavaScript framework"),
        ("window.__GATSBY", "Gatsby", "Static site generator"),
        ("woocommerce", "WooCommerce", "eCommerce"),
        ("Shopify.theme", "Shopify", "eCommerce"),
        ("magento", "Magento", "eCommerce"),
        ("laravel_session", "Laravel", "PHP framework"),
        ("csrfmiddlewaretoken", "Django", "Python framework"),
        ("Telerik.Web.UI", "Telerik UI", ".NET component library"),
        ("swagger-ui", "Swagger UI", "API documentation"),
        ("redoc", "ReDoc", "API documentation"),
    ]
    for sig, name, category in body_sigs:
        if sig.lower() in body.lower():
            if not any(t["name"] == name for t in techs):
                techs.append({"name": name, "category": category,
                             "source": f"Body pattern: {sig}"})

    cookies = {c.name: c.value for c in r.cookies}
    cookie_sigs = [
        ("PHPSESSID", "PHP", "Server-side language"),
        ("JSESSIONID", "Java Servlet", "Java web framework"),
        ("ASP.NET_SessionId", "ASP.NET", "Web framework"),
        ("csrftoken", "Django", "Python framework"),
        ("laravel_session", "Laravel", "PHP framework"),
        ("connect.sid", "Express.js", "Node.js framework"),
        ("rack.session", "Ruby / Rack", "Ruby web framework"),
    ]
    for cookie_name, name, category in cookie_sigs:
        if cookie_name in cookies:
            if not any(t["name"] == name for t in techs):
                techs.append({"name": name, "category": category,
                             "source": f"Cookie: {cookie_name}"})

    return {"url": url, "status_code": r.status_code,
            "technologies": techs, "headers": headers}


def builtin_webanalyze(url, session=None):
    """Built-in Wappalyzer-style fingerprinting — replaces webanalyze.

    This is an alias for builtin_whatweb with the same interface.
    """
    return builtin_whatweb(url, session=session)
