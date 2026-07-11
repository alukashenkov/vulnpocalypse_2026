"""Shared plumbing for the dashboard site: config, the one-per-run archive
download, and the static-HTML site builders.

No ``tqdm`` and no hard ``python-dotenv`` dependency — configuration is read from
environment variables (``DATA_DIR``, ``VULNERS_API_KEY``, ``SITE_DIR``); a local
``.env`` is loaded only as a convenience if ``python-dotenv`` happens to be
installed. This keeps the published dependency list minimal and makes CI runs
depend on nothing but the injected secret + env.
"""
import html
import os
import sys
import time
import zlib
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

ARCHIVE_BASENAME = "vulners_archive_cve.json"
COLLECTION_URL = "https://vulners.com/api/v4/archive/collection/"


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def load_local_env():
    """Load a local ``.env`` if ``python-dotenv`` is available. No-op otherwise.

    CI relies on real environment variables, so dotenv is purely a local-dev
    nicety and is never a required dependency.
    """
    try:
        from dotenv import load_dotenv, find_dotenv  # type: ignore
    except ImportError:
        return
    env_file = find_dotenv(usecwd=True)
    if env_file:
        load_dotenv(env_file)
        print(f"Loaded local .env from {os.path.abspath(env_file)}")


def get_api_key():
    key = os.getenv("VULNERS_API_KEY")
    if not key:
        print("Error: VULNERS_API_KEY is not set (env var or local .env).")
        sys.exit(1)
    return key


def get_data_dir():
    return os.path.abspath(os.getenv("DATA_DIR") or os.getcwd())


def get_site_dir():
    return os.path.abspath(os.getenv("SITE_DIR") or os.path.join(os.getcwd(), "site"))


# --------------------------------------------------------------------------- #
# Archive download (single snapshot; no incremental merge machinery)
# --------------------------------------------------------------------------- #
def _is_json_file_complete(path):
    """Cheap completeness check: last non-whitespace byte is ``]``/``}``."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return False
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            read = min(size, 1024)
            f.seek(size - read)
            chunk = f.read(read).decode("utf-8", errors="ignore").strip()
        return bool(chunk) and chunk[-1] in ("]", "}")
    except (OSError, ValueError):
        return False


def _modified_today(path):
    try:
        mtime = datetime.fromtimestamp(os.path.getmtime(path))
        return mtime.date() == datetime.now().date()
    except OSError:
        return False


def _robust_session():
    session = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def download_archive_once():
    """Ensure a fresh ``cve`` archive exists in ``DATA_DIR`` and return its path.

    Fetches the full ``archive/collection`` snapshot in a single streaming,
    gzip-decompressed GET — no ``collection-update`` deltas, no SQLite, no merge.
    On an empty CI runner this always downloads; locally, an already-complete
    archive modified today is reused instead of re-downloading.
    """
    data_dir = get_data_dir()
    os.makedirs(data_dir, exist_ok=True)
    path = os.path.join(data_dir, ARCHIVE_BASENAME)

    if _is_json_file_complete(path) and _modified_today(path):
        print(f"Reusing existing archive (fresh today): {path}")
        return path

    if os.path.exists(path) and not _is_json_file_complete(path):
        print(f"Existing archive at {path} is incomplete; re-downloading.")
        os.remove(path)

    api_key = get_api_key()
    headers = {"X-Api-Key": api_key, "Accept-Encoding": "gzip"}
    params = {"type": "cve"}

    print(f"Downloading cve collection snapshot to {path} ...")
    start = time.time()
    session = _robust_session()
    try:
        with session.get(
            COLLECTION_URL, params=params, headers=headers, stream=True, timeout=(10, 300)
        ) as r:
            r.raise_for_status()
            decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
            with open(path, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(decompressor.decompress(chunk))
                f.write(decompressor.flush())
    finally:
        session.close()

    if not _is_json_file_complete(path):
        print("Error: downloaded archive failed the completeness check.")
        sys.exit(1)

    size_gb = os.path.getsize(path) / (1024 ** 3)
    print(f"Downloaded archive ({size_gb:.2f} GB) in {time.time() - start:.1f}s.")
    return path


# --------------------------------------------------------------------------- #
# Site builders (plain HTML strings — no templating dependency)
# --------------------------------------------------------------------------- #
_PAGE_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
.wrap { max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
header h1 { margin: 0 0 .25rem; font-size: 1.9rem; }
.meta { color: #888; font-size: .9rem; margin-bottom: 2rem; }
section { margin: 0 0 3rem; }
section h2 { font-size: 1.4rem; margin: 0 0 .5rem; border-bottom: 1px solid rgba(128,128,128,.3); padding-bottom: .35rem; }
.blurb { color: inherit; opacity: .85; margin: .5rem 0 1.25rem; }
.intro { font-size: 1.12rem; line-height: 1.7; opacity: .92; margin: .5rem 0 2rem; }
figure { margin: 0 0 2.5rem; }
figcaption { margin-top: .75rem; opacity: .82; line-height: 1.6; }
img { max-width: 100%; height: auto; border: 1px solid rgba(128,128,128,.2); border-radius: 6px; }
a { color: #3b82f6; }
pre { overflow-x: auto; padding: 1rem; border: 1px solid rgba(128,128,128,.3); border-radius: 6px; background: rgba(128,128,128,.08); font-size: 12.5px; line-height: 1.45; }
footer { margin-top: 3rem; color: #888; font-size: .85rem; border-top: 1px solid rgba(128,128,128,.3); padding-top: 1rem; }
"""


def _html_page(title, body):
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>{html.escape(title)}</title>\n"
        f"<style>{_PAGE_CSS}</style>\n</head>\n<body>\n<div class=\"wrap\">\n"
        f"{body}\n</div>\n</body>\n</html>\n"
    )


def build_site(results, out_dir):
    """Write ``index.html`` and ``tables.html`` into ``out_dir`` from the results.

    ``index.html`` stays light: per dashboard a blurb + its charts, with a link
    into ``tables.html`` where the full aligned-table report lives verbatim in a
    ``<pre>``. Each report is also written as a downloadable ``report_<slug>.txt``.
    """
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # index.html
    index_sections = []
    for r in results:
        figures = []
        for c in r.charts:
            caption = c.get("caption", "")
            cap_html = (
                f"<figcaption>{html.escape(caption)}</figcaption>" if caption else ""
            )
            figures.append(
                f'  <figure><img src="{html.escape(os.path.basename(c["file"]))}" '
                f'alt="{html.escape(r.title)} chart">{cap_html}</figure>'
            )
        index_sections.append(
            f'<section id="{html.escape(r.slug)}">\n'
            f"  <h2>{html.escape(r.title)}</h2>\n"
            f'  <p class="intro">{html.escape(r.blurb)}</p>\n'
            + "\n".join(figures)
            + f'\n  <p><a href="tables.html#{html.escape(r.slug)}">View the full data tables &rarr;</a></p>\n'
            f"</section>"
        )
    index_body = (
        "<header>\n"
        "  <h1>Vulnpocalypse 2026 Statistics Dashboard</h1>\n"
        f'  <p class="meta">Updated {generated} &middot; data from '
        '<a href="https://vulners.com">Vulners</a></p>\n'
        "</header>\n"
        + "\n".join(index_sections)
        + '\n<footer>Rebuilt daily by GitHub Actions. '
        '<a href="tables.html">All data tables</a>.</footer>'
    )

    # tables.html
    table_sections = []
    for r in results:
        txt_name = f"report_{r.slug}.txt"
        with open(os.path.join(out_dir, txt_name), "w", encoding="utf-8") as f:
            f.write(r.report_text)
        table_sections.append(
            f'<section id="{html.escape(r.slug)}">\n'
            f"  <h2>{html.escape(r.title)}</h2>\n"
            f'  <p class="blurb"><a href="{txt_name}">Download as plain text</a></p>\n'
            f"  <pre>{html.escape(r.report_text)}</pre>\n"
            f"</section>"
        )
    tables_body = (
        "<header>\n"
        "  <h1>Data Tables</h1>\n"
        f'  <p class="meta">Updated {generated} &middot; '
        '<a href="index.html">&larr; back to charts</a></p>\n'
        "</header>\n"
        + "\n".join(table_sections)
    )

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(_html_page("Vulnpocalypse 2026 Statistics Dashboard", index_body))
    with open(os.path.join(out_dir, "tables.html"), "w", encoding="utf-8") as f:
        f.write(_html_page("Vulnpocalypse 2026 — Data Tables", tables_body))

    print(f"Wrote index.html + tables.html to {out_dir}")
