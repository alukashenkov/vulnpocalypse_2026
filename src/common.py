"""Shared plumbing for the dashboard site: config, the one-per-run archive
download, and the static-HTML site builders.

No ``tqdm`` and no hard ``python-dotenv`` dependency — configuration is read from
environment variables (``DATA_DIR``, ``VULNERS_API_KEY``, ``SITE_DIR``); a local
``.env`` is loaded only as a convenience if ``python-dotenv`` happens to be
installed. This keeps the published dependency list minimal and makes CI runs
depend on nothing but the injected secret + env.

``ijson`` (already required to read the archive) and stdlib ``sqlite3`` are
imported lazily, only when ``collection-update`` deltas actually have to be
merged.
"""
import html
import json
import os
import re
import sys
import time
import zlib
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

ARCHIVE_BASENAME = "vulners_archive_cve.json"
COLLECTION_URL = "https://vulners.com/api/v4/archive/collection/"
UPDATE_URL = "https://vulners.com/api/v4/archive/collection-update/"

# Server-enforced: collection-update rejects an `after` earlier than this with a
# 400. An archive further behind than this cannot be patched at all — clamping
# `after` forward would silently drop every update in between, so the only honest
# way to close the gap is a full re-download.
MAX_UPDATE_LOOKBACK = timedelta(hours=25)
# Kept clear of the 25h boundary so a slow run cannot drift across it mid-flight.
UPDATE_LOOKBACK_SAFETY = timedelta(minutes=30)
# Slack applied to a foreign/legacy archive's mtime, to absorb clock skew.
MTIME_WATERMARK_MARGIN = timedelta(hours=1)
# Deltas only carry documents that were modified; nothing tells us about ones the
# publisher dropped. A periodic full snapshot bounds that drift.
MAX_SNAPSHOT_AGE = timedelta(days=7)

# ``<archive>.state.json`` belongs to vuln_data_vulners_archive_downloader.py,
# which keeps its own resume watermark there. Two writers on one path clobbered
# each other's schema once already, so this module writes its own sidecar and
# only ever *reads* the downloader's as a fallback.
SITE_STATE_SUFFIX = ".site-state.json"
DOWNLOADER_STATE_SUFFIX = ".state.json"

# How often the merge reports progress, in documents (no tqdm here).
_MERGE_PROGRESS_EVERY = 100_000


class _DecimalEncoder(json.JSONEncoder):
    """ijson yields JSON numbers as ``Decimal``; re-serialise them as floats."""

    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


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


def _to_dt(value):
    """Parse a Vulners ISO timestamp ('...Z' or '...+00:00') into an aware datetime."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _archive_head_watermark(path):
    """``timestamps.updated`` of the archive's first document.

    Published archives are sorted newest-modified-first, so the head document is
    a freshly-downloaded snapshot's high-water mark and therefore its correct
    resume point — the ``collection-state`` cursor is not: it drifts forward on
    its own while the published file stands still. Only meaningful on a pristine
    download; once deltas are merged the head means nothing.

    Decodes exactly one object with ``raw_decode`` rather than hunting for a
    ``},`` delimiter, which lands inside a nested object on almost every real
    document.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            chunk = f.read(1024 * 1024)
        head, _ = json.JSONDecoder().raw_decode(chunk.lstrip().lstrip("[").lstrip())
    except (OSError, ValueError) as e:
        print(f"Note: could not read archive head ({e}).")
        return None
    return _to_dt((head.get("timestamps") or {}).get("updated") or head.get("modified"))


def _read_state(path, suffix):
    try:
        with open(path + suffix, "r", encoding="utf-8") as f:
            state = json.load(f)
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def _read_watermark(path):
    """What the local archive is known to be complete through: ``(dt|None, source)``.

    This has to be recorded locally rather than recovered from either end: after
    a merge the archive is no longer sorted newest-first (updated documents stay
    put, new ones are appended), so its head proves nothing, and the published
    cursor describes the server rather than this copy.
    """
    saved = _to_dt(_read_state(path, SITE_STATE_SUFFIX).get("cursor"))
    if saved:
        return saved, "saved state"

    # No sidecar of our own — the standalone downloader writes the same archive
    # and may have left one describing this very file.
    saved = _to_dt(_read_state(path, DOWNLOADER_STATE_SUFFIX).get("cursor"))
    if saved:
        return saved, "downloader state"

    # Nothing recorded at all. The mtime is refreshed at the end of every
    # successful run, so it is a fair proxy; back it off to absorb clock skew.
    try:
        mtime = datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc)
        return mtime - MTIME_WATERMARK_MARGIN, "archive mtime (no saved state)"
    except OSError:
        return None, "unknown"


def _write_watermark(path, dt, source, downloaded=None):
    """Record the resume point, preserving the snapshot date unless given a new one."""
    if not dt:
        return
    state = _read_state(path, SITE_STATE_SUFFIX)
    state.update({"cursor": dt.isoformat(), "source": source})
    if downloaded:
        state["downloaded"] = downloaded.isoformat()
    try:
        with open(path + SITE_STATE_SUFFIX, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except OSError as e:
        print(f"Warning: could not save resume state ({e}); next run looks further back.")


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


def _stream_gzip_to(session, url, params, headers, dest, timeout):
    """Stream a gzipped endpoint straight to ``dest``, decompressing as it goes.

    The archive is multi-GB, so it never lands in memory whole. Returns the
    number of decompressed bytes written.
    """
    with session.get(
        url, params=params, headers=headers, stream=True, timeout=timeout
    ) as r:
        r.raise_for_status()
        decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
        with open(dest, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(decompressor.decompress(chunk))
            f.write(decompressor.flush())
    return os.path.getsize(dest)


def _ijson_array_prefix(path):
    """The ijson prefix of the first array in a response ('item', 'data.items.item', …)."""
    import ijson

    with open(path, "rb") as f:
        for prefix, event, _ in ijson.parse(f):
            if event == "start_array":
                return prefix + ".item" if prefix else "item"
    return "item"


def _apply_updates(path, update_file):
    """Merge a ``collection-update`` payload into the archive in place.

    Updates are staged in a temporary SQLite table keyed by document id, then the
    archive is streamed through ijson and rewritten: a document with a staged
    replacement is written from the payload, everything else is copied, and the
    ids never seen in the archive are appended as new documents. Both halves are
    O(1) in memory, which is the only way to touch a multi-GB array.

    Returns ``(modified, added, total, max_updated_dt)``; ``max_updated_dt`` is the
    newest modification actually applied and is the only value the watermark may
    advance to. Raises on failure, leaving the original archive untouched.
    """
    import sqlite3

    import ijson

    db_path = path + ".updates.db"
    tmp_path = path + ".merge.tmp"
    for leftover in (db_path, tmp_path):
        if os.path.exists(leftover):
            os.remove(leftover)

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE updates (id TEXT PRIMARY KEY, data TEXT)")
        cur = conn.cursor()

        staged = 0
        max_dt = None
        with open(update_file, "rb") as f:
            for item in ijson.items(f, _ijson_array_prefix(update_file)):
                doc_id = item.get("id")
                if not doc_id:
                    continue
                cur.execute(
                    "INSERT OR REPLACE INTO updates (id, data) VALUES (?, ?)",
                    (doc_id, json.dumps(item, indent=4, cls=_DecimalEncoder)),
                )
                staged += 1
                item_dt = _to_dt(
                    (item.get("timestamps") or {}).get("updated") or item.get("modified")
                )
                if item_dt and (max_dt is None or item_dt > max_dt):
                    max_dt = item_dt
                if staged % 10_000 == 0:
                    conn.commit()
        conn.commit()

        if staged == 0:
            return 0, 0, 0, None

        print(f"Merging {staged:,} updated documents into the archive ...")
        modified = added = total = 0
        with open(path, "rb") as old_f, open(tmp_path, "w", encoding="utf-8") as new_f:
            new_f.write("[\n")
            first = True
            for item in ijson.items(old_f, "item"):
                doc_id = item.get("id")
                if not first:
                    new_f.write(",\n")
                cur.execute("SELECT data FROM updates WHERE id = ?", (doc_id,))
                row = cur.fetchone()
                if row:
                    new_f.write(row[0])
                    # Drop it, so what remains in the table is exactly the new docs.
                    cur.execute("DELETE FROM updates WHERE id = ?", (doc_id,))
                    modified += 1
                else:
                    json.dump(item, new_f, indent=4, cls=_DecimalEncoder)
                first = False
                total += 1
                if total % _MERGE_PROGRESS_EVERY == 0:
                    print(f"  … {total:,} documents merged", flush=True)
            conn.commit()

            # Iterate the cursor rather than fetchall(): the leftover rows are whole
            # documents, and materialising them all defeats the point of staging them.
            for (data,) in conn.execute("SELECT data FROM updates"):
                if not first:
                    new_f.write(",\n")
                new_f.write(data)
                first = False
                total += 1
                added += 1
            new_f.write("\n]")

        if not _is_json_file_complete(tmp_path):
            raise ValueError("merged archive failed the completeness check")
        os.replace(tmp_path, path)
        return modified, added, total, max_dt
    finally:
        conn.close()
        for leftover in (db_path, tmp_path, update_file):
            if os.path.exists(leftover):
                try:
                    os.remove(leftover)
                except OSError:
                    pass


def _download_snapshot(session, path, headers):
    """Fetch the full ``archive/collection`` snapshot and return its watermark."""
    print(f"Downloading cve collection snapshot to {path} ...")
    start = time.time()
    size = _stream_gzip_to(
        session, COLLECTION_URL, {"type": "cve"}, headers, path, timeout=(10, 300)
    )
    if not _is_json_file_complete(path):
        print("Error: downloaded archive failed the completeness check.")
        sys.exit(1)
    print(f"Downloaded archive ({size / 1024 ** 3:.2f} GB) in {time.time() - start:.1f}s.")

    watermark = _archive_head_watermark(path)
    _write_watermark(
        path, watermark, "archive head", downloaded=datetime.now(timezone.utc)
    )
    return watermark


def _reusable_watermark(path, oldest_allowed_after):
    """The resume point of a usable local archive, or ``None`` if it must be refetched.

    Deletes the archive in the cases it returns ``None`` for, so the caller can
    simply download a fresh one.
    """
    if not os.path.exists(path):
        return None

    def discard(reason):
        print(f"{reason} Re-downloading the full snapshot ...")
        try:
            os.remove(path)
        except OSError as e:
            print(f"Failed to remove stale archive: {e}")
        return None

    if not _is_json_file_complete(path):
        return discard(f"Existing archive at {path} is incomplete.")

    downloaded = _to_dt(_read_state(path, SITE_STATE_SUFFIX).get("downloaded"))
    if downloaded and datetime.now(timezone.utc) - downloaded > MAX_SNAPSHOT_AGE:
        age_days = (datetime.now(timezone.utc) - downloaded).days
        return discard(
            f"Snapshot underneath the archive is {age_days} days old; deltas only "
            "carry modified documents, never removals."
        )

    watermark, source = _read_watermark(path)
    if watermark is None or watermark < oldest_allowed_after:
        behind = (
            "of unknown age"
            if watermark is None
            else f"{(datetime.now(timezone.utc) - watermark).total_seconds() / 3600:.1f}h behind"
        )
        return discard(
            f"Local archive is {behind}, past the "
            f"{MAX_UPDATE_LOOKBACK.total_seconds() / 3600:.0f}h collection-update window."
        )

    print(f"Reusing existing archive: {path} (resume point from {source})")
    return watermark


def download_archive_once():
    """Ensure a current ``cve`` archive exists in ``DATA_DIR`` and return its path.

    A complete local archive within the 25h ``collection-update`` window is kept
    and patched with deltas; anything older, missing, or corrupt is refetched as a
    full ``archive/collection`` snapshot first. Either way the run ends with a
    ``collection-update`` pass, so even a snapshot straight off the CDN is topped
    up to the second — published archives are rebuilt only a few times a day and
    are hours stale by the time they are served.

    A failed delta pass is not fatal: the archive is left as it stands and the
    watermark does not move, so the next run retries the same window.
    """
    data_dir = get_data_dir()
    os.makedirs(data_dir, exist_ok=True)
    path = os.path.join(data_dir, ARCHIVE_BASENAME)

    headers = {"X-Api-Key": get_api_key(), "Accept-Encoding": "gzip"}
    now = datetime.now(timezone.utc)
    oldest_allowed_after = now - MAX_UPDATE_LOOKBACK + UPDATE_LOOKBACK_SAFETY

    session = _robust_session()
    try:
        watermark = _reusable_watermark(path, oldest_allowed_after)
        if watermark is None:
            watermark = _download_snapshot(session, path, headers)
        if watermark is None:
            # Only reachable if the fresh snapshot's head would not parse; the
            # widest legal window re-applies more than needed, which is harmless.
            watermark = oldest_allowed_after
            print("Resume point unreadable; falling back to the widest legal window.")

        # Whole seconds widen the window slightly. Re-applying a few documents is
        # idempotent; rounding the other way would skip them.
        after = watermark.strftime("%Y-%m-%dT%H:%M:%S")
        print(
            f"Archive complete through {watermark.isoformat()} "
            f"({(now - watermark).total_seconds() / 3600:.1f}h behind); "
            f"fetching updates after {after} ..."
        )

        update_file = path + ".update.tmp"
        start = time.time()
        try:
            size = _stream_gzip_to(
                session,
                UPDATE_URL,
                {"type": "cve", "after": after},
                headers,
                update_file,
                timeout=(10, 120),
            )
            if size == 0:
                print("No updates published since the resume point.")
                _write_watermark(path, watermark, "unchanged")
                os.remove(update_file)
            else:
                modified, added, total, max_dt = _apply_updates(path, update_file)
                if modified or added:
                    if max_dt and max_dt > watermark:
                        watermark = max_dt
                    _write_watermark(path, watermark, "collection-update")
                    print(
                        f"Applied updates in {time.time() - start:.1f}s: "
                        f"{modified:,} modified, {added:,} new, {total:,} documents total."
                    )
                else:
                    print("Update payload contained no documents.")
                    _write_watermark(path, watermark, "unchanged")
        except Exception as e:  # noqa: BLE001 - a stale archive still builds a site
            print(f"Warning: could not apply collection-update deltas ({e}).")
            print("Continuing with the archive as it stands; watermark not advanced.")
            for leftover in (update_file, path + ".merge.tmp", path + ".updates.db"):
                if os.path.exists(leftover):
                    try:
                        os.remove(leftover)
                    except OSError:
                        pass
    finally:
        session.close()

    # Mark the archive as checked just now, for anything that reads its mtime.
    os.utime(path, None)
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
.intro { font-size: 1.12rem; line-height: 1.7; opacity: .92; margin: .5rem 0 0; }
hr.sep { border: none; border-top: 1px solid rgba(128,128,128,.28); margin: 2.5rem 0; }
figure { margin: 0; }
figcaption { margin-bottom: 1rem; opacity: .82; line-height: 1.6; }
/* Anchored jumps land below the top edge instead of flush against it. */
section, figure { scroll-margin-top: 1.5rem; }
a.permalink { margin-left: .35rem; text-decoration: none; opacity: .45; font-weight: 600; }
a.permalink:hover, a.permalink:focus { opacity: 1; }
.chart-index { margin: 1.25rem 0 0; padding-left: 1.2rem; opacity: .9; }
.chart-index li { margin: .15rem 0; }
img { max-width: 100%; height: auto; border: 1px solid rgba(128,128,128,.2); border-radius: 6px; }
a { color: #3b82f6; }
pre { overflow-x: auto; padding: 1rem; border: 1px solid rgba(128,128,128,.3); border-radius: 6px; background: rgba(128,128,128,.08); font-size: 12.5px; line-height: 1.45; }
footer { margin-top: 3rem; color: #888; font-size: .85rem; border-top: 1px solid rgba(128,128,128,.3); padding-top: 1rem; }
"""


def _slugify(text):
    """Lowercase ``text`` down to the ``[a-z0-9-]`` an HTML id/URL fragment wants."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def chart_anchor(result, chart):
    """The ``id`` (and URL fragment) for one chart on ``index.html``.

    Always namespaced by the dashboard slug, so anchors stay unique once more
    dashboards land on the page. A chart may name its own short ``anchor`` (the
    stable, shareable one — ``{"anchor": "projection"}`` becomes
    ``#monthly-projection``); without it the anchor is derived from the PNG
    filename, which is stable too but long.
    """
    short = chart.get("anchor") or os.path.splitext(os.path.basename(chart["file"]))[0]
    return f"{_slugify(result.slug)}-{_slugify(short)}"


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
        jumps = []
        for c in r.charts:
            anchor = html.escape(chart_anchor(r, c))
            label = c.get("label", "")
            if label:
                jumps.append(
                    f'    <li><a href="#{anchor}">{html.escape(label)}</a></li>'
                )
            # The permalink sits with the caption when there is one, and on its
            # own line above the image when there is not.
            permalink = (
                f'<a class="permalink" href="#{anchor}" '
                f'aria-label="Link to this chart"'
                + (f' title="{html.escape(label)}"' if label else "")
                + ">#</a>"
            )
            cap_html = (
                f"<figcaption>{html.escape(c['caption'])}{permalink}</figcaption>\n    "
                if c.get("caption")
                else f'<figcaption class="blurb">{permalink}</figcaption>\n    '
            )
            # A divider before each chart also separates the intro from the first
            # chart and each chart from the next. Caption sits above the image.
            figures.append(
                '  <hr class="sep">\n'
                f'  <figure id="{anchor}">\n    {cap_html}'
                f'<img src="{html.escape(os.path.basename(c["file"]))}" '
                f'alt="{html.escape(label or r.title)} chart">\n  </figure>'
            )
        index_sections.append(
            f'<section id="{html.escape(r.slug)}">\n'
            f'  <p class="intro">{html.escape(r.blurb)}</p>\n'
            + (
                f'  <ul class="chart-index">\n' + "\n".join(jumps) + "\n  </ul>\n"
                if jumps
                else ""
            )
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
            f"  <h2>{html.escape(r.title)}"
            f'<a class="permalink" href="#{html.escape(r.slug)}" '
            'aria-label="Link to this section">#</a></h2>\n'
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
