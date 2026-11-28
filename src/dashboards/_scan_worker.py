"""Lightweight worker module for parallel multi-core scanning of 1-doc-per-line
Vulners CVE JSON archives.

Deliberately imports only stdlib (+ optional ``orjson``) — no matplotlib, numpy,
or requests — so spawned worker processes start in ~20 ms and scan byte-range
chunks of multi-GB archives concurrently across CPU cores.
"""
import collections
import json
import os
import re
from datetime import date, timedelta

try:
    import orjson as _orjson
except ImportError:
    _orjson = None

_IO_BUFFER_BYTES = 4 * 1024 * 1024

_CHROME_NESSUS_VER = re.compile(r"^(?:MACOSX_)?GOOGLE_CHROME_(\d+)_(\d+)_(\d+)_(\d+)\.NASL$")
_CHROME_POST_URL = re.compile(r"chromereleases\.googleblog\.com/(\d{4}/\d{2}/[^\s\"']+)")
_CHROME_FIX_VER = re.compile(r"prior to (\d+\.\d+\.\d+\.\d+)")
_ANDROID_BULLETIN_URL = re.compile(r"source\.android\.com/(?:docs/)?security/bulletin/([^\s\"'#?]+)")
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

_TRACKED_YEARS = frozenset(("2022", "2023", "2024", "2025", "2026"))


def loads_bytes(raw):
    if _orjson is not None:
        return _orjson.loads(raw)
    return json.loads(raw)


def _chrome_row(item, day, candidate=False):
    """One Chrome CVE's release facts for the fan-in slides."""
    advisories, versions = [], set()
    ench = item.get("enchantments")
    deps = ench.get("dependencies") if isinstance(ench, dict) else None
    refs = deps.get("references") if isinstance(deps, dict) else None
    for ref in refs if isinstance(refs, list) else ():
        if not isinstance(ref, dict):
            continue
        rtype = ref.get("type")
        if rtype == "chrome":
            advisories.extend(str(i) for i in ref.get("idList") or [])
        elif rtype == "nessus":
            for plugin in ref.get("idList") or []:
                mv = _CHROME_NESSUS_VER.match(str(plugin))
                if mv:
                    versions.add(".".join(mv.groups()))
    posts = []
    for url in item.get("references") or ():
        mp = _CHROME_POST_URL.search(str(url))
        if mp and mp.group(1) not in posts:
            posts.append(mp.group(1))
    mf = _CHROME_FIX_VER.search(str(item.get("description") or ""))
    cwes = item.get("cwe") or []
    return {
        "id": item.get("id"),
        "day": day,
        "posts": posts,
        "advisories": advisories,
        "versions": sorted(versions),
        "fix_version": mf.group(1) if mf else None,
        "cwe": sorted({str(c) for c in (cwes if isinstance(cwes, list) else [cwes]) if c}),
        "candidate": candidate,
    }


def _android_row(item, day):
    """One Android-CNA CVE for the bulletin x CWE slide."""
    bulletin = None
    for url in item.get("references") or ():
        mb = _ANDROID_BULLETIN_URL.search(str(url))
        if mb:
            bulletin = mb.group(1).rstrip("/")
            break
    cwes = item.get("cwe") or []
    return {
        "id": item.get("id"),
        "day": day,
        "bulletin": bulletin,
        "cwe": sorted({str(c) for c in (cwes if isinstance(cwes, list) else [cwes]) if c}),
    }


def fanout_record(item):
    """The facts the fan-out slides read from one CVE document."""
    ench = item.get("enchantments")
    deps = ench.get("dependencies") if isinstance(ench, dict) else None
    refs = deps.get("references") if isinstance(deps, dict) else None
    refs = refs if isinstance(refs, list) else []
    return {
        "id": item["id"],
        "published": (item.get("published") or "")[:10],
        "reporter": item.get("reporter"),
        "short": (ench.get("short_description") if isinstance(ench, dict) else None) or "",
        "software": sorted({
            str(a.get("name") or a.get("cpeName") or "")
            for a in (item.get("affectedSoftware") or []) if isinstance(a, dict)
        }),
        "cpe_products": list(dict.fromkeys(
            str(c.get("criteria") or "").split(":")[4].replace("_", " ")
            for key in ("vulnersCpeConfiguration", "nvdCpeConfiguration")
            for conf in ((item.get("cpeConfigurations") or {}).get(key) or [])
            for node in conf.get("nodes") or [] for c in node.get("cpeMatch") or []
            if isinstance(c, dict) and len(str(c.get("criteria") or "").split(":")) > 4
        )),
        "kev": any(isinstance(r, dict) and r.get("type") == "vulncheck_kev" for r in refs),
        "references": [
            {"type": r.get("type"), "idList": [str(i) for i in (r.get("idList") or [])]}
            for r in refs if isinstance(r, dict)
        ],
    }


def make_empty_acc():
    return {
        "stats": {},
        "partial_stats": {},
        "daily_counts_2025": collections.Counter(),
        "daily_counts_2026": collections.Counter(),
        "daily_cna_counts_2026": {},
        "daily_counts": {},
        "daily_counts_kernel": {},
        "candidate_stats": {},
        "status_yearly": {},
        "status_weekly": {},
        "status_cna": {},
        "chrome_cves": [],
        "android_cves": [],
        "fanout_records": {},
        "epss_rows": [],
        "wild_first_seen": collections.Counter(),
        "wild_sources": collections.Counter(),
        "wild_cve_first_seen": {},
        "exploited_cve_published": {},
        "exploited_cve_candidate": set(),
        "native_labels": set(),
        "resolved_labels": collections.Counter(),
        "unresolved_labels": collections.Counter(),
        "total_processed": 0,
        "relevant_found": 0,
        "deferred_email_lines": [],
    }


def _bump_nested_2(d, k1, k2):
    sub = d.get(k1)
    if sub is None:
        sub = collections.Counter()
        d[k1] = sub
    sub[k2] += 1


def _bump_nested_3(d, k1, k2, k3):
    sub1 = d.get(k1)
    if sub1 is None:
        sub1 = {}
        d[k1] = sub1
    sub2 = sub1.get(k2)
    if sub2 is None:
        sub2 = collections.Counter()
        sub1[k2] = sub2
    sub2[k3] += 1


def process_item(item, acc, cfg, week_cache, resolve_fn=None, raw_line=None):
    """Apply the exact ``count_monthly_cves`` per-document logic to one item."""
    acc["total_processed"] += 1

    published_date = item.get("published")
    vuln_status = item.get("vulnStatus")
    reporter = item.get("reporter")
    cna_name = item.get("cna") or reporter or "Unknown"

    if "@" in cna_name and _EMAIL_RE.fullmatch(cna_name):
        raw_id = item.get("id")
        if resolve_fn is not None:
            resolved = resolve_fn(raw_id)
        else:
            cid_u = str(raw_id or "").upper()
            if cid_u.startswith("CVE-"):
                resolved = cfg["assigner_cache"].get(cid_u)
                if resolved is None and raw_line is not None:
                    # Cache miss: defer this single record to the main process
                    # so MITRE API calls stay centralized and batched.
                    acc["total_processed"] -= 1
                    acc["deferred_email_lines"].append((cid_u, raw_line))
                    return
            else:
                resolved = None
        if resolved:
            acc["resolved_labels"][(cna_name, resolved)] += 1
            cna_name = resolved
        else:
            acc["unresolved_labels"][cna_name] += 1
    else:
        acc["native_labels"].add(cna_name)

    is_rejected = bool(vuln_status) and vuln_status.lower() == "rejected"
    is_candidate = bool(reporter) and reporter.lower() == "candidate"
    local_mode = cfg["local_mode"]
    anchor_date_str = cfg["anchor_date_str"]
    anchor_year = cfg["anchor_year"]

    ench = item.get("enchantments")
    expl = ench.get("exploitation") if isinstance(ench, dict) else None
    is_wild = isinstance(expl, dict) and expl.get("wildExploited") is True

    raw_id = item.get("id")
    if not is_rejected:
        if is_wild:
            srcs = [s for s in expl.get("wildExploitedSources") or [] if isinstance(s, dict)]
            seen = [str(s.get("firstSeen") or "")[:10] for s in srcs]
            seen = [d for d in seen if len(d) == 10]
            if seen:
                earliest = min(seen)
                if local_mode:
                    acc["wild_first_seen"][earliest] += 1
                if raw_id:
                    acc["wild_cve_first_seen"][str(raw_id).upper()] = earliest
            if local_mode:
                for s in srcs:
                    st = s.get("type")
                    if st:
                        acc["wild_sources"][st] += 1
        cve_id_upper = str(raw_id or "").upper()
        if (cve_id_upper in cfg["kev_ids"] or is_wild) and published_date and len(published_date) >= 10:
            acc["exploited_cve_published"][cve_id_upper] = published_date[:10]
            if is_candidate:
                acc["exploited_cve_candidate"].add(cve_id_upper)

    if local_mode and raw_id in cfg["fanout_wanted"]:
        acc["fanout_records"][raw_id] = fanout_record(item)

    has_pub = bool(published_date) and len(published_date) >= 10
    if has_pub:
        pub_day_str = published_date[:10]
        pub_year_str = published_date[:4]
        pub_lte_anchor = pub_day_str <= anchor_date_str
    else:
        pub_day_str = ""
        pub_year_str = ""
        pub_lte_anchor = False

    if (
        has_pub
        and pub_lte_anchor
        and pub_year_str.isdigit()
        and int(pub_year_str) >= cfg["status_start_year"]
    ):
        week_iso = week_cache.get(pub_day_str)
        if week_iso is None:
            try:
                pub_day = date(
                    int(pub_year_str), int(published_date[5:7]), int(published_date[8:10])
                )
                week_iso = (pub_day - timedelta(days=pub_day.weekday())).isoformat()
            except ValueError:
                week_iso = ""
            week_cache[pub_day_str] = week_iso
        if week_iso:
            status_key = vuln_status or "Reserved"
            _bump_nested_2(acc["status_yearly"], pub_year_str, status_key)
            _bump_nested_2(acc["status_weekly"], week_iso, status_key)
            if pub_day_str >= cfg["status_cna_start"]:
                _bump_nested_2(acc["status_cna"], cna_name, status_key)

    if is_candidate:
        if has_pub and pub_year_str == anchor_year and pub_lte_anchor:
            mkey = published_date[:7]
            cs = acc["candidate_stats"].get(mkey)
            if cs is None:
                cs = {
                    "active": 0, "rejected": 0,
                    "ref_types": collections.Counter(),
                    "source_sets": collections.Counter(),
                }
                acc["candidate_stats"][mkey] = cs
            cs["rejected" if is_rejected else "active"] += 1
            if isinstance(ench, dict):
                deps = ench.get("dependencies")
                if isinstance(deps, dict):
                    refs = deps.get("references")
                    if isinstance(refs, list):
                        src_types = {
                            ref["type"] for ref in refs
                            if isinstance(ref, dict) and ref.get("type")
                        }
                        for t in src_types:
                            cs["ref_types"][t] += 1
                        if src_types:
                            cs["source_sets"][frozenset(src_types)] += 1
            if local_mode and not is_rejected:
                row = _chrome_row(item, pub_day_str, candidate=True)
                if row["posts"] or row["advisories"] or row["versions"]:
                    acc["chrome_cves"].append(row)
        return

    if is_rejected:
        return

    if (
        local_mode
        and has_pub
        and raw_id
        and pub_year_str.isdigit()
        and int(pub_year_str) >= cfg["epss_min_year"]
        and pub_lte_anchor
    ):
        acc["epss_rows"].append((str(raw_id).upper(), pub_day_str, is_wild))

    if has_pub:
        month = published_date[5:7]
        day = int(published_date[8:10])
        if not pub_lte_anchor:
            return
        if pub_year_str in _TRACKED_YEARS:
            if local_mode and pub_year_str == anchor_year:
                if cna_name == cfg["chrome_cna"]:
                    acc["chrome_cves"].append(_chrome_row(item, pub_day_str))
                if cna_name == cfg["android_cna"]:
                    acc["android_cves"].append(_android_row(item, pub_day_str))

            _bump_nested_3(acc["stats"], month, pub_year_str, cna_name)
            day_key = f"{month}-{day:02d}"
            if local_mode and cna_name == cfg["kernel_cna"]:
                _bump_nested_2(acc["daily_counts_kernel"], pub_year_str, day_key)
            if day <= cfg["current_day"]:
                _bump_nested_3(acc["partial_stats"], month, pub_year_str, cna_name)
            _bump_nested_2(acc["daily_counts"], pub_year_str, day_key)
            if pub_year_str == "2025":
                acc["daily_counts_2025"][day_key] += 1
            elif pub_year_str == "2026":
                acc["daily_counts_2026"][day_key] += 1
                if local_mode:
                    _bump_nested_2(acc["daily_cna_counts_2026"], cna_name, day_key)
            acc["relevant_found"] += 1


def scan_chunk(args):
    """Scan lines in ``[start_offset, end_offset)`` of a 1-doc-per-line archive.

    Returns ``(acc, saw_close_bracket)`` or ``None`` if any line is not a single
    compact JSON object (causing the caller to fall back to streaming ijson).
    """
    file_path, start_offset, end_offset, is_first, is_last, cfg = args
    acc = make_empty_acc()
    week_cache = {}
    saw_close = False

    with open(file_path, "rb", buffering=_IO_BUFFER_BYTES) as f:
        f.seek(start_offset)
        if is_first:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                if s != b"[":
                    return None
                break
            else:
                return None

        while f.tell() < end_offset:
            line = f.readline()
            if not line:
                break
            s = line.strip()
            if not s:
                continue
            if s == b"]":
                saw_close = True
                if not is_last:
                    return None
                # Ensure no trailing non-whitespace content.
                for trailing in f:
                    if trailing.strip():
                        return None
                break
            if s.endswith(b","):
                s = s[:-1].rstrip()
            if not (s.startswith(b"{") and s.endswith(b"}")):
                return None
            try:
                item = loads_bytes(s)
            except ValueError:
                return None
            if not isinstance(item, dict):
                return None
            process_item(item, acc, cfg, week_cache, resolve_fn=None, raw_line=s)

    if is_last and not saw_close:
        return None
    return acc


def compute_line_chunks(file_path, n_workers):
    """Split ``file_path`` into up to ``n_workers`` contiguous newline-aligned byte ranges."""
    size = os.path.getsize(file_path)
    if size == 0 or n_workers <= 1:
        return [(0, size)]
    step = size // n_workers
    boundaries = [0]
    with open(file_path, "rb") as f:
        for i in range(1, n_workers):
            target = i * step
            if target <= boundaries[-1]:
                continue
            f.seek(target)
            f.readline()  # advance to start of next complete line
            pos = f.tell()
            if pos >= size:
                break
            if pos > boundaries[-1]:
                boundaries.append(pos)
    boundaries.append(size)
    return [(boundaries[i], boundaries[i + 1]) for i in range(len(boundaries) - 1)]


def is_compact_ndjson_array(file_path):
    """Quick O(1) check whether ``file_path`` starts with ``[`` on line 1 and a
    complete single-line JSON object on line 2."""
    try:
        with open(file_path, "rb") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                if s != b"[":
                    return False
                break
            else:
                return False
            for line in f:
                s = line.strip()
                if not s:
                    continue
                if s == b"]":
                    return True
                if s.endswith(b","):
                    s = s[:-1].rstrip()
                if not (s.startswith(b"{") and s.endswith(b"}")):
                    return False
                return isinstance(loads_bytes(s), dict)
        return False
    except (OSError, ValueError):
        return False
