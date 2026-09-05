'''Monthly CVE/CNA statistics dashboard.

Generation logic extracted verbatim from the original
cve_monthly_stats_comparison.py so both the site orchestrator (``python -m src``)
and the thin local wrapper drive one copy of the code. Produces the eight charts
(six monthly ones plus the two NVD-status ones that used to live in
cve_status_stats.py) and the aligned-table report; no CSV/TXT outputs, no tqdm, no stdout-teeing on the
published path.
'''
import collections
import csv
import io
import json
import os
import re
import time
from contextlib import redirect_stdout
from datetime import date, datetime, timedelta

import glob
import gzip
import ijson
import numpy as np
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import matplotlib
matplotlib.use("Agg")  # headless: never needs a display in CI
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.image as mpimg
import matplotlib.patheffects as path_effects

from ..base import Dashboard, DashboardResult

# Configuration
TOP_N = 15
# Cap the analysis at a fixed date ("YYYY-MM-DD"); None = through the last full
# day. Env-overridable so the final 2026 run can be pinned to 2026-12-31 (full
# year) — the workflow sets CVE_CUT_OFF_DATE at the year boundary.
CUT_OFF_DATE = os.getenv("CVE_CUT_OFF_DATE") or None
_WRITE_CSV = False   # published path writes no CSV; a local caller may flip this
# Also render every chart a second time as a 16:9 presentation slide (see
# ``monthly_slides``). Off on the published path — the page shows only the six
# charts in CHART_FILES — and flipped on by the local wrapper.
_SLIDES = False

# Last day the numbers actually cover (the anchor). Set by count_monthly_cves()
# and stamped into every chart footer next to the generation date; the two are
# never the same day, and a stale upstream dump makes them drift further apart.
_DATA_THROUGH = None

# Frozen reference predictions calculated on June 6, 2026 (Jan-May completed).
REFERENCE_PREDICTIONS = {
    "06": 7479,
    "07": 8292,
    "08": 8578,
    "09": 10922,
    "10": 11517,
    "11": 8642,
    "12": 16634,
}

# Index of the first month REFERENCE_PREDICTIONS forecasts. The 100k-baseline
# curve rides the actuals up to the month before it and the reference numbers
# from there to December, so this is also the first month whose baseline point
# is a projection worth labelling as one. Derived from the table rather than
# written down twice, so extending the table moves the boundary with it.
_BASELINE_PROJ_IDX = min(int(m) for m in REFERENCE_PREDICTIONS) - 1

# FIRST's Vulnerability Forecasting SIG mid-year forecast for the anchor year's
# full-year CVE count, published June 15th. Drawn on the yearly cumulative chart
# (web and slide) as a dashed "finish line": the axis is raised to keep it in
# view until the current year's curve crosses it.
FIRST_FORECAST_TOTAL = 66_000
FIRST_FORECAST_LABEL = "FIRST Mid-Year Vulnerability Forecast, June 15th"


def clamp_growth(g_m):
    """Bound a projected YoY growth factor.

    The fitted trend is extrapolated as-is — there is no ceiling. Only the floor
    is real: below -100% a month would publish a negative number of CVEs. An
    earlier version also capped growth at +300%, which silently flattened the
    tail of the year once the regression line climbed past it (December 2026
    reached +299.5%, half a point from being truncated without any visible sign).
    """
    return max(-1.0, g_m)


# Charts, in the order they appear on the page (written into the out_dir given
# to generate()). These filenames match what the plotting functions emit.
CHART_FILES = [
    "cve_monthly_stats_comparison_yearly_cumulative.png",
    "cve_monthly_stats_comparison_ytd_growth.png",
    "cve_monthly_stats_comparison_sankey_monthly.png",
    "cve_monthly_stats_comparison_incomplete_month.png",
    "cve_monthly_stats_comparison_projection.png",
    "cve_monthly_stats_comparison_status_yearly.png",
    "cve_monthly_stats_comparison_status_weekly.png",
    "cve_monthly_stats_comparison_candidate_track.png",
]

# Per-chart anchor (the shareable ``#monthly-<anchor>`` fragment on the page) and
# the short name shown in the section's jump list. Anchors are part of published
# URLs — rename a chart file freely, but keep these stable.
CHART_LINKS = {
    "cve_monthly_stats_comparison_yearly_cumulative.png": ("cumulative", "Cumulative CVEs by year"),
    "cve_monthly_stats_comparison_ytd_growth.png": ("pace", "Year-over-year pace"),
    "cve_monthly_stats_comparison_sankey_monthly.png": ("cna-flow", "Monthly flow by CNA"),
    "cve_monthly_stats_comparison_incomplete_month.png": ("month-comparison", "Month-to-month comparison"),
    "cve_monthly_stats_comparison_projection.png": ("projection", "Year-end projections"),
    "cve_monthly_stats_comparison_status_yearly.png": ("nvd-status-yearly", "NVD status by year"),
    "cve_monthly_stats_comparison_status_weekly.png": ("nvd-status-weekly", "NVD status by week"),
    "cve_monthly_stats_comparison_candidate_track.png": ("reserved", "Reserved but unpublished"),
}

MONTHLY_BLURB = (
    "Welcome to the Vulnpocalypse. This is the counter I keep running in the "
    "corner of the screen so I can watch the CVE pipeline lap every year that "
    "came before it. Every chart here is one more angle on the same story: how "
    "fast CVEs are being published, and how far ahead of the years before it "
    "the current pace is running. Data is from the Vulners CVE archive. Grab a "
    "coffee before you scroll."
)

# Caption shown beneath each chart image (keyed by chart filename). Kept purely
# descriptive of what the chart shows — no specific figures, dates, or trend
# claims that would go stale as the data updates.
CHART_CAPTIONS = {
    "cve_monthly_stats_comparison_yearly_cumulative.png": (
        "Five years, five lines, one very rude red one. The newest year crosses "
        "the full-year totals of earlier years long before its own twelve months "
        "are up, then keeps climbing like the finish line owed it money. Numbers "
        "that took those years a whole year to reach, it reaches with months to "
        "spare. The gap between the red line and the pack is not a rendering "
        "glitch. That is just the tide coming in."
    ),
    "cve_monthly_stats_comparison_ytd_growth.png": (
        "This is the speedometer, and the needle is pinned. The current year sits "
        "well above the prior year's line and stays there. The two lines shook "
        "hands once, early on, and have not spoken since."
    ),
    "cve_monthly_stats_comparison_sankey_monthly.png": (
        "The lines above tell you how fast; this one tells you who. The same "
        "firehose, sliced by month and split by CNA, so you can watch the ribbons "
        "swell. Every column hangs from the same line and is drawn to one scale, "
        "so a height means the same number of CVEs wherever it sits: trace one "
        "CNA's band across the months, or measure a handful of the newest month's "
        "publishers against everything an earlier month managed. The dashed line "
        "carries one whole month across the picture for exactly that — wherever "
        "it crosses, everything above it is that month's worth of CVEs. This is "
        'what "more of everything, from everyone" looks like when you actually '
        "draw it."
    ),
    "cve_monthly_stats_comparison_incomplete_month.png": (
        "Down from the whole year to a single window. Three snapshots of the exact "
        "same slice of the calendar, lined up side "
        "by side: this month so far in the middle, the same days of last month on "
        "the left, and the same stretch a year ago on the right. Same window, "
        "three different levels of pain. It answers two questions at a glance, "
        "whether the current month is already outrunning the one before it, and "
        "how much further ahead of last year the whole pipeline has drifted. The "
        "current column is rarely the short one."
    ),
    "cve_monthly_stats_comparison_projection.png": (
        "Two ways to guess where this ends, and neither one lets you sleep. One "
        "line runs the current rate forward; the other draws the rounder "
        "baseline. Both land well above where the prior year finished, which "
        "already reads like the good old days. The asterisks mean projection. The "
        "slope means call the cavalry."
    ),
    "cve_monthly_stats_comparison_status_yearly.png": (
        "Counting is one thing; looking is another. Every CVE published carries an "
        "NVD status that says how far the analysts got with it, and this stacks a "
        "year's worth of them into one bar. The blue is what NVD has actually "
        "analysed. The gray at the top is Deferred: waved through without a look. "
        "The warm colors are the queue, everything still waiting its turn. Watch "
        "how the bars grow, and watch how much of each new bar is anything other "
        "than blue."
    ),
    "cve_monthly_stats_comparison_status_weekly.png": (
        "The same statuses, week by week, full weeks only. The top chart is the "
        "raw count, so the spikes are the weeks that hurt. The bottom chart "
        "squeezes every week to the same height, so what is left is the mix: how "
        "much of each week's output got analysed, how much was deferred, and how "
        "much is still sitting in the queue. When the warm band at the top grows, "
        "the backlog is growing faster than the analysts."
    ),
    "cve_monthly_stats_comparison_candidate_track.png": (
        "And here is the part nobody counts. These are CVE IDs already reserved "
        "but not yet published — the queue behind the curtain, the storm still out "
        "at sea, none of it counted in the numbers above. Each row is a source "
        "feeding that backlog; each column is a month; the brighter the cell, the "
        "more reserved CVEs that source touched. Read a column to see who's driving "
        "the month, and watch the rows: a band that sits dark and then suddenly "
        "lights up is a new source arriving — the next wave forming before it "
        "breaks. Whatever the rest of this page frightened you with, it hasn't "
        "counted these yet."
    ),
}

# The three-column comparison chart loses its "so far" framing on a run where the
# anchor month has closed (the 1st of the following month): all three columns are
# whole months then, so the caption is swapped for this one.
COMPLETE_MONTH_CAPTION = (
    "Down from the whole year to a single window. The month that just closed, "
    "boxed in on both sides: the finished month in "
    "the middle, the month before it on the left, and the same month a year ago "
    "on the right. Three whole months, nothing clipped to match, nothing still "
    "to come in. It answers two questions at a glance, whether the month that "
    "just ended outran the one before it, and how much further ahead of last "
    "year the whole pipeline has drifted. The middle column is rarely the short "
    "one."
)

# ── Shared chart palette ─────────────────────────────────────────────────────
# Every chart draws its series colors from the Sankey "premium" palette so the
# whole dashboard reads as one system. #FF4757 (the Sankey's first red) is the
# anchor; the rest are pulled from the same palette. Colorblind separation on the
# dark (#1E1E1E) surface is validated with the dataviz palette validator.
C_RED = "#FF4757"     # current year / primary emphasis  (Sankey rank 1)
C_BLUE = "#2E86DE"    # previous year / reference         (Sankey rank 8)
C_GREEN = "#2ED573"   # positive / baseline projection    (Sankey rank 15)
C_YELLOW = "#F1C40F"  # (Sankey rank 6)
C_GRAY = "#747D8C"    # oldest year / neutral data        (Sankey Others)

# Fixed color per calendar year for the multi-year comparison charts.
YEAR_COLORS = {
    "2022": C_GRAY,
    "2023": C_YELLOW,
    "2024": C_GREEN,
    "2025": C_BLUE,
    "2026": C_RED,
}

# ── Chrome releases ──────────────────────────────────────────────────────────
# The Chrome CNA as the dashboard names it: ``count_monthly_cves`` takes the
# record's ``cna`` field and falls back to ``reporter`` — Chrome's records carry
# no ``cna`` and ``reporter == "Chrome"``, which is the Sankey's "Chrome" lane.
# For the anchor year every Chrome CVE's release facts are kept for the fan-in
# slide: the Chrome security advisory it references (``type: chrome`` in
# enchantments.dependencies.references, a ``GCSA-…`` id — one advisory is one
# release) and the Chrome version named by its Nessus plugin id.
CHROME_CNA = "Chrome"
_CHROME_NESSUS_VER = re.compile(r"^(?:MACOSX_)?GOOGLE_CHROME_(\d+)_(\d+)_(\d+)_(\d+)\.NASL$")

# ── Fan-out: one CVE, many downstream advisories ─────────────────────────────
# The fan-out slide takes one CVE and counts the distinct downstream records
# that reference it — a distribution's advisory, a vendor's bulletin, an
# ecosystem's advisory — grouped by who issued them. The CVE was picked once,
# offline, from the 2026 CVEs with the most such references (see
# FANOUT_SHORTLIST, whose counts the local run writes to CSV); the picture is
# then drawn from the archive record on every run.
FANOUT_CVE = "CVE-2026-31431"
FANOUT_SHORTLIST = [
    "CVE-2026-31431",   # Linux kernel, KEV
    "CVE-2026-43284",   # Linux kernel, KEV
    "CVE-2026-46300",   # Linux kernel, KEV
    "CVE-2026-42945",   # NGINX, KEV
    "CVE-2025-69419",   # OpenSSL (published Jan 2026)
    "CVE-2026-28390",   # OpenSSL
    "CVE-2026-45447",   # OpenSSL
    "CVE-2026-25210",   # libexpat
    "CVE-2026-35385",   # OpenSSH
    "CVE-2026-5450",    # glibc
    "CVE-2026-35535",   # sudo
    "CVE-2026-11822",   # SQLite
    "CVE-2026-33845",   # GnuTLS
    "CVE-2026-8286",    # curl
    "CVE-2025-14524",   # curl (published Jan 2026)
    "CVE-2026-34743",   # XZ Utils
    "CVE-2026-3381",    # Compress::Raw::Zlib (zlib class)
    "CVE-2026-11979",   # libxml2
    "CVE-2026-4480",    # Samba, KEV
]
# Reference types that are not downstream changes: scanners and detection
# content, CVE mirrors and aggregators, exploit and news feeds, KEV lists.
FANOUT_EXCLUDE = {
    "nessus", "openvas", "nuclei", "tenable", "qualysblog", "veracode", "snyk",
    "ptsecurity", "cvelist", "nvd", "euvd", "vulnrichment", "circl", "cnnvd", "cnvd",
    "bdu_fstec", "attackerkb", "ncsc", "jvn", "kaspersky", "cve", "vulnersosv", "cert",
    "githubexploit", "gitee", "kitploit", "packetstorm", "packetstormnews", "exploitdb",
    "metasploit", "seebug", "zdt", "thn", "talosblog", "rapid7blog", "avleonov",
    "hackerone", "zdi", "wizblog", "akamaiblog", "nodejsblog", "vulncheck_kev", "ics",
    "wordfence", "patchstack", "chrome", "epss", "cisa", "cisa_kev", "mssecure", "securelist",
    "wired", "impervablog", "anthropic", "krebs", "threatpost", "malwarebytes", "schneier",
    "trendmicroblog", "googleprojectzero", "checkpoint_advisories",
}
# Per-CVE tracker pages of vendors that also issue advisories — a page, not a
# change; the advisories are counted instead.
FANOUT_TRACKERS = {"redhatcve", "ubuntucve", "susecve", "debiancve"}
# Reference type -> who issued the record.
FANOUT_GROUPS = {
    "redhat": "Red Hat", "ubuntu": "Ubuntu", "suse": "SUSE", "opensuse": "SUSE",
    "debian": "Debian", "amazon": "Amazon Linux", "oraclelinux": "Oracle Linux",
    "rocky": "Rocky Linux", "almalinux": "AlmaLinux", "fedora": "Fedora", "mageia": "Mageia",
    "alpinelinux": "Alpine", "cgr": "Chainguard", "wolfi": "Chainguard",
    "cbl_mariner": "Azure Linux", "photon": "VMware Photon", "rosalinux": "ROSA Linux",
    "redos": "RED OS", "astralinux": "Astra Linux", "slackware": "Slackware",
    "freebsd": "FreeBSD", "freebsd_advisory": "FreeBSD", "virtuozzo": "Virtuozzo",
    "cloudlinux": "CloudLinux", "gentoo": "Gentoo", "archlinux": "Arch Linux",
    "ibm": "IBM", "aix": "IBM", "hpe": "HPE", "f5": "F5 / NGINX", "nginx": "F5 / NGINX",
    "broadcom": "Broadcom", "arista": "Arista", "cisco": "Cisco", "nvidia": "NVIDIA",
    "oracle": "Oracle", "acronis": "Acronis", "mscve": "Microsoft", "mskb": "Microsoft",
    "apple": "Apple", "mozilla": "Mozilla", "atlassian": "Atlassian", "gitlab": "GitLab",
    "juniper": "Juniper", "paloalto": "Palo Alto", "fortinet": "Fortinet", "huawei": "Huawei",
    "github": "GitHub Advisory Database", "pypa": "PyPI", "rubygems": "RubyGems",
    "friendsofphp": "Packagist (PHP)", "spring": "Spring", "npm": "npm",
    "ivanti": "Ivanti", "samba": "Samba", "sqlite": "SQLite", "curl": "curl", "openssl": "OpenSSL",
    "kernel": "kernel.org", "xen": "Xen", "qemu": "QEMU", "vmware": "VMware", "citrix": "Citrix",
    "dell": "Dell", "lenovo": "Lenovo", "intel": "Intel", "amd": "AMD", "sap": "SAP", "siemens": "Siemens",
    "schneider": "Schneider Electric", "jenkins": "Jenkins", "drupal": "Drupal", "joomla": "Joomla",
    "moodle": "Moodle", "nodejs": "Node.js", "php": "PHP", "postgresql": "PostgreSQL", "mysql": "MySQL",
    "kubernetes": "Kubernetes", "docker": "Docker", "haproxy": "HAProxy", "openbsd": "OpenBSD", "netbsd": "NetBSD",
}
# OSV mirrors many of the above under its own ids; the prefix says whose
# record it is. ``None`` = not a downstream change (per-CVE tracker entries,
# OSS-Fuzz, malicious-package reports, upstream's own advisories).
FANOUT_OSV_PREFIXES = [
    ("RHSA-", "Red Hat"), ("RHBA-", "Red Hat"), ("RHEA-", "Red Hat"),
    ("USN-", "Ubuntu"), ("LSN-", "Ubuntu"), ("UBUNTU-CVE-", None),
    ("DSA-", "Debian"), ("DLA-", "Debian"), ("DTSA-", "Debian"), ("DEBIAN-CVE-", None),
    ("SUSE-", "SUSE"), ("OPENSUSE-", "SUSE"),
    ("ALSA-", "AlmaLinux"), ("ALBA-", "AlmaLinux"), ("ALEA-", "AlmaLinux"),
    ("RLSA-", "Rocky Linux"), ("RXSA-", "Rocky Linux"), ("ELSA-", "Oracle Linux"),
    ("MGASA-", "Mageia"), ("ALPINE-", "Alpine"), ("CGA-", "Chainguard"), ("GLSA-", "Gentoo"),
    ("ASA-", "Arch Linux"), ("BIT-", "Bitnami"), ("MINI-", "Minimus"),
    ("CLSA-", "CloudLinux"), ("OESA-", "openEuler"), ("AZL-", "Azure Linux"), ("ROOT-OS-", "Root OS"),
    ("BELL-", "BellSoft"), ("ECHO-", "Echo"), ("CLEANSTART-", "CleanStart"), ("JLSEC-", "Jetify"),
    ("GHSA-", "GitHub Advisory Database"), ("GO-", "Go (pkg.go.dev)"), ("PYSEC-", "PyPI"),
    ("RUSTSEC-", "crates.io"), ("HSEC-", "Haskell"), ("PSF-", "Python (PSF)"), ("RSEC-", "R (CRAN)"),
    ("MAL-", None), ("CURL-", None), ("OSV-", None), ("GSD-", None), ("UVI-", None),
    ("EUVD-", None), ("CVE-", None),
]
_FANOUT_RHSA = re.compile(r"^(RH[SBE]A-\d{4}:\d+)")


def _fanout_route(ref_type, ref_id):
    """(issuer, canonical id) for one reference, or ``None`` when it is not a
    downstream record. Canonical ids let the same advisory seen through two
    sources (a vendor feed and OSV) count once."""
    rid = str(ref_id).strip().upper()
    if ref_type in FANOUT_EXCLUDE or ref_type in FANOUT_TRACKERS:
        return None
    if ref_type == "osv":
        rid = rid[4:] if rid.startswith("OSV:") else rid
        for prefix, group in FANOUT_OSV_PREFIXES:
            if rid.startswith(prefix):
                if group is None:
                    return None
                break
        else:
            group = "OSV (other ecosystems)"
    else:
        group = FANOUT_GROUPS.get(ref_type)
        if group is None:
            group = f"other: {ref_type}"
    # Canonical forms.
    if group == "Red Hat":
        mr = _FANOUT_RHSA.match(rid)
        rid = mr.group(1) if mr else rid
    elif group == "Debian":
        rid = re.sub(r"^DEBIAN:", "", rid)
        rid = re.sub(r":[0-9A-F]+$", "", rid)
    elif group == "Alpine":
        rid = "ALPINE-" + re.sub(r"^ALPINE[:-]", "", rid)
    elif group == "Chainguard":
        rid = re.sub(r"^(CHAINGUARD|WOLFI):", "", rid)
    elif group == "FreeBSD":
        rid = re.sub(r"^FREEBSD_ADVISORY:", "", rid)
    elif group == "Azure Linux":          # CBLMARINER:83249 and AZL-83249 are one record
        rid = re.sub(r"^(CBLMARINER:|AZL-)", "AZL-", rid)
    elif group == "CloudLinux":           # CLSA-2026:177… and CLSA-2026-177… are one record
        rid = rid.replace(":", "-")
    return group, rid


# ── Fan-out, the accurate way: Vulners ``audit/cve`` ─────────────────────────
# ``POST /api/v4/audit/cve {"cve": id}`` returns ``affectedPackages``: one entry
# per fixed package per distro release — ``{id: advisory, name: package,
# range, registry, distro: [family, release]}``. That is the downstream
# picture at the resolution a fleet schedules it: a package update on a
# product release. Responses are cached for a day in DATA_DIR; the archive
# references (``fanout_breakdown``) stay as the offline fallback.
VULNERS_AUDIT_URL = "https://vulners.com/api/v4/audit/cve"
AUDIT_CACHE_BASENAME = "vulners_audit_cache.json"
AUDIT_CACHE_MAX_AGE_H = 24

# distro family (as ``audit/cve`` names it) -> product name on the slide
FANOUT_PRODUCTS = {
    "rhel": "Red Hat Enterprise Linux", "almalinux": "AlmaLinux", "rocky": "Rocky Linux",
    "ubuntu": "Ubuntu", "ubuntu-pro": "Ubuntu Pro (ESM)", "debian": "Debian",
    "sles": "SUSE Linux Enterprise (SLES)", "sled": "SUSE Linux Enterprise Desktop",
    "sle-rt": "SUSE Linux Enterprise Real Time", "sl-micro": "SUSE Linux Micro",
    "opensuse-leap": "openSUSE Leap", "opensuse-tumbleweed": "openSUSE Tumbleweed",
    "amzn": "Amazon Linux", "fedora": "Fedora", "oracle": "Oracle Linux", "oraclelinux": "Oracle Linux",
    "astra": "Astra Linux", "mageia": "Mageia", "openeuler": "openEuler", "alpine": "Alpine Linux",
    "wolfi": "Wolfi (Chainguard)", "chainguard": "Chainguard", "minimos": "MinimOS (Minimus)",
    "hummingbird": "Hummingbird", "freebsd": "FreeBSD", "photon": "VMware Photon OS",
    "gentoo": "Gentoo", "arch": "Arch Linux", "cbl-mariner": "Azure Linux", "azurelinux": "Azure Linux",
    "rosa": "ROSA Linux", "redos": "RED OS", "cloudlinux": "CloudLinux", "virtuozzo": "Virtuozzo",
}
FANOUT_REGISTRIES = {"golang": "Go modules", "npm": "npm", "pypi": "PyPI", "maven": "Maven",
                     "cargo": "crates.io", "rubygems": "RubyGems", "composer": "Packagist", "nuget": "NuGet"}
# Package-name suffixes that are the same build, not another product to patch.
_PKG_VARIANT_SUFFIX = re.compile(r"-(debuginfo|debugsource|devel|doc|docs|headers|source|dbg|dbgsym|common|libs)$")


def _audit_cache_path():
    return os.path.join(os.path.abspath(os.getenv("DATA_DIR") or os.getcwd()), AUDIT_CACHE_BASENAME)


def fetch_audit_cve(cve_id):
    """``audit/cve`` result for one CVE (``{"cve", "affectedPackages", "affectedCpe"}``),
    from the day's cache or the API. ``None`` without an API key or on failure —
    the caller falls back to the archive references."""
    path = _audit_cache_path()
    cache = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                cache = json.load(f)
        except (OSError, ValueError):
            cache = {}
    hit = cache.get(cve_id)
    if hit and isinstance(hit, dict) and "fetched" in hit:
        try:
            age_h = (datetime.now() - datetime.fromisoformat(hit["fetched"])).total_seconds() / 3600
        except ValueError:
            age_h = float("inf")
        if age_h < AUDIT_CACHE_MAX_AGE_H and hit.get("result") is not None:
            return hit["result"]
    api_key = os.getenv("VULNERS_API_KEY")
    if not api_key:
        print("VULNERS_API_KEY not set; fan-out slide falls back to archive references.")
        return hit.get("result") if hit else None
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=Retry(
        total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["POST"],
    )))
    try:
        r = session.post(
            VULNERS_AUDIT_URL, headers={"X-Api-Key": api_key, "Content-Type": "application/json"},
            json={"cve": cve_id}, timeout=60,
        )
        r.raise_for_status()
        result = r.json().get("result")
    except (requests.RequestException, ValueError) as e:
        print(f"audit/cve failed for {cve_id}: {e}")
        return hit.get("result") if hit else None
    if not isinstance(result, dict):
        return hit.get("result") if hit else None
    cache[cve_id] = {"fetched": datetime.now().isoformat(timespec="seconds"), "result": result}
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except OSError as e:
        print(f"Could not write {path}: {e}")
    return result


def fanout_packages(audit_result):
    """Downstream package updates per product, from an ``audit/cve`` result.

    One update = one package name on one product release; the same package
    listed under two advisories (a vendor's own id and OSV's mirror) is one
    update. Returns ``(rows, totals)``: ``rows`` sorted by updates, each
    ``{"product", "updates", "releases", "advisories", "packages": [base names by
    frequency]}``; ``totals`` = ``{"updates", "products", "releases", "advisories"}``.
    """
    per = {}
    all_releases, all_advisories, all_updates = set(), set(), set()
    for p in (audit_result or {}).get("affectedPackages") or []:
        if not isinstance(p, dict) or not p.get("name"):
            continue
        distro = p.get("distro") or []
        family = distro[0] if distro else None
        release = distro[1] if len(distro) > 1 else (family or p.get("registry") or "?")
        if family:
            product = FANOUT_PRODUCTS.get(family, family)
        else:
            product = FANOUT_REGISTRIES.get(p.get("registry"), f"{p.get('registry') or 'other'} packages")
        row = per.setdefault(product, {"updates": set(), "releases": set(), "advisories": set(),
                                       "packages": collections.Counter()})
        update = (release, p["name"])
        row["updates"].add(update)
        row["releases"].add(release)
        adv = _fanout_route_advisory(p.get("id"))
        row["advisories"].add(adv)
        row["packages"][_PKG_VARIANT_SUFFIX.sub("", p["name"])] += 1
        all_updates.add((product,) + update)
        all_releases.add((product, release))
        all_advisories.add(adv)
    rows = [{
        "product": product, "updates": len(r["updates"]), "releases": len(r["releases"]),
        "advisories": len(r["advisories"]),
        "packages": [n for n, _ in r["packages"].most_common()],
    } for product, r in per.items()]
    rows.sort(key=lambda r: (-r["updates"], r["product"]))
    totals = {"updates": len(all_updates), "products": len(rows), "releases": len(all_releases),
              "advisories": len(all_advisories)}
    return rows, totals


def _fanout_route_advisory(adv_id):
    """Canonical advisory id for an ``affectedPackages`` entry: OSV mirrors and
    Red Hat's per-CVE suffixes collapse onto the vendor's own id."""
    rid = str(adv_id or "").upper()
    rid = rid[4:] if rid.startswith("OSV:") else rid
    mr = _FANOUT_RHSA.match(rid)
    if mr:
        return mr.group(1)
    rid = re.sub(r"^DEBIAN:", "", rid)
    rid = re.sub(r":[0-9A-F]{5}$", "", rid)
    return rid


def fanout_breakdown(references):
    """Distinct downstream records per issuer for one CVE's
    ``enchantments.dependencies.references``. Returns ``{issuer: set(ids)}``."""
    groups = collections.defaultdict(set)
    for ref in references if isinstance(references, list) else ():
        if not isinstance(ref, dict):
            continue
        for rid in ref.get("idList") or []:
            routed = _fanout_route(ref.get("type"), rid)
            if routed:
                groups[routed[0]].add(routed[1])
    return dict(groups)


# ── Exploitation signals vs publication volume ───────────────────────────────
# CISA KEV additions by ``dateAdded`` are set against the monthly publication
# count; the catalog is fetched the way cve_epss_comparison.py does it, once a
# day into DATA_DIR. (The archive's ``wildExploited`` flag was tried as a second
# series and dropped: dated by its sources' ``firstSeen`` it spikes when a source
# is onboarded, and by publication month it says little the KEV series does not.)
EXPLOIT_START_MONTH = "2024-01"
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CATALOG_BASENAME = "known_exploited_vulnerabilities.json"


def download_cisa_kev(data_dir=None):
    """Path to today's copy of the CISA KEV catalog in ``data_dir`` (DATA_DIR by
    default); re-downloaded once a day, else the local copy is kept. ``None``
    when neither a download nor a local copy is available."""
    import urllib.error
    import urllib.request

    data_dir = os.path.abspath(data_dir or os.getenv("DATA_DIR") or os.getcwd())
    target_path = os.path.join(data_dir, KEV_CATALOG_BASENAME)
    if os.path.exists(target_path):
        if datetime.fromtimestamp(os.path.getmtime(target_path)).date() == datetime.now().date():
            return target_path
    print(f"Downloading CISA KEV catalog from: {KEV_CATALOG_URL}")
    try:
        req = urllib.request.Request(
            KEV_CATALOG_URL, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            payload = response.read()
        os.makedirs(data_dir, exist_ok=True)
        with open(target_path, "wb") as out_file:
            out_file.write(payload)
        return target_path
    except Exception as e:  # noqa: BLE001 - any failure falls back to the local copy
        print(f"Failed to download CISA KEV catalog: {e}")
        return target_path if os.path.exists(target_path) else None


def load_cisa_kev_cves(data_dir=None):
    """The set of CVE ids in the CISA KEV catalog (upper-cased), or an empty set
    when the catalog is unavailable. Ported from cve_epss_comparison.py."""
    path = download_cisa_kev(data_dir)
    if not path:
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print(f"Could not read KEV catalog {path}: {e}")
        return set()
    return {str(v.get("cveID")).upper().strip() for v in data.get("vulnerabilities", []) if v.get("cveID")}


def kev_additions_by_month(data_dir=None):
    """``{"YYYY-MM": additions}`` from the CISA KEV catalog's ``dateAdded``, plus
    the catalog's release date; ``({}, None)`` when the catalog is unavailable."""
    path = download_cisa_kev(data_dir)
    if not path:
        return {}, None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print(f"Could not read KEV catalog {path}: {e}")
        return {}, None
    counts = collections.Counter()
    for vuln in data.get("vulnerabilities", []):
        added = str(vuln.get("dateAdded") or "")
        if len(added) >= 7:
            counts[added[:7]] += 1
    return dict(counts), (data.get("dateReleased") or "")[:10] or None


# ── Kernel bug-fix discovery vs CVE publishing ───────────────────────────────
# HAND-TRANSCRIBED DATA. The top panel of the kernel-fixes slide is not in the
# archive: it comes from LWN's chart "Bugs introduced and fixed by release",
# Jonathan Corbet, "Development statistics for the 7.2 kernel", LWN.net,
# 2026-08-17, file fixes-7.2.svg (CC BY-SA 4.0). The SVG is matplotlib output,
# so the values below were read off its polylines against the y-axis ticks
# (0..4000, 38.786 px per 1000) rather than estimated by eye; they are still a
# transcription of a published chart, not LWN's underlying data, and are
# rounded to the nearest commit. One release = one x position, v4.0 .. v7.2.
# The four series carry LWN's own legend names.
# The article's text gives 4,830 commits with Fixes tags in 7.2; the chart's
# "Bugs Fixed" polyline reads 4,549 at 7.2 (and "Commits fixed" 4,306). The
# chart evidently counts on a narrower basis than the prose — likely only Fixes
# tags whose target commit lies within the plotted history. The slide draws the
# chart's numbers, since that is what was transcribed, and says so.
LWN_FIXES_SOURCE_URL = "https://lwn.net/Articles/1088776/"   # "Development statistics for the 7.2 kernel", 2026-08-17
LWN_FIXES_ARTICLE_72_COMMITS = 4830   # the prose figure, for the record; not drawn
LWN_FIXES_RELEASES = [
    "4.0", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8", "4.9", "4.10", "4.11", "4.12", "4.13",
    "4.14", "4.15", "4.16", "4.17", "4.18", "4.19", "4.20",
    "5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8", "5.9", "5.10", "5.11", "5.12", "5.13",
    "5.14", "5.15", "5.16", "5.17", "5.18", "5.19",
    "6.0", "6.1", "6.2", "6.3", "6.4", "6.5", "6.6", "6.7", "6.8", "6.9", "6.10", "6.11", "6.12", "6.13",
    "6.14", "6.15", "6.16", "6.17", "6.18", "6.19",
    "7.0", "7.1", "7.2",
]
LWN_FIXES_SERIES = {
    # green, thick — Fixes: tags in the release, i.e. bugs fixed
    "Bugs Fixed": [
        239, 272, 355, 361, 380, 400, 435, 598, 628, 785, 804, 991, 884, 927, 1073, 1201, 1198, 1056, 1088, 1161, 1208,
        1222, 1420, 1420, 1458, 1604, 1651, 1548, 1551, 1771, 1700, 2001, 1717, 1740, 1976, 1872, 1667, 2031, 1918, 1993, 1903,
        2112, 2211, 2334, 2089, 1951, 2029, 1991, 1793, 2036, 2134, 1910, 1923, 2151, 2021, 1958, 2036, 2043, 2041, 2121, 2197,
        2940, 3714, 4549,
    ],
    # blue, thin — distinct commits named by those Fixes: tags
    "Commits fixed": [
        229, 263, 345, 350, 365, 389, 427, 579, 607, 744, 765, 945, 853, 875, 1016, 1135, 1155, 1016, 1053, 1120, 1153,
        1165, 1357, 1378, 1398, 1506, 1573, 1472, 1473, 1660, 1602, 1894, 1635, 1690, 1886, 1787, 1564, 1933, 1827, 1885, 1820,
        2021, 2102, 2220, 1992, 1833, 1914, 1867, 1704, 1930, 2019, 1844, 1841, 2049, 1929, 1868, 1952, 1968, 1966, 2028, 2088,
        2797, 3547, 4306,
    ],
    # brown, thick — bugs introduced in the release (found so far)
    "Bugs introduced": [
        733, 754, 1216, 1100, 1015, 1100, 1353, 1219, 1636, 1555, 1494, 1452, 1725, 1455, 1580, 1621, 1559, 1485, 1497, 1788, 1743,
        1647, 1630, 1657, 1648, 1799, 1790, 1761, 1944, 1918, 1574, 1903, 1632, 1576, 1811, 1771, 1734, 1484, 1455, 1570, 1763,
        1699, 1353, 1422, 1430, 1342, 1387, 1265, 1336, 1698, 1197, 1144, 1295, 1110, 1029, 869, 1163, 1073, 818, 842, 839,
        548, 331, 1,
    ],
    # orange, thin — commits in the release later named by a Fixes: tag
    "Buggy commits introduced": [
        500, 546, 778, 707, 646, 725, 868, 767, 984, 924, 905, 876, 1035, 920, 969, 975, 967, 964, 964, 1060, 1087,
        1081, 1064, 1080, 1065, 1065, 1125, 989, 1161, 1228, 1051, 1173, 1028, 1002, 1141, 1099, 996, 992, 947, 1057, 1110,
        1042, 897, 905, 893, 919, 908, 861, 841, 950, 852, 765, 857, 737, 739, 605, 780, 726, 614, 607, 583,
        417, 273, 1,
    ],
}
# Mainline release dates, so the x-axis is time. 4.x and 5.16–5.19 from the
# kernel's release history; 5.0–5.15, 6.x and 7.x from the kernel.org tarball
# listing (mirrors.edge.kernel.org/pub/linux/kernel/v*.x/, which stamps the
# day after a Sunday release — a day's drift that does not show on this axis).
LWN_FIXES_RELEASE_DATES = {
    "4.0": "2015-04-12", "4.1": "2015-06-21", "4.2": "2015-08-30", "4.3": "2015-11-01", "4.4": "2016-01-10",
    "4.5": "2016-03-13", "4.6": "2016-05-15", "4.7": "2016-07-24", "4.8": "2016-10-02", "4.9": "2016-12-11",
    "4.10": "2017-02-19", "4.11": "2017-04-30", "4.12": "2017-07-02", "4.13": "2017-09-03", "4.14": "2017-11-12",
    "4.15": "2018-01-28", "4.16": "2018-04-01", "4.17": "2018-06-03", "4.18": "2018-08-12", "4.19": "2018-10-22",
    "4.20": "2018-12-23",
    "5.0": "2019-03-04", "5.1": "2019-05-06", "5.2": "2019-07-08", "5.3": "2019-09-16", "5.4": "2019-11-25",
    "5.5": "2020-01-27", "5.6": "2020-03-30", "5.7": "2020-06-01", "5.8": "2020-08-03", "5.9": "2020-10-12",
    "5.10": "2020-12-14", "5.11": "2021-02-15", "5.12": "2021-04-26", "5.13": "2021-06-28", "5.14": "2021-08-30",
    "5.15": "2021-10-31", "5.16": "2022-01-09", "5.17": "2022-03-20", "5.18": "2022-05-22", "5.19": "2022-07-31",
    "6.0": "2022-10-03", "6.1": "2022-12-12", "6.2": "2023-02-20", "6.3": "2023-04-24", "6.4": "2023-06-26",
    "6.5": "2023-08-27", "6.6": "2023-10-30", "6.7": "2024-01-08", "6.8": "2024-03-10", "6.9": "2024-05-13",
    "6.10": "2024-07-15", "6.11": "2024-09-15", "6.12": "2024-11-18", "6.13": "2025-01-20", "6.14": "2025-03-24",
    "6.15": "2025-05-26", "6.16": "2025-07-28", "6.17": "2025-09-29", "6.18": "2025-12-01", "6.19": "2026-02-09",
    "7.0": "2026-04-13", "7.1": "2026-06-14", "7.2": "2026-08-17",
}
KERNEL_FIXES_SERIES = "Bugs Fixed"     # the series drawn: Fixes: tags per release
KERNEL_FIXES_WINDOW_START = "2022-01-01"   # the archive's daily counts begin here
# The kernel's own CNA, as the dashboard names it (record ``cna``/``reporter``
# "Linux"); it began assigning CVEs in February 2024, so cycles before that
# carry no kernel CVEs and are excluded from the CVE plateau.
KERNEL_CNA = "Linux"
KERNEL_CNA_START = "2024-02-01"


def daily_publication_series(daily_counts, start_date, end_date):
    """Continuous daily publication counts from ``daily_counts[year][mm-dd]``
    between two ISO dates inclusive, as ``(dates, counts)``."""
    start = date.fromisoformat(start_date)
    end = date.fromisoformat(end_date[:10])
    dates, counts = [], []
    cur = start
    while cur <= end:
        dates.append(datetime(cur.year, cur.month, cur.day))
        counts.append(daily_counts.get(str(cur.year), {}).get(cur.strftime("%m-%d"), 0))
        cur += timedelta(days=1)
    return dates, counts


# ── EPSS: recency penalty and recall ─────────────────────────────────────────
# Two slides re-render panels of cve_epss_comparison.py's dashboards from the
# monthly pass. The archive side is collected here (``epss_rows``: one row per
# CVE of the last seven years — id, publication day, exploited-in-the-wild
# flag); the EPSS side is the daily score feeds from empiricalsec/epss_scores,
# fetched and read exactly as that script does (the helpers below are ported
# from it). The feeds are only touched when the slides render, i.e. locally.
EPSS_HIGH_CUTOFF = 0.10            # "EPSS flagged it": score at/above this
EPSS_FEED_BASE_URL = "https://raw.githubusercontent.com/empiricalsec/epss_scores/main"
AGING_SNAPSHOTS_BACK = 3           # snapshots at the anchor feed date, -1y, -2y, -3y
AGING_MAX_AGE = 3                  # cohort ages 0..3 tracked per snapshot
AGING_MAX_DATE_DRIFT_DAYS = 14     # reject a resolved snapshot further than this from target
EPSS_RECALL_YEARS_BACK = 3         # recall slide: anchor year and the three before it
# Rows are kept for cohorts the oldest snapshot can see: anchor year - 3 (oldest
# snapshot) - 3 (its oldest cohort).
EPSS_ROWS_YEARS_BACK = AGING_SNAPSHOTS_BACK + AGING_MAX_AGE


def _epss_data_dir():
    return os.path.abspath(os.getenv("DATA_DIR") or os.getcwd())


def download_latest_epss_scores(data_dir=None):
    """Path to the newest EPSS daily feed (today, walking back up to 7 days),
    downloaded into ``data_dir`` unless already there; falls back to the newest
    local feed. Ported from cve_epss_comparison.py."""
    import urllib.error
    import urllib.request

    data_dir = os.path.abspath(data_dir or _epss_data_dir())
    os.makedirs(data_dir, exist_ok=True)
    today = datetime.now()
    for i in range(7):
        date_check = today - timedelta(days=i)
        file_name = f"epss_scores-{date_check.strftime('%Y-%m-%d')}.csv.gz"
        target_path = os.path.join(data_dir, file_name)
        if os.path.exists(target_path) and os.path.getsize(target_path) > 0:
            return target_path
        url = f"{EPSS_FEED_BASE_URL}/{date_check.strftime('%Y')}/{file_name}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            with urllib.request.urlopen(req, timeout=15) as response:
                payload = response.read()
            with open(target_path, "wb") as out_file:
                out_file.write(payload)
            print(f"Downloaded EPSS feed {file_name}")
            return target_path
        except urllib.error.HTTPError as e:
            if e.code != 404:
                print(f"HTTP error downloading {file_name}: {e}")
        except Exception as e:  # noqa: BLE001
            print(f"Error downloading {file_name}: {e}")
    existing = sorted(glob.glob(os.path.join(data_dir, "epss_scores-*.csv.gz")))
    if existing:
        print(f"EPSS feed download failed; using newest local feed {os.path.basename(existing[-1])}")
        return existing[-1]
    raise RuntimeError("No EPSS feed could be downloaded and none is present locally.")


def download_historical_epss_scores(data_dir, target_date_str):
    """``(path, actual_date)`` for the EPSS feed nearest ``target_date_str``
    (exact day first, then ±1..7 days). Ported from cve_epss_comparison.py."""
    import urllib.error
    import urllib.request

    target_date = datetime.strptime(target_date_str, "%Y-%m-%d")
    for offset in [0] + [d for i in range(1, 8) for d in (-i, i)]:
        date_check = target_date + timedelta(days=offset)
        date_str = date_check.strftime("%Y-%m-%d")
        file_name = f"epss_scores-{date_str}.csv.gz"
        target_path = os.path.join(data_dir, file_name)
        if os.path.exists(target_path) and os.path.getsize(target_path) > 0:
            return target_path, date_str
        url = f"{EPSS_FEED_BASE_URL}/{date_check.strftime('%Y')}/{file_name}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            with urllib.request.urlopen(req, timeout=60) as response:
                payload = response.read()
            with open(target_path, "wb") as out_file:
                out_file.write(payload)
            print(f"Downloaded EPSS feed {file_name}")
            return target_path, date_str
        except urllib.error.HTTPError as e:
            if e.code != 404:
                print(f"HTTP error downloading {file_name}: {e}")
        except Exception as e:  # noqa: BLE001
            print(f"Error downloading {file_name}: {e}")
    existing = sorted(glob.glob(os.path.join(data_dir, target_date.strftime("epss_scores-%Y-*.csv.gz"))))
    if existing:
        best = existing[-1]
        return best, os.path.basename(best).replace("epss_scores-", "").replace(".csv.gz", "")
    raise RuntimeError(f"No EPSS feed near {target_date_str} could be downloaded and none is present locally.")


def load_epss_scores_csv(csv_gz_path):
    """``{CVE-ID: epss}`` from one daily feed. Ported from cve_epss_comparison.py."""
    epss_map = {}
    with gzip.open(csv_gz_path, "rt", encoding="utf-8") as f:
        first_line = f.readline()
        if not first_line.startswith("#"):
            f.seek(0)
        for row in csv.DictReader(f):
            cve = row.get("cve")
            epss_val = row.get("epss")
            if cve and epss_val is not None:
                try:
                    epss_map[cve.upper()] = float(epss_val)
                except ValueError:
                    pass
    return epss_map


def read_epss_model_version(csv_gz_path):
    """The feed's model version from its leading comment line, or ``None``."""
    try:
        with gzip.open(csv_gz_path, "rt", encoding="utf-8") as f:
            first_line = f.readline()
    except Exception:  # noqa: BLE001
        return None
    if not first_line.startswith("#"):
        return None
    mv = re.search(r"model_version\s*:\s*([^,\s]+)", first_line)
    return mv.group(1) if mv else None


def epss_date_from_filename(csv_gz_path):
    mv = re.search(r"epss_scores-(\d{4}-\d{2}-\d{2})\.csv\.gz$", os.path.basename(csv_gz_path or ""))
    return mv.group(1) if mv else None


def _shift_years(date_obj, years_back):
    try:
        return date_obj.replace(year=date_obj.year - years_back)
    except ValueError:
        return date_obj.replace(year=date_obj.year - years_back, day=28)


def resolve_aging_snapshots(data_dir, anchor_date_str, anchor_path):
    """The anchor feed plus ``AGING_SNAPSHOTS_BACK`` feeds exactly one year apart
    (oldest first), each ``{target, date, path, model_version}``; a feed that
    cannot be fetched or drifts too far from its target is skipped. Ported from
    cve_epss_comparison.py."""
    anchor_date = datetime.strptime(anchor_date_str, "%Y-%m-%d")
    snapshots = [{"target": anchor_date_str, "date": anchor_date_str, "path": anchor_path,
                  "model_version": read_epss_model_version(anchor_path)}]
    for years_back in range(1, AGING_SNAPSHOTS_BACK + 1):
        target_dt = _shift_years(anchor_date, years_back)
        target_str = target_dt.strftime("%Y-%m-%d")
        try:
            path, actual_date = download_historical_epss_scores(data_dir, target_str)
        except Exception as e:  # noqa: BLE001
            print(f"EPSS snapshot {target_str} unavailable ({e}); skipped.")
            continue
        drift = abs((datetime.strptime(actual_date, "%Y-%m-%d") - target_dt).days)
        if drift > AGING_MAX_DATE_DRIFT_DAYS:
            print(f"EPSS snapshot {target_str} resolved to {actual_date}, {drift} days off; skipped.")
            continue
        snapshots.append({"target": target_str, "date": actual_date, "path": path,
                          "model_version": read_epss_model_version(path)})
    snapshots.sort(key=lambda snap: snap["date"])
    return snapshots


def cohort_aging_from_rows(epss_rows, snapshots):
    """Phase two of cve_epss_comparison.py's ``load_epss_cohort_aging_data``, run
    over the rows the monthly pass already holds instead of a second archive
    scan: for every (snapshot, publication-year cohort) the scores that snapshot
    gave the cohort's CVEs published on or before the snapshot date. Returns
    ``{snapshot_date: {year: {"scores", "eligible", "missing"}}}``; one feed is
    loaded at a time."""
    for snap in snapshots:
        snap_year = int(snap["date"][:4])
        snap["cohort_years"] = [str(snap_year - age) for age in range(AGING_MAX_AGE + 1)]
    res = {}
    for snap in snapshots:
        snap_date = snap["date"]
        snap_years = set(snap["cohort_years"])
        epss_map = load_epss_scores_csv(snap["path"])
        snap["n_scores"] = len(epss_map)
        scores = {y: [] for y in snap_years}
        eligible = {y: 0 for y in snap_years}
        missing = {y: 0 for y in snap_years}
        for cve_key, published_day, _wild in epss_rows:
            year = published_day[:4]
            if year not in snap_years or published_day > snap_date:
                continue
            eligible[year] += 1
            epss_val = epss_map.get(cve_key)
            if epss_val is not None:
                scores[year].append(epss_val)
            else:
                missing[year] += 1
        del epss_map
        res[snap_date] = {
            year: {"scores": np.array(scores[year]), "eligible": eligible[year], "missing": missing[year]}
            for year in snap_years
        }
    return res


def calculate_cohort_aging_stats(aging_data, snapshots):
    """Ported verbatim in substance from cve_epss_comparison.py: share of each
    scored cohort at/above ``EPSS_HIGH_CUTOFF`` by publication year and by cohort
    age at scoring time, plus each snapshot's own oldest-to-newest fall."""
    cells = {}
    by_age = {age: {} for age in range(AGING_MAX_AGE + 1)}
    for snap in snapshots:
        snap_date = snap["date"]
        snap_year = int(snap_date[:4])
        cells[snap_date] = {}
        for year, bucket in aging_data[snap_date].items():
            year_scores = bucket["scores"]
            n_scored = len(year_scores)
            age = snap_year - int(year)
            if n_scored == 0:
                cells[snap_date][year] = None
                continue
            pct_ge_cutoff = float(np.sum(year_scores >= EPSS_HIGH_CUTOFF)) / n_scored * 100
            cells[snap_date][year] = {
                "age": age, "year": year, "n_scored": n_scored, "eligible": bucket["eligible"],
                "missing": bucket["missing"],
                "unscored_pct": bucket["missing"] / bucket["eligible"] * 100 if bucket["eligible"] else 0.0,
                "pct_ge_cutoff": pct_ge_cutoff,
                "median": float(np.median(year_scores)), "mean": float(np.mean(year_scores)),
            }
            by_age[age][snap_date] = pct_ge_cutoff
    age_spread = {}
    for age, per_snapshot in by_age.items():
        if per_snapshot:
            values = list(per_snapshot.values())
            age_spread[age] = {"min": min(values), "max": max(values), "spread": max(values) - min(values),
                               "mean": sum(values) / len(values), "n_snapshots": len(values)}
    oldest_age = max(age_spread) if age_spread else AGING_MAX_AGE
    drops = {}
    for snap_date, snap_cells in cells.items():
        snap_year = int(snap_date[:4])
        base = snap_cells.get(str(snap_year - oldest_age))
        newest = snap_cells.get(str(snap_year))
        if base and newest and base["pct_ge_cutoff"] > 0:
            ratio = newest["pct_ge_cutoff"] / base["pct_ge_cutoff"]
            drops[snap_date] = {"ratio": ratio, "drop_pct": (1 - ratio) * 100, "from_age": oldest_age}
    return {"cells": cells, "by_age": by_age, "age_spread": age_spread, "drops": drops, "oldest_age": oldest_age}


def epss_recall_by_year(epss_rows, epss_map, anchor_date, years, exploited_ids=None):
    """Per publication year, the same-period (Jan 1 → anchor month-day) sets
    cve_epss_comparison.py's overlap chart uses: CVEs the latest feed scores above
    ``EPSS_HIGH_CUTOFF`` and exploited CVEs, and the share of the exploited ones
    EPSS flagged (recall). "Exploited" is membership of ``exploited_ids`` (the
    CISA KEV catalog on the slide) when given, else the archive's wildExploited
    flag as the standalone script uses."""
    cutoff_md = anchor_date[5:10]
    out = []
    for year in years:
        epss_set, wild_set, pop = set(), set(), 0
        for cve_key, published_day, wild in epss_rows:
            if published_day[:4] != year or published_day[5:10] > cutoff_md:
                continue
            pop += 1
            val = epss_map.get(cve_key)
            if val is not None and val > EPSS_HIGH_CUTOFF:
                epss_set.add(cve_key)
            if (cve_key in exploited_ids) if exploited_ids is not None else wild:
                wild_set.add(cve_key)
        both = epss_set & wild_set
        out.append({
            "year": year, "pop": pop, "n_epss": len(epss_set), "n_wild": len(wild_set), "both": len(both),
            "epss_only": len(epss_set - wild_set), "expl_only": len(wild_set - epss_set),
            "recall": (len(both) / len(wild_set) * 100.0) if wild_set else 0.0,
        })
    return out, cutoff_md


# ── NVD status charts ────────────────────────────────────────────────────────
# Every CVE carries the NVD ``vulnStatus`` it was published with; these two
# charts count them by year and by week. Only the six NVD workflow statuses are
# drawn — "Reserved" (no status) and "Rejected" are never in the picture.
STATUS_START_YEAR = 2022            # the yearly bars start here
STATUS_WEEKLY_START = "2024-01-01"  # the weekly chart starts on the first Monday on/after
# Bottom-to-top stack order of the yearly bars and of the weekly areas.
STATUS_BAR_ORDER = ["Analyzed", "Modified", "Undergoing Analysis", "Awaiting Analysis", "Received", "Deferred"]
STATUS_STACK_ORDER = ["Deferred", "Analyzed", "Modified", "Undergoing Analysis", "Awaiting Analysis", "Received"]
STATUS_COLORS = {
    "Analyzed": "#1E90FF",            # Dodger Blue
    "Modified": "#70A1FF",            # Sky Blue
    "Undergoing Analysis": "#ECCC68", # Warm Yellow
    "Awaiting Analysis": "#FFA502",   # Orange
    "Received": "#FF4757",            # Vibrant Red
    "Deferred": "#747D8C",            # Slate Gray
}
# The statuses that mean "NVD has not looked at this yet".
STATUS_QUEUE = ("Undergoing Analysis", "Awaiting Analysis", "Received")

# ── Sankey lane colors ───────────────────────────────────────────────────────
# A lane's color belongs to its *place* in the ranking, not to the CNA's name.
# Keying it by name (as this did) leaves any CNA that climbs into the top 15
# without a color of its own — it fell through to the "Others" gray, the one
# color that means "not a ranked lane at all". Ranks are permanent; the CNAs
# holding them are not.
#
# The lanes are stacked in rank order, so rank N and rank N+1 always touch, and
# this order is the one that maximizes the separation of every touching pair —
# found by searching the orderings of these hues, with #FF4757 pinned to rank 1 so
# the dashboard's primary red stays on the biggest CNA and the "Others" gray held
# as the tail lane it always is. Against the dark #1E1E1E surface, worst adjacent
# ΔE 18.0 under protanopia/deuteranopia (target 8) and 24.8 under normal vision
# (floor 15), every lane ≥ 3:1 contrast — dataviz validate_palette.py, --mode dark.
# Re-run it if you touch the order; the old name-keyed palette scored 4.6/9.9.
SANKEY_RANK_COLORS = [
    "#FF4757",   # 1  Coral Red        (also C_RED, the dashboard's accent)
    "#FFBE1A",   # 2  Amber
    "#00D2D3",   # 3  Cyan
    "#FF9F43",   # 4  Bright Orange
    "#E84393",   # 5  Deep Pink
    "#F1C40F",   # 6  Yellow
    "#EE5253",   # 7  Red
    "#2E86DE",   # 8  Dodger Blue
    "#FF6B6B",   # 9  Light Coral
    "#6C5CE7",   # 10 Indigo
    "#10AC84",   # 11 Teal Green
    "#A55EEA",   # 12 Lavender Purple
    "#1DD1A1",   # 13 Mint
    "#9B59B6",   # 14 Amethyst Purple
    "#2ED573",   # 15 Light Green
]
SANKEY_OTHERS_COLOR = C_GRAY   # the pooled tail lane, and everyone below rank 15


def sankey_rank_colors(ranked_names):
    """Map top CNAs to their rank color. ``ranked_names`` must be in rank order."""
    return {
        name: SANKEY_RANK_COLORS[i]
        for i, name in enumerate(ranked_names[:len(SANKEY_RANK_COLORS)])
    }


def sankey_lane_colors(stack_order, rank_colors=None):
    """Color every lane of a Sankey stack, given its top-to-bottom order.

    The 15 rank colors are the only colors any Sankey uses: a CNA holding a rank
    wears that rank's color in every chart, which is what lets one be followed
    across them. A chart that names more CNAs than there are ranks — the
    incomplete-month one also names whoever leads the previous month or last
    year's column — paints those lanes in the "Others" gray, since being outside
    the top 15 is exactly what they have in common.
    """
    rank_colors = rank_colors or {}
    return {name: rank_colors.get(name, SANKEY_OTHERS_COLOR) for name in stack_order}


# ── Cumulative-chart geometry ────────────────────────────────────────────────
# The year-over-year cumulative chart is drawn at a *fixed* vertical scale: one
# inch of axes height is always _CUM_CVES_PER_INCH CVEs. A record year therefore
# makes the picture taller rather than squashing every earlier curve towards the
# floor — the whole point of the chart is that the gap between the years is
# legible, and an autoscaled axis erases exactly that as the top curve runs away.
#
# Growth cannot go on forever, so it stops once the saved PNG is square. From
# there the figure is frozen and the axis compresses the way an autoscaled one
# always would.
_CUM_FIG_W = 14.0            # inches; the chart's width never changes
_CUM_FIG_H_MIN = 9.0         # the shape the chart had before it started growing
_CUM_FIG_H_MAX = 14.151      # tallest figure whose tight-cropped PNG is square
_CUM_AXES_TOP_IN = 0.909     # inches reserved above the axes for the title
_CUM_AXES_BOTTOM_IN = 0.701  # inches below it: month ticks + the footer stamp
# 50,571 CVEs — 2025's full-year total plus the headroom below — over 7.3905in of
# axes. That is the scale the chart already had when this was introduced, so
# locking it left the picture of the day untouched and only bites later.
_CUM_CVES_PER_INCH = 6842.8
_CUM_HEADROOM = 1.05         # blank space kept above the tallest curve

# ── Publishing-speed-chart geometry ──────────────────────────────────────────
# Same idea for the YoY publishing-speed chart: one inch of axes height is always
# _SPEED_PER_INCH CVEs/day, so a faster year lifts the red curve off the blue one
# instead of pressing both towards the floor, and the two years stay comparable
# against the same ruler from one run to the next. It grows until the saved PNG
# is square, then the figure is frozen and the axis compresses as before.
_SPEED_FIG_W = 14.0            # inches; the chart's width never changes
_SPEED_FIG_H_MIN = 7.0         # the shape the chart had before it started growing
_SPEED_FIG_H_MAX = 14.085      # tallest figure whose tight-cropped PNG is square
_SPEED_AXES_TOP_IN = 0.6467    # inches reserved above the axes for the title
_SPEED_AXES_BOTTOM_IN = 0.6406 # inches below it: month ticks + the footer stamp
# 346.7 CVEs/day — the 2026 peak of the 30-day average plus the headroom below —
# over 5.7127in of axes, i.e. the scale the chart already had when this was
# introduced. Locking it left the picture of the day untouched.
_SPEED_PER_INCH = 60.69
_SPEED_HEADROOM = 1.05         # blank space kept above the fastest curve

# Monthly-flow Sankey: the two text gutters flanking the columns. Both hold text
# sized in points, so they are reserved in inches and converted to data units at
# draw time (see ``plot_custom_sankey_flow``) — a data-unit margin would mean
# something different in January than in December. The left gutter holds the CNA
# names, the right the last column's values, the cumulative ruler, and the
# overhang of the last header, which is the widest of them ("Aug 1-15" while the
# month is still running).
_SANKEY_GUTTER_IN = 2.55     # inches reserved left of the first column
_SANKEY_VALUES_IN = 1.45     # inches reserved right of the last column

# Monthly-flow Sankey: the vertical frame. The columns all hang from
# ``_SANKEY_Y_TOP`` and the busiest one reaches ``_SANKEY_Y_FLOOR``, which fixes
# the CVEs-per-y-unit scale for the whole picture; everything below the floor is
# the room the callout and the logo sit in. The figure is sized so the y unit
# keeps the value it had at 17.5in (66.86 units per inch) — point-sized text then
# occupies the same fraction of the picture as before, and the extra height goes
# entirely to the bands, which is what it was asked for.
_SANKEY_FIG_W = 19.25
_SANKEY_FIG_H = 20.5
_SANKEY_Y_TOP = 985.0        # the shared baseline every column starts from
_SANKEY_Y_FLOOR = -205.0     # where the busiest column's underside lands
_SANKEY_Y_BOTTOM = -250.0    # bottom of the axis
# Lanes are separated by shrinking each band inward by this much rather than by
# spacing them apart: spacing would push every boundary below it off the CVE
# scale, an inset costs no layout at all. ``_SANKEY_MIN_BAND`` keeps a lane too
# thin to survive the inset visible as a hairline.
_SANKEY_BAND_INSET = 1.8
_SANKEY_MIN_BAND = 1.0
_SANKEY_LABEL_MIN_H = 12.5   # y units a lane needs before its value is printed
_SANKEY_CALLOUT_Y = 5.0      # where the callout sits inside the empty wedge
# How close to a whole reference month still counts as carrying one. The callout
# names the *fewest* CNAs that clear this: three names that come to nine tenths
# of January is the sharper sentence, and a fourth that tips the sum over the
# line only blunts it.
_SANKEY_ALMOST = 0.85


def _spread_label_ys(targets, min_gap, lo, hi):
    """Nudge labels apart without reordering them.

    ``targets`` is the y each label wants — its lane's center — listed
    top-to-bottom; the return is the y each one gets: as close to its target as
    a ``min_gap`` spacing inside ``[lo, hi]`` allows. Lanes drawn to a true
    scale stack the small ones far tighter than their own text, and this is what
    keeps that text readable without handing those lanes height they did not
    earn.
    """
    ys = list(targets)
    n = len(ys)
    if n == 0:
        return ys
    for i in range(1, n):                 # settle downward from the top
        ys[i] = min(ys[i], ys[i - 1] - min_gap)
    ys[-1] = max(ys[-1], lo)              # then back up off the floor
    for i in range(n - 2, -1, -1):
        ys[i] = max(ys[i], ys[i + 1] + min_gap)
    ys[0] = min(ys[0], hi)                # and down again if that broke the ceiling
    for i in range(1, n):
        ys[i] = min(ys[i], ys[i - 1] - min_gap)
    return ys

# ── Watermark logo ───────────────────────────────────────────────────────────
# Square, transparent-background Vulners logo, overlaid bottom-left on every
# chart. Drop the file at src/assets/vulners_logo.png; if it is missing the
# charts simply render without it (a one-time note is printed).
_LOGO_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "assets", "vulners_logo.png"
)  # -> src/assets/vulners_logo.png
# Sized as a fraction of figure width so it looks the same on every chart when
# the page scales each image to the same on-screen width. Tune these two if the
# real logo reads too big/small. Height is derived to keep the square undistorted.
_LOGO_WIDTH_FRAC = 0.04      # logo width as a fraction of the figure width
_LOGO_MARGIN_X_FRAC = 0.006  # gap from the left edge, fraction of figure width
_LOGO_MARGIN_Y_FRAC = 0.010  # gap from the bottom edge, fraction of figure height
_logo_cache = None           # None = not loaded; False = missing/failed; array = loaded


def _load_logo():
    global _logo_cache
    if _logo_cache is None:
        if os.path.exists(_LOGO_PATH):
            try:
                _logo_cache = mpimg.imread(_LOGO_PATH)
            except Exception as e:  # noqa: BLE001
                print(f"Could not load logo {_LOGO_PATH}: {e}")
                _logo_cache = False
        else:
            print(f"Logo not found at {_LOGO_PATH}; charts render without it.")
            _logo_cache = False
    return _logo_cache if _logo_cache is not False else None


def _add_logo(fig, corners=("bottom-left",)):
    """Overlay the square logo in the given figure corner(s), same physical size
    on every chart (figure-fraction sizing keeps it undistorted)."""
    logo = _load_logo()
    if logo is None:
        return
    fw, fh = fig.get_size_inches()
    aspect = fw / fh
    w = _LOGO_WIDTH_FRAC              # fraction of width
    h = _LOGO_WIDTH_FRAC * aspect     # fraction of height -> physically square
    mx = _LOGO_MARGIN_X_FRAC
    my = _LOGO_MARGIN_Y_FRAC
    for corner in corners:
        x0 = mx if "left" in corner else 1 - mx - w
        y0 = my  # bottom
        ax_logo = fig.add_axes([x0, y0, w, h], zorder=1000)
        ax_logo.imshow(logo, interpolation="antialiased")
        ax_logo.axis("off")


def _cumulative_layout(max_total):
    """Axis top and figure height for a cumulative chart peaking at ``max_total``.

    Returns ``(y_top, fig_h)``. The height tracks the data at a fixed
    CVEs-per-inch scale until the picture is square; beyond that the figure is
    pinned at its maximum and the caller's axis simply holds more per inch.
    """
    y_top = max(max_total, 1) * _CUM_HEADROOM
    chrome = _CUM_AXES_TOP_IN + _CUM_AXES_BOTTOM_IN
    fig_h = chrome + y_top / _CUM_CVES_PER_INCH
    return y_top, min(max(fig_h, _CUM_FIG_H_MIN), _CUM_FIG_H_MAX)


def _speed_layout(max_speed):
    """Axis top and figure height for the speed chart peaking at ``max_speed``.

    The cumulative chart's rule (see ``_cumulative_layout``) applied to CVEs/day:
    a fixed number of CVEs/day per inch of axes until the picture is square,
    then a frozen figure and an axis that holds more per inch.
    """
    y_top = max(max_speed, 1) * _SPEED_HEADROOM
    chrome = _SPEED_AXES_TOP_IN + _SPEED_AXES_BOTTOM_IN
    fig_h = chrome + y_top / _SPEED_PER_INCH
    return y_top, min(max(fig_h, _SPEED_FIG_H_MIN), _SPEED_FIG_H_MAX)


def _pin_axes_height(fig, ax, top_in, bottom_in):
    """Freeze the axes' vertical extent to absolute inches.

    ``tight_layout`` sizes its padding as a *fraction* of the figure, which would
    quietly change the units-per-inch scale the moment the figure grows taller.
    The horizontal box it worked out is kept as-is — that one should keep
    following the width of the y tick labels, which do get wider as the counts
    gain a digit.
    """
    _, fig_h = fig.get_size_inches()
    pos = ax.get_position()
    ax.set_position([
        pos.x0,
        bottom_in / fig_h,
        pos.width,
        (fig_h - top_in - bottom_in) / fig_h,
    ])


# Plotting functions below append their saved-file messages here. Kept so those
# functions stay byte-for-byte identical to the original; not shown on the site.
saved_files_log = []


def _stamp():
    """Footer stamp: when the charts were drawn *and* what date the data runs to.

    The build date alone is misleading — the counts stop at the anchor (the last
    full day) and the upstream archive dump is cut a few hours before that, so a
    rebuild always advances "Generated on" even when nothing new has landed.
    Printing both makes a flat day read as flat data, not a broken build.
    """
    today = datetime.now().strftime("%Y-%m-%d")
    if not _DATA_THROUGH:
        return f"Generated on {today}"
    return f"Generated on {today} | Data through {_DATA_THROUGH}"


def count_monthly_cves(file_path, cut_off_date=None):
    """
    Counts CVEs published month-by-month for 2022 to 2026 using ijson.
    """
    # stats[month_str][year_str][cna_name] = count
    stats = collections.defaultdict(
        lambda: collections.defaultdict(collections.Counter)
    )
    # partial_stats[month_str][year_str][cna_name] = count (up to current day)
    partial_stats = collections.defaultdict(
        lambda: collections.defaultdict(collections.Counter)
    )
    # daily_counts_2025[month_day_str] = count
    daily_counts_2025 = collections.Counter()
    # daily_counts_2026[month_day_str] = count
    daily_counts_2026 = collections.Counter()
    # daily_cna_counts_2026[cna_name][month_day_str] = count
    daily_cna_counts_2026 = collections.defaultdict(collections.Counter)
    # daily_counts[year_str][month_day_str] = count
    daily_counts = collections.defaultdict(collections.Counter)
    # daily_counts_kernel[year_str][month_day_str] = count, kernel CNA only
    daily_counts_kernel = collections.defaultdict(collections.Counter)
    # candidate_stats["YYYY-MM"] = {"active", "rejected", "ref_types": Counter}
    # The "hidden" reserved/candidate CVEs, excluded from the main counts.
    candidate_stats = collections.defaultdict(
        lambda: {"active": 0, "rejected": 0, "ref_types": collections.Counter()}
    )
    # status_yearly[year_str][vulnStatus] and status_weekly[monday_iso][vulnStatus]
    # = count, for the NVD status charts. Counted over every record, candidates
    # and all, the way the standalone cve_status_stats.py did, so those two
    # pictures keep their numbers when drawn from here.
    status_yearly = collections.defaultdict(collections.Counter)
    status_weekly = collections.defaultdict(collections.Counter)
    # chrome_cves: one row per Chrome-CNA CVE of the anchor year —
    # {"id", "day", "advisories": [GCSA ids], "versions": [Chrome versions]}.
    chrome_cves = []
    # fanout_records[cve_id] = the archive record's facts the fan-out slide and
    # its shortlist CSV need, for FANOUT_CVE and every FANOUT_SHORTLIST entry.
    fanout_records = {}
    fanout_wanted = set(FANOUT_SHORTLIST) | {FANOUT_CVE}
    # epss_rows: (CVE id, publication day, exploited-in-the-wild flag) for every
    # kept CVE of the last EPSS_ROWS_YEARS_BACK+1 years, for the EPSS slides.
    epss_rows = []

    if cut_off_date:
        now = datetime.strptime(cut_off_date, "%Y-%m-%d")
        print(f"Limiting analysis to custom cut-off date: {cut_off_date}")
        current_month_int = now.month
        current_month_str = f"{current_month_int:02d}"
        current_day = now.day
    else:
        today = datetime.now()
        now = today - timedelta(days=1)
        print(f"Limiting analysis to last full date: {now.strftime('%Y-%m-%d')}")
        current_month_int = today.month
        current_month_str = f"{current_month_int:02d}"
        current_day = now.day

    anchor_date_str = now.strftime("%Y-%m-%d")
    anchor_year = anchor_date_str[:4]

    # True when the anchor lands on the last day of its month, i.e. the month the
    # data ends in is *finished*. That is what a run on the 1st sees (the anchor
    # is the last full day, so yesterday closed out the previous month), and what
    # the pinned year-end cut-off sees. In that case there is no running partial
    # month: the anchor month is presented as a completed month everywhere —
    # counted as fact in the projection, drawn full-width in the Sankeys.
    anchor_month_complete = (now + timedelta(days=1)).month != now.month

    global _DATA_THROUGH
    _DATA_THROUGH = anchor_date_str

    total_processed = 0
    relevant_found = 0

    abs_file_path = os.path.abspath(file_path)
    if not os.path.exists(file_path):
        print(f"Error: File {abs_file_path} not found.")
        return None

    file_size = os.path.getsize(file_path)
    print(f"Scanning file: {abs_file_path} ({file_size / (1024**3):.2f} GB)")

    start_time = time.time()

    try:
        with open(file_path, "rb") as f:
            parser = ijson.items(f, "item")

            for item in parser:
                total_processed += 1

                published_date = item.get("published")
                vuln_status = item.get("vulnStatus")
                reporter = item.get("reporter")

                is_rejected = bool(vuln_status) and vuln_status.lower() == "rejected"
                is_candidate = bool(reporter) and reporter.lower() == "candidate"

                if item.get("id") in fanout_wanted:
                    ench = item.get("enchantments")
                    deps = ench.get("dependencies") if isinstance(ench, dict) else None
                    refs = deps.get("references") if isinstance(deps, dict) else None
                    refs = refs if isinstance(refs, list) else []
                    fanout_records[item["id"]] = {
                        "id": item["id"],
                        "published": (published_date or "")[:10],
                        "reporter": reporter,
                        "short": (ench.get("short_description") if isinstance(ench, dict) else None) or "",
                        "software": sorted({
                            str(a.get("name") or a.get("cpeName") or "")
                            for a in (item.get("affectedSoftware") or []) if isinstance(a, dict)
                        }),
                        "kev": any(isinstance(r, dict) and r.get("type") == "vulncheck_kev" for r in refs),
                        "references": [
                            {"type": r.get("type"), "idList": [str(i) for i in (r.get("idList") or [])]}
                            for r in refs if isinstance(r, dict)
                        ],
                    }

                if (
                    published_date and len(published_date) >= 10
                    and published_date[:10] <= anchor_date_str
                    and published_date[:4].isdigit()
                    and int(published_date[:4]) >= STATUS_START_YEAR
                ):
                    try:
                        pub_day = date(
                            int(published_date[:4]), int(published_date[5:7]), int(published_date[8:10])
                        )
                    except ValueError:
                        pub_day = None
                    if pub_day is not None:
                        status_key = vuln_status or "Reserved"
                        status_yearly[published_date[:4]][status_key] += 1
                        week_start = pub_day - timedelta(days=pub_day.weekday())
                        status_weekly[week_start.isoformat()][status_key] += 1

                # Candidate (reserved / not-yet-published) CVEs are excluded from
                # the main counts, but tracked separately as the "hidden" volume:
                # active vs rejected, plus OSV/GitHub reference presence, by month
                # of the current year up to the anchor date.
                if is_candidate:
                    if (
                        published_date and len(published_date) >= 10
                        and published_date[:4] == anchor_year
                        and published_date[:10] <= anchor_date_str
                    ):
                        mkey = published_date[:7]
                        candidate_stats[mkey]["rejected" if is_rejected else "active"] += 1
                        # Count each source once per CVE (presence, not reference
                        # multiplicity) so overlapping refs don't double-count.
                        ench = item.get("enchantments")
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
                                        candidate_stats[mkey]["ref_types"][t] += 1
                    continue

                if is_rejected:
                    continue

                if (
                    published_date and len(published_date) >= 10 and item.get("id")
                    and published_date[:4].isdigit()
                    and int(published_date[:4]) >= int(anchor_year) - EPSS_ROWS_YEARS_BACK
                    and published_date[:10] <= anchor_date_str
                ):
                    ench = item.get("enchantments")
                    expl = ench.get("exploitation") if isinstance(ench, dict) else None
                    epss_rows.append((
                        str(item["id"]).upper(), published_date[:10],
                        isinstance(expl, dict) and expl.get("wildExploited") is True,
                    ))

                if published_date and len(published_date) >= 10:
                    year = published_date[:4]
                    month = published_date[5:7]
                    day = int(published_date[8:10])
                    record_date_str = published_date[:10]

                    if record_date_str > anchor_date_str:
                        continue

                    if year in ["2022", "2023", "2024", "2025", "2026"]:
                        cna_name = item.get("cna") or reporter or "Unknown"

                        if cna_name == CHROME_CNA and year == anchor_year:
                            advisories, versions = [], set()
                            ench = item.get("enchantments")
                            deps = ench.get("dependencies") if isinstance(ench, dict) else None
                            refs = deps.get("references") if isinstance(deps, dict) else None
                            for ref in refs if isinstance(refs, list) else ():
                                if not isinstance(ref, dict):
                                    continue
                                if ref.get("type") == "chrome":
                                    advisories.extend(str(i) for i in ref.get("idList") or [])
                                elif ref.get("type") == "nessus":
                                    for plugin in ref.get("idList") or []:
                                        mv = _CHROME_NESSUS_VER.match(str(plugin))
                                        if mv:
                                            versions.add(".".join(mv.groups()))
                            chrome_cves.append({
                                "id": item.get("id"),
                                "day": record_date_str,
                                "advisories": advisories,
                                "versions": sorted(versions),
                            })

                        # Store in full monthly stats
                        stats[month][year][cna_name] += 1
                        if cna_name == KERNEL_CNA:
                            daily_counts_kernel[year][f"{month}-{day:02d}"] += 1

                        # Store in partial stats if within the same day-range as current date
                        if day <= current_day:
                            partial_stats[month][year][cna_name] += 1

                        # Store daily counts for plotting
                        day_key = f"{month}-{day:02d}"
                        daily_counts[year][day_key] += 1
                        if year == "2025":
                            daily_counts_2025[day_key] += 1
                        elif year == "2026":
                            daily_counts_2026[day_key] += 1
                            daily_cna_counts_2026[cna_name][day_key] += 1

                        relevant_found += 1

    except ijson.common.IncompleteJSONError as e:
        print(f"\nError: File parsing ended prematurely: {e}")
        print(f"The data file '{abs_file_path}' is corrupted/incomplete.")
        try:
            os.remove(file_path)
            print("Successfully deleted the corrupted file. Please re-run the script to perform a clean download.")
        except Exception as remove_err:
            print(f"Failed to delete the corrupted file: {remove_err}")
        return None

    duration = time.time() - start_time
    print(f"Scan completed in {duration:.2f} seconds.")
    print(f"Total records processed: {total_processed:,}")
    print(f"Total 2022-2026 CVEs found: {relevant_found:,}")

    return {
        "stats": stats,
        "partial_stats": partial_stats,
        "current_month": current_month_str,
        "current_day": current_day,
        "anchor_date": anchor_date_str,
        "anchor_month_complete": anchor_month_complete,
        "daily_counts_2025": daily_counts_2025,
        "daily_counts_2026": daily_counts_2026,
        "daily_counts": daily_counts,
        "daily_counts_kernel": daily_counts_kernel,
        "daily_cna_counts_2026": daily_cna_counts_2026,
        "candidate_stats": candidate_stats,
        "status_yearly": status_yearly,
        "status_weekly": status_weekly,
        "chrome_cves": chrome_cves,
        "fanout_records": fanout_records,
        "epss_rows": epss_rows,
    }


def make_incomplete_month_printer(
    month_name,
    data_2025_full,
    data_2025_partial,
    data_2026_partial,
    curr_ytd_2025,
    curr_ytd_2026,
    range_label,
    anchor_date,
    prev_data_2026_full,
    prev_others_count,
):
    """
    Creates and returns a callback function to print comparison stats for an incomplete month.
    Using a factory function avoids closure cell variables defined in a loop and avoids
    mutable default arguments.
    """
    def print_incomplete_month():
        print(f"\n{'=' * 20} Incomplete Month: {month_name} {'=' * 20}")
        print_combined_incomplete_month_table(
            f"Combined Stats for {month_name} (Incomplete)",
            data_2025_full,
            data_2025_partial,
            data_2026_partial,
            curr_ytd_2025,
            curr_ytd_2026,
            f"{month_name} '25",
            f"2025 ({range_label})",
            f"2026 ({range_label})",
            anchor_date,
            print_table=True,
            prev_data_2026_full=prev_data_2026_full,
            prev_others_count=prev_others_count,
        )
    return print_incomplete_month


def print_all_months_table(
    full_months,
    anchor_date,
    stats=None,
    partial_stats=None,
    current_month_str=None,
    incomplete_month_print_fn=None,
    current_month_is_partial=True,
):
    """
    Prints one compact 4-column sub-table per month (CNA | 2025 | 2026 | YoY%)
    followed by a cross-month totals summary.
    full_months: list of (month_str, month_name, data_2025, data_2026)

    ``current_month_is_partial`` is False when the data anchor closed out its
    month (a run on the 1st, or the pinned year-end cut-off): there is then no
    month-to-date to report, every month with data is already in ``full_months``,
    and the projections start at the month after the last of them.
    """
    if not full_months:
        return set()

    # Check if the current month actually has any 2026 records. If not, suppress incomplete month logic.
    current_month_has_data = False
    if (
        current_month_is_partial
        and current_month_str and stats and current_month_str in stats
        and "2026" in stats[current_month_str]
    ):
        current_month_has_data = sum(stats[current_month_str]["2026"].values()) > 0

    # Collect all CNAs across all months
    all_cnas = set()
    for _, _, d25, d26 in full_months:
        all_cnas |= d25.keys()
        all_cnas |= d26.keys()

    combined = []
    for cna in all_cnas:
        row = {"name": cna, "total_26": 0, "total_25": 0}
        for month_str, _, d25, d26 in full_months:
            v25 = d25.get(cna, 0)
            v26 = d26.get(cna, 0)
            row[f"25_{month_str}"] = v25
            row[f"26_{month_str}"] = v26
            row["total_25"] += v25
            row["total_26"] += v26
        combined.append(row)

    def fmt_yoy(curr, prev):
        if prev > 0:
            val = ((curr - prev) / prev) * 100
            return f"{val:+7.1f}%"
        return "   N/A  " if curr == 0 else "  +Inf  "

    # ── Per-month sub-tables ─────────────────────────────────────────────────
    print(f"\nFull Month Comparison \u2014 By Month (As of {anchor_date})")

    all_top_names = set()

    for month_str, month_name, d25, d26 in full_months:
        lbl_25 = f"{month_name[:3]} '25"
        lbl_26 = f"{month_name[:3]} '26"
        lbl_yoy = "YoY %"

        # Identify all CNAs in this specific month
        month_cnas = set(d25.keys()) | set(d26.keys())
        month_rows = []
        for cna in month_cnas:
            month_rows.append({
                "name": cna,
                "v25": d25.get(cna, 0),
                "v26": d26.get(cna, 0)
            })

        # Top CNAs: any CNA in the Top-N for this month in 2025 or 2026
        top_25 = sorted(month_rows, key=lambda x: x["v25"], reverse=True)[:TOP_N]
        top_26 = sorted(month_rows, key=lambda x: x["v26"], reverse=True)[:TOP_N]

        month_top_names = set()
        month_top_names |= {r["name"] for r in top_25 if r["v25"] > 0}
        month_top_names |= {r["name"] for r in top_26 if r["v26"] > 0}
        all_top_names |= month_top_names

        top_rows = [r for r in month_rows if r["name"] in month_top_names]
        other_rows = [r for r in month_rows if r["name"] not in month_top_names]

        # Sort top rows by 2026 volume for this month
        top_rows.sort(key=lambda x: x["v26"], reverse=True)

        rows_fmt = []
        if other_rows:
            v25_oth = sum(r["v25"] for r in other_rows)
            v26_oth = sum(r["v26"] for r in other_rows)
            c25_oth = sum(1 for r in other_rows if r["v25"] > 0)
            c26_oth = sum(1 for r in other_rows if r["v26"] > 0)
            rows_fmt.append({
                "name": "Others",
                "s25": f"{v25_oth:,} ({c25_oth})" if c25_oth > 0 else "0",
                "s26": f"{v26_oth:,} ({c26_oth})" if c26_oth > 0 else "0",
                "yoy": fmt_yoy(v26_oth, v25_oth)
            })

        for r in top_rows:
            rows_fmt.append({
                "name": r["name"],
                "s25": f"{r['v25']:,}",
                "s26": f"{r['v26']:,}",
                "yoy": fmt_yoy(r["v26"], r["v25"])
            })

        g25 = sum(r["v25"] for r in month_rows)
        g26 = sum(r["v26"] for r in month_rows)
        tot_fmt = {
            "name": "Total",
            "s25": f"{g25:,}",
            "s26": f"{g26:,}",
            "yoy": fmt_yoy(g26, g25),
        }

        name_w = 35
        w25 = max(
            len(lbl_25),
            max((len(r["s25"]) for r in rows_fmt), default=0),
            len(tot_fmt["s25"]),
        )
        w26 = max(
            len(lbl_26),
            max((len(r["s26"]) for r in rows_fmt), default=0),
            len(tot_fmt["s26"]),
        )
        wyoy = max(
            len(lbl_yoy),
            max((len(r["yoy"]) for r in rows_fmt), default=0),
            len(tot_fmt["yoy"]),
        )
        sep = name_w + 3 + w25 + 3 + w26 + 3 + wyoy

        print(f"\n  \u2500\u2500 {month_name} \u2500\u2500")
        print(f"  {chr(45) * sep}")
        print(
            f"  {'CNA Name':<{name_w}} | {lbl_25:>{w25}} | {lbl_26:>{w26}} | {lbl_yoy:>{wyoy}}"
        )
        print(f"  {chr(45) * sep}")
        for r in rows_fmt:
            print(
                f"  {r['name']:<{name_w}} | {r['s25']:>{w25}} | {r['s26']:>{w26}} | {r['yoy']:>{wyoy}}"
            )
        print(f"  {chr(45) * sep}")
        print(
            f"  {tot_fmt['name']:<{name_w}} | {tot_fmt['s25']:>{w25}} | {tot_fmt['s26']:>{w26}} | {tot_fmt['yoy']:>{wyoy}}"
        )

    # ── Cross-month totals summary with trend projection ──────────────────────
    lbl_mon = "Month"
    lbl_25t = "2025 Total"
    lbl_26t = "2026 Total"
    lbl_yoyt = "YoY %"
    lbl_mom = "MoM Pred"
    lbl_momp = "MoM %"

    completed_month_strs = [m[0] for m in full_months]
    n = len(full_months)
    
    # Calculate completed month YoY growth rates to fit the trend line
    x_coords = []
    y_coords = []
    for idx, (month_str, _, _, _) in enumerate(full_months, 1):
        g25 = sum(r[f"25_{month_str}"] for r in combined)
        g26 = sum(r[f"26_{month_str}"] for r in combined)
        x_coords.append(idx)
        y_coords.append((g26 - g25) / g25 if g25 > 0 else 0.0)

    slope = 0.0
    intercept = 0.0
    if n >= 2:
        mean_x = sum(x_coords) / n
        mean_y = sum(y_coords) / n
        num = sum((x_coords[i] - mean_x) * (y_coords[i] - mean_y) for i in range(n))
        den = sum((x_coords[i] - mean_x) ** 2 for i in range(n))
        if den != 0:
            slope = num / den
            intercept = mean_y - slope * mean_x
        else:
            intercept = mean_y
    elif n == 1:
        intercept = y_coords[0]

    months_map = {
        "01": "January", "02": "February", "03": "March", "04": "April",
        "05": "May", "06": "June", "07": "July", "08": "August",
        "09": "September", "10": "October", "11": "November", "12": "December"
    }

    # Recursive Month-on-Month (MoM) prediction calculations
    def get_month_total(year_str, month_str):
        if stats and month_str in stats and year_str in stats[month_str]:
            return sum(stats[month_str][year_str].values())
        return 0

    months_list = [f"{i:02d}" for i in range(1, 13)]
    prev_month_map = {
        "01": ("12", "2025", "2024"),
        "02": ("01", "2026", "2025"),
        "03": ("02", "2026", "2025"),
        "04": ("03", "2026", "2025"),
        "05": ("04", "2026", "2025"),
        "06": ("05", "2026", "2025"),
        "07": ("06", "2026", "2025"),
        "08": ("07", "2026", "2025"),
        "09": ("08", "2026", "2025"),
        "10": ("09", "2026", "2025"),
        "11": ("10", "2026", "2025"),
        "12": ("11", "2026", "2025"),
    }

    # Calculate average YoY growth factor acceleration from completed months
    yoy_factors = []
    for ms in completed_month_strs:
        g25 = get_month_total("2025", ms)
        g26 = get_month_total("2026", ms)
        if g25 > 0:
            yoy_factors.append(g26 / g25)

    # Pivot of the MoM prediction chain: the first month with no actuals of its
    # own. That is the running month while one exists; once the anchor month has
    # closed it is simply the month after the last completed one (and "13" — i.e.
    # never — when the year itself is complete).
    if current_month_is_partial:
        cur_month_str = current_month_str or "13"
    else:
        nxt = int(completed_month_strs[-1]) + 1 if completed_month_strs else 13
        cur_month_str = f"{nxt:02d}" if nxt <= 12 else "13"

    # If the current month has data, compute its actual partial YoY factor
    # and include it as a "fact" in the acceleration trend calculation
    current_month_yoy_factor = None
    if current_month_has_data and partial_stats and cur_month_str != "13":
        partial_25 = sum(partial_stats[cur_month_str]["2025"].values()) if (cur_month_str in partial_stats and "2025" in partial_stats[cur_month_str]) else 0
        partial_26 = sum(partial_stats[cur_month_str]["2026"].values()) if (cur_month_str in partial_stats and "2026" in partial_stats[cur_month_str]) else 0
        curr_full_25 = get_month_total("2025", cur_month_str)
        if partial_25 > 0 and curr_full_25 > 0:
            current_month_yoy_factor = partial_26 / partial_25
            # Add current month's actual YoY factor to the trend
            yoy_factors.append(current_month_yoy_factor)

    accelerations = []
    for i in range(1, len(yoy_factors)):
        accelerations.append(yoy_factors[i] - yoy_factors[i-1])
        
    average_acceleration = sum(accelerations) / len(accelerations) if accelerations else 0.0

    mom_predictions = {}
    for ms in months_list:
        prev_ms, prev_yr_26, prev_yr_25 = prev_month_map[ms]
        
        # Decide the 2026 value of the previous month
        if prev_yr_26 == "2026" and prev_ms >= cur_month_str:
            prev_val_26 = mom_predictions[prev_ms]
        else:
            prev_val_26 = get_month_total(prev_yr_26, prev_ms)
            
        curr_val_25 = get_month_total("2025", ms)
        prev_val_25 = get_month_total(prev_yr_25, prev_ms)
        
        # Current month with actual data: use the partial YoY factor as fact
        if ms == cur_month_str and current_month_yoy_factor is not None:
            pred_mom = curr_val_25 * current_month_yoy_factor if curr_val_25 > 0 else 0.0
        elif prev_val_25 > 0:
            yoy_factor = prev_val_26 / prev_val_25
            if current_month_yoy_factor is not None:
                # Current month is fact — only add acceleration for months after it
                if ms > cur_month_str:
                    yoy_factor += average_acceleration
            else:
                # No current month data — use original behavior
                if ms >= cur_month_str:
                    yoy_factor += average_acceleration
            pred_mom = curr_val_25 * yoy_factor
        else:
            pred_mom = 0.0
            
        mom_predictions[ms] = pred_mom

    # Calculate overall YoY and projection targets first
    all_months_list = [f"{i:02d}" for i in range(1, 13)]
    all_g25_real = sum(sum(r[f"25_{ms}"] for r in combined) for ms, *_ in full_months)
    all_g26_real = sum(sum(r[f"26_{ms}"] for r in combined) for ms, *_ in full_months)
    all_g25_total = all_g25_real
    all_g26_total = all_g26_real

    # Compute projection adjustment factor to land on exactly 100,000 total CVEs
    unadj_proj_sum = 0
    remaining_2025_sum = 0
    remaining_month_strs = [m for m in all_months_list if m not in completed_month_strs]
    
    for month_str in remaining_month_strs:
        m_idx = int(month_str)
        if n >= 2:
            g_m = slope * m_idx + intercept
        elif n == 1:
            g_m = intercept
        else:
            g_m = 0.0
        g_m = clamp_growth(g_m)
        
        g25 = 0
        if stats and month_str in stats and "2025" in stats[month_str]:
            g25 = sum(stats[month_str]["2025"].values())
            
        unadj_proj_sum += g25 * (1 + g_m)
        remaining_2025_sum += g25
        
    total_unadj = all_g26_real + unadj_proj_sum
    diff = 100000 - total_unadj
    d_adj = diff / remaining_2025_sum if remaining_2025_sum > 0 else 0.0

    # Build val_2026 dictionary containing actuals/projections for 2026
    val_2026 = {}
    for month_str, _, _, _ in full_months:
        val_2026[month_str] = sum(r[f"26_{month_str}"] for r in combined)

    temp_sum = all_g26_real
    for idx, month_str in enumerate(remaining_month_strs):
        m_idx = int(month_str)
        if n >= 2:
            g_m = slope * m_idx + intercept
        elif n == 1:
            g_m = intercept
        else:
            g_m = 0.0
        g_m = clamp_growth(g_m) + d_adj
        
        g25 = 0
        if stats and month_str in stats and "2025" in stats[month_str]:
            g25 = sum(stats[month_str]["2025"].values())
            
        g26_proj = int(round(g25 * (1 + g_m)))
        if idx == len(remaining_month_strs) - 1:
            g26_proj = 100000 - temp_sum
        temp_sum += g26_proj
        val_2026[month_str] = g26_proj

    totals_rows = []
    # 1. Add completed months
    for month_str, month_name, _, _ in full_months:
        g25 = sum(r[f"25_{month_str}"] for r in combined)
        g26 = sum(r[f"26_{month_str}"] for r in combined)
        
        # Check if this completed month has a reference prediction (i.e. June or later)
        ref_pred = REFERENCE_PREDICTIONS.get(month_str)
        if ref_pred is not None:
            t26_str = f"{g26:,} (Pred: {ref_pred:,})"
        else:
            t26_str = f"{g26:,}"
            
        t_mom_val = int(round(mom_predictions.get(month_str, 0)))
        
        # Calculate MoM %
        prev_ms = f"{int(month_str)-1:02d}"
        if month_str == "01":
            prev_val = sum(stats["12"]["2025"].values()) if (stats and "12" in stats and "2025" in stats["12"]) else 0
        else:
            prev_val = val_2026[prev_ms]
            
        mom_pct = ((g26 - prev_val) / prev_val * 100) if prev_val > 0 else 0.0
        mom_pct_str = f"{mom_pct:>+7.1f}%"
        
        totals_rows.append(
            {
                "mon": f"{month_name[:3]} \u2019{month_str}",
                "t25": f"{g25:,}",
                "t26": t26_str,
                "yoy": fmt_yoy(g26, g25),
                "mom_pred": f"{g26:,} (Pred: {t_mom_val:,})",
                "mom_pct": mom_pct_str,
            }
        )

    # 2. Add projected remaining months (if stats is available)
    temp_sum = all_g26_real
    all_g25_total = all_g25_real
    all_g26_total = all_g26_real
    for idx, month_str in enumerate(remaining_month_strs):
        month_name = months_map.get(month_str, month_str)
        m_idx = int(month_str)
        
        if n >= 2:
            g_m = slope * m_idx + intercept
        elif n == 1:
            g_m = intercept
        else:
            g_m = 0.0
        g_m = clamp_growth(g_m) + d_adj
        
        g25 = 0
        if stats and month_str in stats and "2025" in stats[month_str]:
            g25 = sum(stats[month_str]["2025"].values())
            
        g26_proj = val_2026[month_str]
        all_g25_total += g25
        all_g26_total += g26_proj

        if stats:
            ref_pred = REFERENCE_PREDICTIONS.get(month_str)
            t_mom_val = int(round(mom_predictions.get(month_str, 0)))
            
            # Calculate MoM %
            prev_ms = f"{int(month_str)-1:02d}"
            if month_str == "01":
                prev_val = sum(stats["12"]["2025"].values()) if (stats and "12" in stats and "2025" in stats["12"]) else 0
            else:
                prev_val = val_2026[prev_ms]
            
            # Check if this is the current incomplete month
            if month_str == current_month_str and current_month_has_data:
                g26_act = sum(stats[month_str]["2026"].values()) if "2026" in stats[month_str] else 0
                
                # Format t26 string: "Actual / Reference Prediction (Percent Reached)"
                if ref_pred is not None:
                    pct = (g26_act / ref_pred * 100) if ref_pred > 0 else 0.0
                    t26_str = f"{g26_act:,} / {ref_pred:,} ({pct:.1f}%)"
                else:
                    t26_str = f"{g26_act:,} (Proj: {g26_proj:,}*)"
                
                # YoY string: MTD YoY vs Proj YoY
                g25_partial = sum(partial_stats[month_str]["2025"].values()) if (partial_stats and month_str in partial_stats and "2025" in partial_stats[month_str]) else 0
                yoy_mtd_pct = ((g26_act - g25_partial) / g25_partial * 100) if g25_partial > 0 else 0.0
                yoy_proj_pct = g_m * 100
                yoy_str = f"{yoy_mtd_pct:>+5.1f}% MTD (Proj: {yoy_proj_pct:>+5.1f}%*)"
                mon_label = f"{month_name[:3]} \u2019{month_str} (Inc)"
                
                # MoM % string: MTD MoM vs Proj MoM
                mom_mtd_pct = ((g26_act - prev_val) / prev_val * 100) if prev_val > 0 else 0.0
                mom_proj_pct = ((g26_proj - prev_val) / prev_val * 100) if prev_val > 0 else 0.0
                mom_pct_str = f"{mom_mtd_pct:>+5.1f}% MTD (Proj: {mom_proj_pct:>+5.1f}%*)"
                mom_pred_str = f"{g26_act:,} (Pred: {t_mom_val:,}*)"
            else:
                # Future month (prediction only)
                if ref_pred is not None:
                    t26_str = f"{g26_proj:,}* (Ref: {ref_pred:,})"
                else:
                    t26_str = f"{g26_proj:,}*"
                yoy_str = f"{g_m * 100:>+7.1f}%*"
                mon_label = f"{month_name[:3]} \u2019{month_str}*"
                
                mom_pct = ((g26_proj - prev_val) / prev_val * 100) if prev_val > 0 else 0.0
                mom_pct_str = f"{mom_pct:>+7.1f}%*"
                mom_pred_str = f"{t_mom_val:,}*"

            totals_rows.append(
                {
                    "mon": mon_label,
                    "t25": f"{g25:,}",
                    "t26": t26_str,
                    "yoy": yoy_str,
                    "mom_pred": mom_pred_str,
                    "mom_pct": mom_pct_str,
                }
            )

    all_mom_pred_real = sum(int(round(mom_predictions[ms])) for ms in completed_month_strs)
    all_mom_pred_total = sum(get_month_total("2026", ms) if ms in completed_month_strs else int(round(mom_predictions[ms])) for ms in months_list)

    cum_mom_str = f"{all_g26_real:,} (Pred: {all_mom_pred_real:,})"
    proj_mom_str = f"{all_mom_pred_total:,}*" if (stats and len(completed_month_strs) < 12) else ""

    wmon = max([len(lbl_mon), len("Cumulative"), len("Proj Total")] + [len(r["mon"]) for r in totals_rows])
    wt25 = max([len(lbl_25t), len(f"{all_g25_real:,}"), len(f"{all_g25_total:,}")] + [len(r["t25"]) for r in totals_rows])
    wt26 = max([len(lbl_26t), len(f"{all_g26_real:},"), len(f"{all_g26_total:,}*")] + [len(r["t26"]) for r in totals_rows])
    wyoyt = max([len(lbl_yoyt), len(fmt_yoy(all_g26_real, all_g25_real))] + [len(r["yoy"]) for r in totals_rows])
    wmom = max([len(lbl_mom), len(cum_mom_str), len(proj_mom_str)] + [len(r["mom_pred"]) for r in totals_rows])
    wmomp = max([len(lbl_momp), len("-")] + [len(r["mom_pct"]) for r in totals_rows])
    
    sep = wmon + 3 + wt25 + 3 + wt26 + 3 + wyoyt + 3 + wmom + 3 + wmomp

    if incomplete_month_print_fn is not None:
        incomplete_month_print_fn()

    print("\n  \u2500\u2500 Monthly Totals Summary \u2500\u2500")
    print(f"  {chr(45) * sep}")
    print(
        f"  {lbl_mon:<{wmon}} | {lbl_25t:>{wt25}} | {lbl_26t:>{wt26}} | {lbl_yoyt:>{wyoyt}} | {lbl_mom:>{wmom}} | {lbl_momp:>{wmomp}}"
    )
    print(f"  {chr(45) * sep}")
    for r in totals_rows:
        print(
            f"  {r['mon']:<{wmon}} | {r['t25']:>{wt25}} | {r['t26']:>{wt26}} | {r['yoy']:>{wyoyt}} | {r['mom_pred']:>{wmom}} | {r['mom_pct']:>{wmomp}}"
        )
    print(f"  {chr(45) * sep}")
    print(
        f"  {'Cumulative':<{wmon}} | {all_g25_real:>{wt25},} | {all_g26_real:>{wt26},} | {fmt_yoy(all_g26_real, all_g25_real):>{wyoyt}} | {cum_mom_str:>{wmom}} | {'-':>{wmomp}}"
    )
    if stats and len(completed_month_strs) < 12:
        proj_yoy_pct = ((all_g26_total - all_g25_total) / all_g25_total * 100) if all_g25_total > 0 else 0.0
        proj_yoy_str = f"{proj_yoy_pct:>+7.1f}%*"
        proj_g26_str = f"{all_g26_total:,}*"
        print(
            f"  {'Proj Total':<{wmon}} | {all_g25_total:>{wt25},} | {proj_g26_str:>{wt26}} | {proj_yoy_str:>{wyoyt}} | {proj_mom_str:>{wmom}} | {'-':>{wmomp}}"
        )

    return all_top_names


def print_combined_incomplete_month_table(
    title,
    data_2025_full,
    data_2025_partial,
    data_2026_partial,
    ytd_2025,
    ytd_2026,
    label_25_full,
    label_25_partial,
    label_26_partial,
    anchor_date,
    print_table=True,
    prev_data_2026_full=None,
    prev_others_count=0,
):
    """
    Utility to print a combined table for incomplete months including YTD.
    """
    all_cnas = (
        set(data_2025_full.keys())
        | set(data_2025_partial.keys())
        | set(data_2026_partial.keys())
    )
    combined = []
    for cna in all_cnas:
        combined.append(
            {
                "name": cna,
                "25_full": data_2025_full.get(cna, 0),
                "25_part": data_2025_partial.get(cna, 0),
                "26_part": data_2026_partial.get(cna, 0),
                "ytd_25": ytd_2025.get(cna, 0),
                "ytd_26": ytd_2026.get(cna, 0),
            }
        )

    # Top CNAs from the incomplete/partial periods of 2025 and 2026
    top_c25p = sorted(combined, key=lambda x: x["25_part"], reverse=True)[:TOP_N]
    top_c26p = sorted(combined, key=lambda x: x["26_part"], reverse=True)[:TOP_N]

    top_names = (
        {r["name"] for r in top_c25p if r["25_part"] > 0}
        | {r["name"] for r in top_c26p if r["26_part"] > 0}
    )

    top_cnas = [r for r in combined if r["name"] in top_names]
    others = [r for r in combined if r["name"] not in top_names]

    top_cnas.sort(key=lambda x: x["26_part"], reverse=True)
    top_names_found = {r["name"] for r in top_cnas}

    display_rows = []
    if others:
        c25f = sum(1 for r in others if r["25_full"] > 0)
        c25p = sum(1 for r in others if r["25_part"] > 0)
        c26p = sum(1 for r in others if r["26_part"] > 0)
        display_rows.append(
            {
                "name": "Others",
                "25_full": sum(r["25_full"] for r in others),
                "25_part": sum(r["25_part"] for r in others),
                "26_part": sum(r["26_part"] for r in others),
                "c25f": c25f,
                "c25p": c25p,
                "c26p": c26p,
                "ytd_25": sum(r["ytd_25"] for r in others),
                "ytd_26": sum(r["ytd_26"] for r in others),
            }
        )
    display_rows.extend(top_cnas)

    # Pre-calculate strings for dynamic formatting
    def fmt_yoy(curr, prev):
        if prev > 0:
            val = ((curr - prev) / prev) * 100
            return f"{val:+8.1f}%"
        return "    N/A  " if curr == 0 else "   +Inf  "

    if prev_data_2026_full is not None:
        total_prev_26_full = sum(prev_data_2026_full.values())
    else:
        total_prev_26_full = 0

    formatted_rows = []
    for r in display_rows:
        if r["name"] == "Others":
            vf_str = f"{r['25_full']:,} ({r['c25f']})" if r["c25f"] > 0 else "0"
            vp25_str = f"{r['25_part']:,} ({r['c25p']})" if r["c25p"] > 0 else "0"
            vp26_str = f"{r['26_part']:,} ({r['c26p']})" if r["c26p"] > 0 else "0"
            prev_part = prev_others_count
        else:
            vf_str = f"{r['25_full']:,}"
            vp25_str = f"{r['25_part']:,}"
            vp26_str = f"{r['26_part']:,}"
            prev_part = prev_data_2026_full.get(r["name"], 0) if prev_data_2026_full is not None else 0

        formatted_rows.append(
            {
                "name": r["name"],
                "vf": vf_str,
                "vp25": vp25_str,
                "vp26": vp26_str,
                "ym": fmt_yoy(r["26_part"], r["25_part"]),
                "mom": fmt_yoy(r["26_part"], prev_part),
                "yf": fmt_yoy(r["26_part"], r["25_full"]),
            }
        )

    # Totals
    g_25f = sum(r["25_full"] for r in combined)
    g_25p = sum(r["25_part"] for r in combined)
    g_26p = sum(r["26_part"] for r in combined)

    total_row = {
        "name": "Total",
        "vf": f"{g_25f:,}",
        "vp25": f"{g_25p:,}",
        "vp26": f"{g_26p:,}",
        "ym": fmt_yoy(g_26p, g_25p),
        "mom": fmt_yoy(g_26p, total_prev_26_full),
        "yf": fmt_yoy(g_26p, g_25f),
    }

    # Widths
    wf = max(
        len(label_25_full),
        max((len(r["vf"]) for r in formatted_rows), default=0),
        len(total_row["vf"]),
    )
    wp25 = max(
        len(label_25_partial),
        max((len(r["vp25"]) for r in formatted_rows), default=0),
        len(total_row["vp25"]),
    )
    wp26 = max(
        len(label_26_partial),
        max((len(r["vp26"]) for r in formatted_rows), default=0),
        len(total_row["vp26"]),
    )
    w_mtd = max(
        len("YoY (MTD)"),
        max((len(r["ym"]) for r in formatted_rows), default=0),
        len(total_row["ym"]),
    )
    w_mom = max(
        len("MoM %"),
        max((len(r["mom"]) for r in formatted_rows), default=0),
        len(total_row["mom"]),
    )
    w_yf = max(
        len("YoY (Full)"),
        max((len(r["yf"]) for r in formatted_rows), default=0),
        len(total_row["yf"]),
    )

    sep_len = 35 + 3 + wf + 3 + wp25 + 3 + wp26 + 3 + w_mtd + 3 + w_mom + 3 + w_yf

    if print_table:
        print(f"\n{title} (Up to {anchor_date})")
        print("-" * sep_len)
        print(
            f"{'CNA Name':<35} | {label_25_full:>{wf}} | {label_25_partial:>{wp25}} | {label_26_partial:>{wp26}} | {'YoY (MTD)':>{w_mtd}} | {'MoM %':>{w_mom}} | {'YoY (Full)':>{w_yf}}"
        )
        print("-" * sep_len)

        for r in formatted_rows:
            print(
                f"{r['name']:<35} | {r['vf']:>{wf}} | {r['vp25']:>{wp25}} | {r['vp26']:>{wp26}} | {r['ym']:>{w_mtd}} | {r['mom']:>{w_mom}} | {r['yf']:>{w_yf}}"
            )

        print("-" * sep_len)
        t = total_row
        print(
            f"{t['name']:<35} | {t['vf']:>{wf}} | {t['vp25']:>{wp25}} | {t['vp26']:>{wp26}} | {t['ym']:>{w_mtd}} | {t['mom']:>{w_mom}} | {t['yf']:>{w_yf}}"
        )

        # Export to CSV — disabled on the published path (no CSV outputs).
        if _WRITE_CSV:
            csv_file = "cve_monthly_stats_comparison_incomplete_month.csv"
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "CNA Name",
                        label_25_full,
                        label_25_partial,
                        label_26_partial,
                        "YoY (MTD)",
                        "MoM %",
                        "YoY (Full)",
                    ]
                )
                for idx, r in enumerate(display_rows):
                    f_row = formatted_rows[idx]
                    writer.writerow(
                        [
                            r["name"],
                            r["25_full"],
                            r["25_part"],
                            r["26_part"],
                            f_row["ym"].strip(),
                            f_row["mom"].strip(),
                            f_row["yf"].strip(),
                        ]
                    )
                writer.writerow(
                    [
                        total_row["name"],
                        sum(r["25_full"] for r in combined),
                        sum(r["25_part"] for r in combined),
                        sum(r["26_part"] for r in combined),
                        total_row["ym"].strip(),
                        total_row["mom"].strip(),
                        total_row["yf"].strip(),
                    ]
                )
            saved_files_log.append(f"Saved incomplete month stats to {os.path.abspath(csv_file)}")

    return top_names_found


def print_summary_table(title, ytd_2025, ytd_2026, top_names, anchor_date):
    """
    Utility to print a final summary table for given top names.
    Columns: CNA Name | YTD 2025 | YTD 2026 | YoY %
    """
    combined = []
    all_cnas = set(ytd_2025.keys()) | set(ytd_2026.keys())

    for cna in all_cnas:
        v25 = ytd_2025.get(cna, 0)
        v26 = ytd_2026.get(cna, 0)
        if v25 == 0 and v26 == 0:
            continue
        combined.append({"name": cna, "2025": v25, "2026": v26})

    top_rows = [r for r in combined if r["name"] in top_names]
    others = [r for r in combined if r["name"] not in top_names]

    # Sort top by 2026 YTD
    top_rows.sort(key=lambda x: x["2026"], reverse=True)

    display_rows = []
    if others:
        c25 = sum(1 for r in others if r["2025"] > 0)
        c26 = sum(1 for r in others if r["2026"] > 0)
        display_rows.append(
            {
                "name": "Others",
                "2025": sum(r["2025"] for r in others),
                "2026": sum(r["2026"] for r in others),
                "c25": c25,
                "c26": c26,
            }
        )
    display_rows.extend(top_rows)

    # Pre-calculate strings
    def fmt_yoy_pct(curr, prev):
        if prev > 0:
            val = ((curr - prev) / prev) * 100
            return f"{val:+8.1f}%"
        return "    N/A  " if curr == 0 else "   +Inf  "

    def fmt_yoy_net(curr, prev):
        diff = curr - prev
        return f"{diff:+d}"

    formatted_rows = []
    for r in display_rows:
        if r["name"] == "Others":
            v1_str = f"{r['2025']:,} ({r['c25']})" if r["c25"] > 0 else "0"
            v2_str = f"{r['2026']:,} ({r['c26']})" if r["c26"] > 0 else "0"
        else:
            v1_str = f"{r['2025']:,}"
            v2_str = f"{r['2026']:,}"

        formatted_rows.append(
            {
                "name": r["name"],
                "v1": v1_str,
                "v2": v2_str,
                "yy_net": fmt_yoy_net(r["2026"], r["2025"]),
                "yy_pct": fmt_yoy_pct(r["2026"], r["2025"]),
            }
        )

    # Totals
    g_25 = sum(r["2025"] for r in combined)
    g_26 = sum(r["2026"] for r in combined)
    total_row = {
        "name": "Total",
        "v1": f"{g_25:,}",
        "v2": f"{g_26:,}",
        "yy_net": fmt_yoy_net(g_26, g_25),
        "yy_pct": fmt_yoy_pct(g_26, g_25),
    }

    # Widths
    w1 = max(
        len("YTD 2025"),
        max((len(r["v1"]) for r in formatted_rows), default=0),
        len(total_row["v1"]),
    )
    w2 = max(
        len("YTD 2026"),
        max((len(r["v2"]) for r in formatted_rows), default=0),
        len(total_row["v2"]),
    )
    w3 = max(
        len("YoY Net"),
        max((len(r["yy_net"]) for r in formatted_rows), default=0),
        len(total_row["yy_net"]),
    )
    w4 = max(
        len("YoY %"),
        max((len(r["yy_pct"]) for r in formatted_rows), default=0),
        len(total_row["yy_pct"]),
    )

    sep_len = 35 + 3 + w1 + 3 + w2 + 3 + w3 + 3 + w4

    print(f"\n{title} (Total as of {anchor_date})")
    print("=" * sep_len)
    print(
        f"{'CNA Name':<35} | {'YTD 2025':>{w1}} | {'YTD 2026':>{w2}} | {'YoY Net':>{w3}} | {'YoY %':>{w4}}"
    )
    print("-" * sep_len)

    for r in formatted_rows:
        print(
            f"{r['name']:<35} | {r['v1']:>{w1}} | {r['v2']:>{w2}} | {r['yy_net']:>{w3}} | {r['yy_pct']:>{w4}}"
        )

    print("-" * sep_len)
    t = total_row
    print(
        f"{t['name']:<35} | {t['v1']:>{w1}} | {t['v2']:>{w2}} | {t['yy_net']:>{w3}} | {t['yy_pct']:>{w4}}"
    )

    # Export to CSV — disabled on the published path (no CSV outputs).
    if _WRITE_CSV:
        csv_file = "cve_monthly_stats_comparison_ytd_summary.csv"
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["CNA Name", "YTD 2025", "YTD 2026", "YoY Net", "YoY %"])
            for r in display_rows:
                writer.writerow(
                    [
                        r["name"],
                        r["2025"],
                        r["2026"],
                        fmt_yoy_net(r["2026"], r["2025"]),
                        fmt_yoy_pct(r["2026"], r["2025"]).strip(),
                    ]
                )
            writer.writerow(
                [
                    total_row["name"],
                    sum(r["2025"] for r in combined),
                    sum(r["2026"] for r in combined),
                    total_row["yy_net"],
                    total_row["yy_pct"].strip(),
                ]
            )
        saved_files_log.append(f"Saved YTD summary stats to {os.path.abspath(csv_file)}")


def _build_sankey_lines(data_2025, data_2026, top_names, label_25, label_26):
    """
    Shared helper that builds SankeyMatic lines from two CNA→count dicts.
    Returns a list of strings (one per Sankey edge).
    """
    sankey_lines = []

    # Calculate "Others" and their contributor counts
    others_2025 = sum(v for k, v in data_2025.items() if k not in top_names)
    others_2026 = sum(v for k, v in data_2026.items() if k not in top_names)
    others_c25 = sum(1 for k, v in data_2025.items() if k not in top_names and v > 0)
    others_c26 = sum(1 for k, v in data_2026.items() if k not in top_names and v > 0)

    # Prepare data for top CNAs + Others
    display_data = []
    if others_2025 > 0 or others_2026 > 0:
        display_data.append(
            {
                "name_25": f"Others, {others_c25}" if others_c25 > 0 else "Others",
                "name_26": f"Others, {others_c26}" if others_c26 > 0 else "Others",
                "2025": others_2025,
                "2026": others_2026,
            }
        )

    # Add top CNAs sorted by their 2026 volume
    sorted_top = sorted(
        [
            {
                "name_25": name,
                "name_26": name,
                "2025": data_2025.get(name, 0),
                "2026": data_2026.get(name, 0),
            }
            for name in top_names
        ],
        key=lambda x: x["2026"],
        reverse=True,
    )
    display_data.extend(sorted_top)

    for item in display_data:
        n25 = item["name_25"]
        n26 = item["name_26"]
        v25 = item["2025"]
        v26 = item["2026"]

        # Stage 1: source -> CNA in 2025
        if v25 > 0:
            sankey_lines.append(f"{label_25} [{v25}] {n25} (2025)")

        # Stage 2: CNA in 2025 -> CNA in 2026
        v_flow = min(v25, v26)
        if v_flow > 0:
            sankey_lines.append(f"{n25} (2025) [{v_flow}] {n26} (2026)")

        # Stage 3: CNA in 2026 -> sink
        if v26 > 0:
            sankey_lines.append(f"{n26} (2026) [{v26}] {label_26}")

    return sankey_lines


def generate_sankeymatic_input(
    ytd_2025, ytd_2026, top_names, filename="cve_monthly_stats_comparison_sankey.txt"
):
    """
    Generates a SankeyMatic-compatible input file based on full YoY data.
    4 data slices: 2025 ytd -> CNA in 2025 -> CNA in 2026 -> 2026 ytd
    """
    sankey_lines = _build_sankey_lines(
        ytd_2025, ytd_2026, top_names, "2025 YTD", "2026 YTD"
    )

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(sankey_lines))

    saved_files_log.append(f"Saved SankeyMatic input to {os.path.abspath(filename)}")


def generate_sankeymatic_incomplete_month(
    data_2025_partial,
    data_2026_partial,
    top_names,
    month_name,
    current_day,
    filename="cve_monthly_stats_comparison_incomplete_month.txt",
):
    """
    Generates a SankeyMatic-compatible input file for the incomplete (current) month.
    Uses the same conventions as the YTD Sankey.
    """
    range_label = f"{month_name[:3]} 1-{current_day}"
    label_25 = f"2025 ({range_label})"
    label_26 = f"2026 ({range_label})"

    sankey_lines = _build_sankey_lines(
        data_2025_partial, data_2026_partial, top_names, label_25, label_26
    )

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(sankey_lines))

    saved_files_log.append(f"Saved incomplete-month SankeyMatic input to {os.path.abspath(filename)}")


def generate_sankeymatic_incomplete_vs_full(
    data_2025_full,
    data_2026_partial,
    top_names,
    month_name,
    current_day,
    filename="cve_monthly_stats_comparison_incomplete_vs_full.txt",
):
    """
    Generates a SankeyMatic-compatible input file comparing the full month of 2025
    to the incomplete (current) month of 2026.
    """
    label_25 = f"2025 (Full {month_name})"
    label_26 = f"2026 ({month_name[:3]} 1-{current_day})"

    sankey_lines = _build_sankey_lines(
        data_2025_full, data_2026_partial, top_names, label_25, label_26
    )

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(sankey_lines))

    saved_files_log.append(f"Saved incomplete-vs-full-month SankeyMatic input to {os.path.abspath(filename)}")



def generate_sankeymatic_monthly_flow(
    stats,
    partial_stats,
    top_names,
    anchor_date,
    filename="cve_monthly_stats_comparison_sankey_monthly.txt",
):
    """
    Generates a SankeyMatic-compatible input file showing the monthly flow
    of CVE contributions for top YTD CNAs, starting from December 2025,
    flowing through each month of 2026, and ending at 2026 YTD.
    """
    anchor_month_str = anchor_date[5:7]  # e.g., "06" for June

    # Get December 2025 data
    dec_2025_data = stats.get("12", {}).get("2025", {})

    # Build list of stages
    stages = []

    # Stage 0: December 2025
    stages.append({
        "label": "Dec 2025",
        "data": dec_2025_data
    })

    # Month abbreviation mapping
    months_abbrev = {
        "01": "Jan", "02": "Feb", "03": "Mar", "04": "Apr",
        "05": "May", "06": "Jun", "07": "Jul", "08": "Aug",
        "09": "Sep", "10": "Oct", "11": "Nov", "12": "Dec"
    }

    # Stages 1 to K: Jan to anchor_month (removed " 2026" from label to yield CNA - Mon format)
    for m_int in range(1, int(anchor_month_str) + 1):
        m_str = f"{m_int:02d}"
        m_label = months_abbrev[m_str]

        if m_str < anchor_month_str:
            # Full month
            m_data = stats.get(m_str, {}).get("2026", {})
        else:
            # Current (possibly incomplete) month
            m_data = partial_stats.get(m_str, {}).get("2026", {})

        stages.append({
            "label": m_label,
            "data": m_data
        })

    # Calculate 2026 totals for each top CNA to sort the flows by 2026 volume
    cna_totals_2026 = collections.Counter()
    for stage in stages[1:]:  # skip Dec 2025
        for cna, count in stage["data"].items():
            cna_totals_2026[cna] += count

    # Sort top_names by total 2026 volume descending
    sorted_top_names = sorted(top_names, key=lambda c: cna_totals_2026[c], reverse=True)

    sankey_lines = []

    # Build sequential flows from Stage i to Stage i+1 using "CNA - Mon" style labels
    for i in range(len(stages) - 1):
        curr_stage = stages[i]
        next_stage = stages[i + 1]

        curr_label = curr_stage["label"]
        next_label = next_stage["label"]

        curr_data = curr_stage["data"]
        next_data = next_stage["data"]

        # Calculate others for current stage
        curr_others_val = sum(v for k, v in curr_data.items() if k not in top_names)
        curr_others_count = sum(1 for k, v in curr_data.items() if k not in top_names and v > 0)
        curr_others_label = f"Others, {curr_others_count} - {curr_label}" if curr_others_count > 0 else f"Others - {curr_label}"

        next_others_count = sum(1 for k, v in next_data.items() if k not in top_names and v > 0)
        next_others_label = f"Others, {next_others_count} - {next_label}" if next_others_count > 0 else f"Others - {next_label}"

        # If this is the last transition (May -> June), we want the flow to represent June's actual volume
        # so that the June column in the Sankey diagram is sized by June's volume rather than May's,
        # without needing a final YTD column.
        is_last_transition = (i == len(stages) - 2)
        flow_data = next_data if is_last_transition else curr_data
        flow_others_val = sum(v for k, v in next_data.items() if k not in top_names) if is_last_transition else curr_others_val

        for cna in sorted_top_names:
            val = flow_data.get(cna, 0)
            val = max(1, val)  # Ensure a minimum value of 1 to keep flow lines continuous
            sankey_lines.append(f"{cna} - {curr_label} [{val}] {cna} - {next_label}")

        if flow_others_val > 0:
            sankey_lines.append(f"{curr_others_label} [{flow_others_val}] {next_others_label}")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(sankey_lines))

    saved_files_log.append(f"Saved monthly flow SankeyMatic input to {os.path.abspath(filename)}")



def monthly_flow_rank_order(stats, partial_stats, top_names, anchor_month_str, anchor_month_complete):
    """Rank ``top_names`` the way the monthly-flow Sankey stacks them.

    That stack order *is* the ranking the lane colors are keyed on, so it has to
    be computable without drawing the chart: the incomplete-month chart needs the
    same answer, and it is drawn first.
    """
    totals = collections.Counter()
    for m_int in range(1, int(anchor_month_str) + 1):
        m_str = f"{m_int:02d}"
        complete = m_str < anchor_month_str or anchor_month_complete
        month_data = (stats if complete else partial_stats).get(m_str, {}).get("2026", {})
        for cna, count in month_data.items():
            totals[cna] += count
    return sorted(top_names, key=lambda c: totals[c], reverse=True)


def sankey_rank_color_map(stats, partial_stats, ytd_2026, anchor_month_str, anchor_month_complete):
    """The dashboard's CNA→color mapping: rank in the monthly-flow Sankey.

    Every Sankey chart resolves its colors through this, so a CNA that leads the
    year is the same color wherever it appears.
    """
    top_names = [c for c, _ in ytd_2026.most_common(TOP_N)]
    return sankey_rank_colors(
        monthly_flow_rank_order(stats, partial_stats, top_names, anchor_month_str, anchor_month_complete)
    )


def _prep_sankey_flow(stats, partial_stats, top_names, anchor_date, anchor_month_complete=False):
    """Everything ``plot_custom_sankey_flow`` draws, before any layout.

    Shared with the slide renderer (``monthly_slides``) so both pictures are cut
    from the very same numbers; nothing in here knows about inches or y units.
    """
    anchor_month_str = anchor_date[5:7]  # e.g., "06" for June
    current_year = int(anchor_date[:4])  # display year, derived from the data anchor
    prev_year = current_year - 1
    dec_2025_data = stats.get("12", {}).get("2025", {})

    # Month abbreviation mapping
    months_abbrev = {
        "01": "Jan", "02": "Feb", "03": "Mar", "04": "Apr",
        "05": "May", "06": "Jun", "07": "Jul", "08": "Aug",
        "09": "Sep", "10": "Oct", "11": "Nov", "12": "Dec"
    }

    stages = []
    # Stage 0: December (previous year)
    stages.append({
        "label": f"Dec {prev_year}",
        "data": dec_2025_data
    })

    # Stages 1 to K: Jan 2026 to anchor_month 2026
    anchor_day = int(anchor_date[8:10])
    for m_int in range(1, int(anchor_month_str) + 1):
        m_str = f"{m_int:02d}"
        m_label = months_abbrev[m_str]

        if m_str < anchor_month_str or anchor_month_complete:
            m_data = stats.get(m_str, {}).get("2026", {})
        else:
            # Anchor month is incomplete — show its day range in the header.
            m_data = partial_stats.get(m_str, {}).get("2026", {})
            m_label = f"{m_label} 1-{anchor_day}"

        stages.append({
            "label": m_label,
            "data": m_data
        })

    # Sort top_names by total 2026 volume descending. This is the ranking the
    # lane colors are keyed on, so it comes from the shared helper.
    sorted_top_names = monthly_flow_rank_order(
        stats, partial_stats, top_names, anchor_month_str, anchor_month_complete
    )
    all_items = sorted_top_names + ["Others"]

    # Month headers
    stage_labels = [s["label"] for s in stages]

    # Per-stage volumes, exact. There is no minimum-height floor here on
    # purpose: with the columns hung from a common baseline the vertical axis
    # *is* the CVE axis, so padding a near-empty lane to keep it visible would
    # shift every boundary below it and break the one thing the layout is for.
    # Lanes too thin to see are handled at draw time instead (``_draw_span``),
    # which changes the ink without moving the boundaries.
    raw_data = []
    totals = []
    for stage in stages:
        stage_data = stage["data"]
        volumes = {cna: stage_data.get(cna, 0) for cna in sorted_top_names}
        volumes["Others"] = sum(
            v for k, v in stage_data.items() if k not in sorted_top_names
        )
        raw_data.append(volumes)
        totals.append(sum(volumes.values()))

    max_total = max(totals) if totals else 1

    # One color per rank, in the stack's own order — this chart defines the
    # ranking every other Sankey inherits.
    colors = sankey_lane_colors(all_items, sankey_rank_colors(sorted_top_names))

    # ── The reference guide ──────────────────────────────────────────────────
    # One month's entire output, carried across every column at the depth it
    # reaches. The first month of the current year is the natural yardstick: the
    # dashed line leaves that column's own underside, so wherever it crosses a
    # later month it says "this many CNAs, and you have already matched it".
    ref_idx = 1 if len(stages) > 1 else None
    ref_total = totals[ref_idx] if ref_idx is not None else 0
    ref_label = stage_labels[ref_idx] if ref_idx is not None else ""
    # Only meaningful once a later month has grown clear of the yardstick.
    show_ref = (
        ref_idx is not None
        and len(stages) >= 4
        and ref_total > 0
        and totals[-1] >= 1.25 * ref_total
    )

    # ── The callout ──────────────────────────────────────────────────────────
    # How many of the newest month's top CNAs it takes to cover an entire
    # earlier month, read off the same numbers the chart is drawn from, so it
    # can never drift from what is on screen.
    callout = None
    if show_ref:
        cum = 0
        n_cnas = 0
        for name in sorted_top_names:
            cum += raw_data[-1][name]
            n_cnas += 1
            if cum >= _SANKEY_ALMOST * ref_total:
                break
        ref_publishers = sum(1 for v in stages[ref_idx]["data"].values() if v > 0)
        pct = round(cum / ref_total * 100)
        verb = (
            "out-publish" if pct >= 102 else
            "match" if pct >= 98 else
            "nearly match"
        )
        callout = {
            "cum": cum, "n_cnas": n_cnas, "ref_publishers": ref_publishers,
            "pct": pct, "verb": verb,
        }

    return {
        "anchor_month_str": anchor_month_str,
        "current_year": current_year,
        "prev_year": prev_year,
        "months_abbrev": months_abbrev,
        "stages": stages,
        "stage_labels": stage_labels,
        "sorted_top_names": sorted_top_names,
        "all_items": all_items,
        "raw_data": raw_data,
        "totals": totals,
        "max_total": max_total,
        "colors": colors,
        "ref_idx": ref_idx,
        "ref_total": ref_total,
        "ref_label": ref_label,
        "show_ref": show_ref,
        "callout": callout,
    }


def plot_custom_sankey_flow(
    stats,
    partial_stats,
    top_names,
    anchor_date,
    anchor_month_complete=False,
    output_filename="cve_monthly_stats_comparison_sankey_monthly.png",
):
    """
    Plots a custom Sankey flow visualization of CVE contributions for top YTD
    CNAs, starting from December of the previous year, flowing through each
    month of the current year, and ending at the anchor month.

    Every column hangs from one shared baseline and is drawn to one scale, so a
    height means the same number of CVEs wherever it sits: a lane can be read
    against another lane, against the ruler on the right, and against a whole
    column of some other month. That last comparison is the reason for the
    layout. The columns used to be centered on one another with a fixed gap
    between lanes, and both of those broke it — a centered column has no shared
    origin to measure from, and 15 gaps of padding made a full column stand
    taller than the CVEs in it, by more the further down you counted. So the
    gaps are gone (the separation is now taken from *inside* each band, which
    costs no layout) and the counts are used unfloored. The dashed guide carries
    the first month of the year across the picture for exactly that comparison.

    The last column is the anchor month. It is normally partial, and its header
    carries the day range that says so; when ``anchor_month_complete`` it is a
    whole month and gets a plain month header, like every column before it.
    """
    p = _prep_sankey_flow(
        stats, partial_stats, top_names, anchor_date, anchor_month_complete
    )
    anchor_month_str = p["anchor_month_str"]
    current_year = p["current_year"]
    prev_year = p["prev_year"]
    months_abbrev = p["months_abbrev"]
    stages = p["stages"]
    sorted_top_names = p["sorted_top_names"]
    all_items = p["all_items"]
    stage_labels = p["stage_labels"]
    raw_data = p["raw_data"]
    totals = p["totals"]
    max_total = p["max_total"]
    colors = p["colors"]
    # y-units per CVE — the scale of the whole picture, one number.
    unit = (_SANKEY_Y_TOP - _SANKEY_Y_FLOOR) / max(max_total, 1)

    # Stack every column downward from the same baseline.
    stage_positions = []
    for volumes in raw_data:
        pos = {}
        cursor = _SANKEY_Y_TOP
        for item in all_items:
            h = volumes[item] * unit
            pos[item] = (cursor - h, cursor)
            cursor -= h
        stage_positions.append(pos)

    def _draw_span(y0, y1):
        """The ink for a lane whose exact extent is ``y0..y1``.

        Bands are separated by shrinking them inward rather than by spacing them
        apart, so the separation costs no layout and the boundaries stay on the
        CVE scale. A lane thinner than the inset keeps a hairline instead of
        vanishing — the only place the drawing departs from the data, and it
        moves nothing.
        """
        h = y1 - y0
        if h <= 0:
            return y0, y1
        d = min(_SANKEY_BAND_INSET, max(0.0, (h - _SANKEY_MIN_BAND) / 2.0))
        return y0 + d, y1 - d

    # Plot
    plt.style.use("dark_background")
    fig, ax = plt.subplots(
        figsize=(_SANKEY_FIG_W, _SANKEY_FIG_H), facecolor="#1E1E1E"
    )
    ax.set_facecolor("#1E1E1E")

    # Horizontal extent. The columns sit at x = 0 .. len(stages)-1; the only things
    # outside that span are text — CNA names in the left gutter, the last column's
    # values, the cumulative ruler and its header overhang on the right — and text
    # is sized in points, so it needs the same *inches* whatever the month count
    # is. Sizing the margins in data units instead (as a hardcoded -1.0 did)
    # silently overpays: in January, with two columns, one data unit is most of the
    # picture and the gutter swallows it. So reserve inches, then solve for the
    # data range that yields them:
    #   range = span + (gutter + values) * range / fig_w
    # Everything that centers on the picture centers on x_center — not on a constant
    # that only ever held for one particular month count.
    span = len(stages) - 1
    fig_w = fig.get_size_inches()[0]
    x_range = span / (1.0 - (_SANKEY_GUTTER_IN + _SANKEY_VALUES_IN) / fig_w)
    x_left = -_SANKEY_GUTTER_IN * x_range / fig_w
    x_right = span + _SANKEY_VALUES_IN * x_range / fig_w
    x_center = (x_left + x_right) / 2.0
    # Everything placed *beside* a column — the node block, its value, the CNA
    # names and their leaders, the ruler — is text or text-sized furniture, so it
    # is offset in inches for the same reason the gutters are. Written in data
    # units it would grow with the month count: at two columns one data unit is
    # most of the picture, and a name offset that reads as a hair's breadth in
    # December pushes the label clean off the canvas in January.
    x_in = x_range / fig_w  # data units per inch

    def get_curve_points(x1, y1, x2, y2, num_points=100):
        cx1 = x1 + (x2 - x1) * 0.4
        cy1 = y1
        cx2 = x2 - (x2 - x1) * 0.4
        cy2 = y2
        t = np.linspace(0, 1, num_points)
        x = (1-t)**3 * x1 + 3*(1-t)**2*t * cx1 + 3*(1-t)*t**2 * cx2 + t**3 * x2
        y = (1-t)**3 * y1 + 3*(1-t)**2*t * cy1 + 3*(1-t)*t**2 * cy2 + t**3 * y2
        return x, y

    # ── The ruler ────────────────────────────────────────────────────────────
    # Depth below the baseline, in CVEs. It is what turns "that band looks about
    # as tall as that column" into a number, and it only reads because every
    # column starts at the same line.
    grid_x0, grid_x1 = -0.10 * x_in, span + 0.72 * x_in
    ax.plot(
        [grid_x0, grid_x1], [_SANKEY_Y_TOP] * 2,
        color="#FFFFFF", alpha=0.22, linewidth=1.4, zorder=0.5,
    )
    step = next(
        (s for s in (250, 500, 1000, 2000, 2500, 5000, 10000, 20000)
         if max_total / s <= 6),
        20000,
    )
    ruler_x = span + 0.80 * x_in
    for depth in range(0, int(max_total) + 1, step):
        y = _SANKEY_Y_TOP - depth * unit
        if depth:
            ax.plot(
                [grid_x0, grid_x1], [y] * 2,
                color="#FFFFFF", alpha=0.10, linewidth=1.0, zorder=0.5,
            )
        tick = f"{depth // 1000}k" if step >= 1000 and depth else f"{depth:,}"
        ax.text(
            ruler_x, y, tick,
            ha="left", va="center", color="#6E7A88", fontsize=13,
        )
    ax.text(
        ruler_x, _SANKEY_Y_TOP + 14, "CVEs\ndeep",
        ha="left", va="bottom", color="#6E7A88", fontsize=12.5, style="italic",
        linespacing=1.15,
    )

    # Draw flow bands between stages
    for s in range(len(stages) - 1):
        x_s = s
        x_s1 = s + 1
        pos_s = stage_positions[s]
        pos_s1 = stage_positions[s + 1]

        for item in all_items:
            y_start_s, y_end_s = _draw_span(*pos_s[item])
            y_start_s1, y_end_s1 = _draw_span(*pos_s1[item])

            x_top, y_top = get_curve_points(x_s, y_end_s, x_s1, y_end_s1)
            x_bot, y_bot = get_curve_points(x_s, y_start_s, x_s1, y_start_s1)

            x_poly = np.concatenate([x_top, x_bot[::-1]])
            y_poly = np.concatenate([y_top, y_bot[::-1]])

            ax.fill(x_poly, y_poly, color=colors.get(item, "#747D8C"), alpha=0.38, edgecolor="none")

        # The underside of the last lane is the month total, so tracing it is
        # tracing the growth curve. Worth a line of its own.
        y_low_s = stage_positions[s][all_items[-1]][0]
        y_low_s1 = stage_positions[s + 1][all_items[-1]][0]
        cx, cy = get_curve_points(x_s, y_low_s, x_s1, y_low_s1)
        ax.plot(cx, cy, color="#FFFFFF", alpha=0.22, linewidth=1.2, zorder=2)

    # ── The reference guide ──────────────────────────────────────────────────
    # One month's entire output, carried across every column at the depth it
    # reaches. The first month of the current year is the natural yardstick: the
    # dashed line leaves that column's own underside, so wherever it crosses a
    # later column it says "this many CNAs, and you have already matched it".
    ref_idx, ref_total, ref_label = p["ref_idx"], p["ref_total"], p["ref_label"]
    show_ref = p["show_ref"]
    ref_y = _SANKEY_Y_TOP - ref_total * unit
    if show_ref:
        ax.plot(
            [grid_x0, span + 0.58 * x_in], [ref_y] * 2,
            color=C_YELLOW, alpha=0.55, linewidth=1.8,
            linestyle=(0, (7, 5)), zorder=2.2,
        )
        tag = ax.text(
            ref_idx + 0.13 * x_in, ref_y - 6, f"all of {ref_label} ({ref_total:,})",
            ha="left", va="top", color=C_YELLOW, fontsize=15,
            fontweight="bold", zorder=4,
        )
        tag.set_path_effects([
            path_effects.Stroke(linewidth=3, foreground="#1E1E1E"),
            path_effects.Normal(),
        ])

    # Draw stage blocks and labels
    last_s = len(stages) - 1
    for s, stage in enumerate(stages):
        x_pos = s
        pos = stage_positions[s]
        volumes = raw_data[s]
        stage_data = stage["data"]

        # The last column carries the numbers people actually read, so its
        # labels are nudged apart rather than dropped; elsewhere a value is
        # printed only where its own lane has the room, which keeps the small
        # lanes honest instead of padding them out to fit their text.
        spread = None
        if s == last_s:
            centers = [sum(pos[item]) / 2.0 for item in all_items]
            spread = _spread_label_ys(
                centers, 14.5, _SANKEY_Y_FLOOR - 18, _SANKEY_Y_TOP
            )

        for i, item in enumerate(all_items):
            y_start, y_end = pos[item]
            y_center = (y_start + y_end) / 2.0
            d_start, d_end = _draw_span(y_start, y_end)
            val = volumes[item]

            # Draw block
            if val > 0:
                rect = plt.Rectangle(
                    (x_pos - 0.077 * x_in, d_start), 0.154 * x_in, d_end - d_start,
                    facecolor=colors.get(item, "#747D8C"), edgecolor="none", zorder=3,
                )
                ax.add_patch(rect)

            # Label the monthly contribution value if there is one to show and
            # somewhere to put it.
            if val > 0 and (spread is not None or y_end - y_start >= _SANKEY_LABEL_MIN_H):
                if item == "Others":
                    cna_count = sum(
                        1 for k, v in stage_data.items()
                        if k not in sorted_top_names and v > 0
                    )
                    label_text = f"{val}\n[{cna_count}]"
                else:
                    label_text = f"{val}"
                label_y = spread[i] if spread is not None else y_center
                label_x = x_pos + (0.20 if spread is not None else 0.115) * x_in
                if spread is not None and abs(label_y - y_center) > 5:
                    ax.plot(
                        [label_x - 0.02 * x_in, x_pos + 0.095 * x_in], [label_y, y_center],
                        color="#FFFFFF", alpha=0.35, linewidth=0.9, zorder=3.5,
                    )
                txt = ax.text(
                    label_x,
                    label_y,
                    label_text,
                    ha="left",
                    va="center",
                    color="#FFFFFF",
                    fontsize=14,
                    fontweight="bold",
                    zorder=4
                )
                txt.set_path_effects([
                    path_effects.Stroke(linewidth=2, foreground='#1E1E1E'),
                    path_effects.Normal()
                ])

        # Label month header with month name and total count below it
        ax.text(s, 1040, stage_labels[s], ha="center", va="bottom", color="#FFFFFF", fontsize=22.5, fontweight="bold")
        ax.text(s, 1012, f"({totals[s]:,})", ha="center", va="bottom", color="#A4B0BE", fontsize=18, fontweight="normal")

    # CNA names, in the left gutter beside the first column. Drawn to scale the
    # tail lanes stack tighter than their own names, so the names are nudged
    # apart and a leader points back at the lane each one belongs to.
    first_pos = stage_positions[0]
    name_centers = [sum(first_pos[item]) / 2.0 for item in all_items]
    name_ys = _spread_label_ys(
        name_centers, 16.5,
        min(name_centers[-1], _SANKEY_Y_TOP - totals[0] * unit) - 30,
        _SANKEY_Y_TOP,
    )
    for item, center, label_y in zip(all_items, name_centers, name_ys):
        if abs(label_y - center) > 3:
            ax.plot(
                [-0.82 * x_in, -0.25 * x_in, -0.086 * x_in],
                [label_y, label_y, center],
                color="#FFFFFF", alpha=0.3, linewidth=0.9,
                solid_joinstyle="round", zorder=3.5,
            )
        ax.text(
            -0.86 * x_in,
            label_y,
            item,
            ha="right",
            va="center",
            color="#FFFFFF",
            fontsize=16.5,
            fontweight="bold",
        )

    # ── The callout ──────────────────────────────────────────────────────────
    # The picture's whole point, said once in words, in the space the growth
    # curve leaves empty. How many of the newest month's top CNAs it takes to
    # cover an entire earlier month is read off the same numbers the chart is
    # drawn from, so it can never drift from what is on screen.
    if show_ref:
        cum = p["callout"]["cum"]
        n_cnas = p["callout"]["n_cnas"]
        ref_publishers = p["callout"]["ref_publishers"]
        pct = p["callout"]["pct"]
        verb = p["callout"]["verb"]
        # The callout lives in the empty wedge under the growth curve. Early in
        # the year there is no wedge yet, and text dropped there would land on
        # the bands — so it is drawn only where the columns it would run beneath
        # are short enough to clear it.
        head = (
            f"{stage_labels[-1]}: the top {n_cnas} CNAs alone "
            f"{verb} all of {ref_label}"
        )
        head_w = 0.20 * len(head) * x_in     # ~0.2in per character at 25pt bold
        head_top = _SANKEY_CALLOUT_Y + 26 + 34
        room = all(
            _SANKEY_Y_TOP - totals[c] * unit > head_top
            for c in range(min(len(stages), int(head_w) + 2))
        )
        if room and cum >= _SANKEY_ALMOST * ref_total and n_cnas < len(sorted_top_names):
            body = (
                f"{cum:,} CVEs from {n_cnas} publishers, against {ref_total:,} "
                f"from {ref_publishers} in {ref_label} — {pct}% of the month.\n"
                f"The dashed line is {ref_label}'s entire month, carried across "
                f"every column — wherever it\ncrosses, everything above it is "
                f"one {ref_label} of CVEs."
            )
            ax.text(
                0.04 * x_in, _SANKEY_CALLOUT_Y + 26, head,
                ha="left", va="bottom", color="#FFFFFF", fontsize=25,
                fontweight="bold",
            )
            ax.text(
                0.04 * x_in, _SANKEY_CALLOUT_Y + 6, body,
                ha="left", va="top", color="#A4B0BE", fontsize=17,
                linespacing=1.6,
            )

    # Title & Subtitle
    ax.text(
        x_center, 1090,
        f"Monthly CVE Contributions of Top CNAs (Dec {prev_year} - {months_abbrev[anchor_month_str]} {current_year})",
        ha="center",
        va="bottom",
        color="#FFFFFF",
        fontsize=27,
        fontweight="bold"
    )
    ax.text(
        x_center, 1065,
        "Every column hangs from the same baseline at one scale, so equal heights "
        f"mean equal CVE counts. Lanes ordered by total {current_year} volume.",
        ha="center",
        va="bottom",
        color="#A4B0BE",
        fontsize=18.5,
        style="italic"
    )

    ax.set_xlim(x_left, x_right)
    ax.set_ylim(_SANKEY_Y_BOTTOM, 1120)
    ax.axis("off")

    # With the frame off there is nothing for the default subplot margins to hold,
    # and they only pushed the flows inward — roughly a tenth of the picture on the
    # left went to padding the logo sits in. Spanning the figure hands that width
    # back to the bands and the CNA names.
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)
    _add_logo(fig)
    plt.savefig(
        output_filename,
        dpi=200,
        bbox_inches="tight",
        pad_inches=0,
        facecolor=fig.get_facecolor(),
        edgecolor="none"
    )
    plt.close()
    saved_files_log.append(f"Saved custom monthly flow Sankey chart to {os.path.abspath(output_filename)}")


def _prep_incomplete_sankey(
    data_2025_partial,
    data_2026_partial,
    prev_data_partial,
    top_names,
    range_label,
    prev_range_label,
    prev_year_str,
    anchor_date,
    center_is_complete=False,
    rank_colors=None,
):
    """Everything ``plot_incomplete_month_sankey`` draws, before any layout.

    Shared with the slide renderer (``monthly_slides``). ``raw_data`` carries
    the floored lane volumes the web chart sizes its bands by; ``exact_data``
    the unfloored counts, for a renderer that hangs its columns to scale.
    """
    current_year = int(anchor_date[:4])  # display year, derived from the data anchor
    prev_year = current_year - 1

    # Three stages: previous month (MoM) -> current year -> previous year (YoY).
    stages = [
        {"label": f"{prev_year_str} ({prev_range_label})", "data": prev_data_partial},
        {"label": f"{current_year} ({range_label})", "data": data_2026_partial},
        {"label": f"{prev_year} ({range_label})", "data": data_2025_partial},
    ]

    # Sort top CNAs by their current-month (pivot) volume, and drop the ones that
    # published nothing in it. ``top_names`` also carries the leaders of the
    # previous month and of last year, so a CNA can be named here purely for a
    # column that is not the subject of the chart; with no pivot volume its lane
    # is drawn at the minimum band height across all three stops and reads as a
    # flow that does not exist. What it did publish in the other two columns is
    # not lost — it joins "Others" there.
    sorted_top_names = sorted(
        (c for c in top_names if data_2026_partial.get(c, 0) > 0),
        key=lambda c: data_2026_partial.get(c, 0),
        reverse=True,
    )
    all_items = sorted_top_names + ["Others"]

    stage_labels = [s["label"] for s in stages]

    # As in plot_custom_sankey_flow: the max(5, ...) floor sizes the bands so a
    # near-empty lane stays visible, but the header must report the real data.
    # Every lane now has pivot-month volume, but the flanking columns can still
    # sit at 0 (a CNA that started publishing this month, say), and each of those
    # would otherwise add 5 to that column's header.
    raw_data = []
    exact_data = []
    totals = []
    display_totals = []
    for stage in stages:
        stage_data = stage["data"]
        volumes = {}
        exact = {}
        for cna in sorted_top_names:
            volumes[cna] = max(5, stage_data.get(cna, 0))
            exact[cna] = stage_data.get(cna, 0)
        others_val = sum(v for k, v in stage_data.items() if k not in sorted_top_names)
        volumes["Others"] = max(5, others_val)
        exact["Others"] = others_val

        raw_data.append(volumes)
        exact_data.append(exact)
        totals.append(sum(volumes.values()))
        display_totals.append(sum(stage_data.values()))

    max_total_vol = max(totals) if totals else 1.0

    # Inherited from the monthly-flow ranking, so a top-15 CNA is the same color
    # in both charts; the extra lanes this chart names stay gray.
    colors = sankey_lane_colors(all_items, rank_colors)

    title = f"CVE Contributions of Top CNAs ({range_label}) — MoM & YoY"
    if center_is_complete:
        subtitle = (
            f"Left: previous month, {prev_range_label} (MoM).  Center: {range_label}, "
            f"complete.  Right: {prev_year} same month (YoY).  "
            f"Sized by volume, sorted by {range_label} volume."
        )
    else:
        subtitle = (
            f"Left: previous month {prev_range_label} (MoM).  Center: current incomplete month.  "
            f"Right: {prev_year} same range (YoY).  Sized by volume, sorted by current-month volume."
        )

    return {
        "current_year": current_year,
        "prev_year": prev_year,
        "stages": stages,
        "stage_labels": stage_labels,
        "sorted_top_names": sorted_top_names,
        "all_items": all_items,
        "raw_data": raw_data,
        "exact_data": exact_data,
        "totals": totals,
        "display_totals": display_totals,
        "max_total_vol": max_total_vol,
        "colors": colors,
        "title": title,
        "subtitle": subtitle,
        "range_label": range_label,
        "prev_range_label": prev_range_label,
        "center_is_complete": center_is_complete,
    }


def plot_incomplete_month_sankey(
    data_2025_partial,
    data_2026_partial,
    prev_data_partial,
    top_names,
    range_label,
    prev_range_label,
    prev_year_str,
    anchor_date,
    output_filename="cve_monthly_stats_comparison_incomplete_month.png",
    center_is_complete=False,
    rank_colors=None,
):
    """
    Plots a custom Sankey flow visualization of the incomplete (current) month
    across three stops:
      1. previous month, same day-range (MoM)          — leftmost
      2. 2026, current incomplete month                — center (pivot)
      3. 2025, same day-range (YoY reference)          — rightmost

    ``center_is_complete`` flips the wording for a run where the pivot month has
    already ended (the 1st of the following month): the three columns are then
    whole months rather than matching slices of them.

    So the previous month flows into the current month, which is then compared to
    the same range in 2025. This mirrors the visual style of
    ``plot_custom_sankey_flow`` (stacked columns joined by tapering flow bands,
    sized by absolute volume). ``top_names`` should already include every top CNA
    of the previous month so that MoM contributors appear as their own lanes in
    all three stops rather than folded into "Others". ``rank_colors`` is the
    dashboard's CNA→color mapping (see ``sankey_rank_color_map``): a CNA in the
    year's top 15 wears the same color here as in the monthly-flow chart, and a
    lane named only for this chart gets the "Others" gray.
    """
    p = _prep_incomplete_sankey(
        data_2025_partial, data_2026_partial, prev_data_partial, top_names,
        range_label, prev_range_label, prev_year_str, anchor_date,
        center_is_complete=center_is_complete, rank_colors=rank_colors,
    )
    current_year = p["current_year"]
    prev_year = p["prev_year"]
    stages = p["stages"]
    sorted_top_names = p["sorted_top_names"]
    all_items = p["all_items"]
    stage_labels = p["stage_labels"]
    raw_data = p["raw_data"]
    totals = p["totals"]
    display_totals = p["display_totals"]
    max_total_vol = p["max_total_vol"]
    colors = p["colors"]

    # Compute stacked positions centered at y = 500, scaled by absolute volumes
    gap = 12
    num_items = len(all_items)
    max_avail_height = 1050 - (num_items - 1) * gap

    stage_positions = []
    for s, stage in enumerate(stages):
        volumes = raw_data[s]
        total_vol = totals[s]

        avail_height = (total_vol / max_total_vol) * max_avail_height
        stage_total_height = avail_height + (num_items - 1) * gap

        pos = {}
        curr_y = 475.0 + stage_total_height / 2.0
        for item in all_items:
            h = (volumes[item] / total_vol) * avail_height
            y_start = curr_y - h
            y_end = curr_y
            pos[item] = (y_start, y_end)
            curr_y = y_start - gap
        stage_positions.append(pos)

    # Plot. Width scales with the number of stops so columns sit far enough apart
    # for the (left-column) CNA name labels to clear the neighbouring column.
    plt.style.use("dark_background")
    fig_width = 9.0 + 4.5 * (len(stages) - 1)
    fig, ax = plt.subplots(figsize=(fig_width, 17.5), facecolor="#1E1E1E")
    ax.set_facecolor("#1E1E1E")

    def get_curve_points(x1, y1, x2, y2, num_points=100):
        cx1 = x1 + (x2 - x1) * 0.4
        cy1 = y1
        cx2 = x2 - (x2 - x1) * 0.4
        cy2 = y2
        t = np.linspace(0, 1, num_points)
        x = (1-t)**3 * x1 + 3*(1-t)**2*t * cx1 + 3*(1-t)*t**2 * cx2 + t**3 * x2
        y = (1-t)**3 * y1 + 3*(1-t)**2*t * cy1 + 3*(1-t)*t**2 * cy2 + t**3 * y2
        return x, y

    # Draw flow bands between stages
    for s in range(len(stages) - 1):
        x_s = s
        x_s1 = s + 1
        pos_s = stage_positions[s]
        pos_s1 = stage_positions[s + 1]

        for item in all_items:
            y_start_s, y_end_s = pos_s[item]
            y_start_s1, y_end_s1 = pos_s1[item]

            x_top, y_top = get_curve_points(x_s, y_end_s, x_s1, y_end_s1)
            x_bot, y_bot = get_curve_points(x_s, y_start_s, x_s1, y_start_s1)

            x_poly = np.concatenate([x_top, x_bot[::-1]])
            y_poly = np.concatenate([y_top, y_bot[::-1]])

            ax.fill(x_poly, y_poly, color=colors.get(item, "#747D8C"), alpha=0.35, edgecolor="none")

    # Draw stage blocks and labels
    for s, stage in enumerate(stages):
        x_pos = s
        pos = stage_positions[s]
        stage_data = stage["data"]
        for item in all_items:
            y_start, y_end = pos[item]
            y_center = (y_start + y_end) / 2.0

            if item == "Others":
                val = sum(v for k, v in stage_data.items() if k not in sorted_top_names)
            else:
                val = stage_data.get(item, 0)

            rect = plt.Rectangle((x_pos - 0.04, y_start), 0.08, y_end - y_start, facecolor=colors.get(item, "#747D8C"), edgecolor="none", zorder=3)
            ax.add_patch(rect)

            if val > 0:
                if item == "Others":
                    cna_count = sum(1 for k, v in stage_data.items() if k not in sorted_top_names and v > 0)
                    label_text = f"{val}\n[{cna_count}]"
                else:
                    label_text = f"{val}"
                txt = ax.text(
                    x_pos + 0.06,
                    y_center,
                    label_text,
                    ha="left",
                    va="center",
                    color="#FFFFFF",
                    fontsize=14,
                    fontweight="bold",
                    zorder=4
                )
                txt.set_path_effects([
                    path_effects.Stroke(linewidth=2, foreground='#1E1E1E'),
                    path_effects.Normal()
                ])

            # Label the CNA name once, in the left margin at the first column.
            if s == 0:
                ax.text(
                    x_pos - 0.06,
                    y_center,
                    item,
                    ha="right",
                    va="center",
                    color="#FFFFFF",
                    fontsize=18,
                    fontweight="bold"
                )

        ax.text(s, 1040, stage_labels[s], ha="center", va="bottom", color="#FFFFFF", fontsize=22.5, fontweight="bold")
        ax.text(s, 1012, f"({display_totals[s]:,})", ha="center", va="bottom", color="#A4B0BE", fontsize=18, fontweight="normal")

    # Title & Subtitle
    title_x = (len(stages) - 1) / 2.0
    ax.text(
        title_x, 1090,
        p["title"],
        ha="center",
        va="bottom",
        color="#FFFFFF",
        fontsize=26,
        fontweight="bold"
    )
    subtitle = p["subtitle"]
    ax.text(
        title_x, 1065,
        subtitle,
        ha="center",
        va="bottom",
        color="#A4B0BE",
        fontsize=15,
        style="italic"
    )

    ax.set_xlim(-1.1, len(stages) - 0.35)
    ax.set_ylim(-50, 1120)
    ax.axis("off")

    plt.tight_layout()
    _add_logo(fig)
    plt.savefig(
        output_filename,
        dpi=200,
        bbox_inches="tight",
        pad_inches=0,
        facecolor=fig.get_facecolor(),
        edgecolor="none"
    )
    plt.close()
    saved_files_log.append(f"Saved incomplete-month Sankey chart to {os.path.abspath(output_filename)}")


def _prep_ytd_growth(daily_counts_2025, daily_counts_2026, anchor_date_str):
    """Everything ``plot_ytd_growth`` draws, before any layout. Shared with the
    slide renderer (``monthly_slides``)."""
    current_year = int(anchor_date_str[:4])  # display year, derived from the data anchor
    prev_year = current_year - 1
    start_date = datetime(2026, 1, 1)
    try:
        end_date = datetime.strptime(anchor_date_str, "%Y-%m-%d")
    except ValueError:
        end_date = datetime.strptime(anchor_date_str[:10], "%Y-%m-%d")

    dates_2026 = []
    curr = start_date
    while curr <= end_date:
        dates_2026.append(curr)
        curr += timedelta(days=1)

    cumulative_2025 = 0
    cumulative_2026 = 0

    ytd_values_2025 = []
    ytd_values_2026 = []
    ytd_growth_pct = []
    ytd_growth_abs = []
    date_series = []
    daily_values_2025 = []
    daily_values_2026 = []

    for dt in dates_2026:
        key = dt.strftime("%m-%d")
        count_25 = daily_counts_2025.get(key, 0)
        count_26 = daily_counts_2026.get(key, 0)

        cumulative_2025 += count_25
        cumulative_2026 += count_26

        ytd_values_2025.append(cumulative_2025)
        ytd_values_2026.append(cumulative_2026)

        growth_abs = cumulative_2026 - cumulative_2025
        ytd_growth_abs.append(growth_abs)

        # Use additive smoothing in the denominator (adding a prior of 100)
        # to prevent extreme outliers on the first few days of the year when cumulative counts are tiny.
        growth_pct = (growth_abs / (cumulative_2025 + 100)) * 100
        ytd_growth_pct.append(growth_pct)
        date_series.append(dt)

        daily_values_2025.append(count_25)
        daily_values_2026.append(count_26)

    # Compute 30-day moving averages of daily counts
    ma_2025 = []
    ma_2026 = []
    for i in range(len(dates_2026)):
        start_idx = max(0, i - 30)
        window_size = i + 1 - start_idx
        ma_2025.append(sum(daily_values_2025[start_idx : i + 1]) / window_size)
        ma_2026.append(sum(daily_values_2026[start_idx : i + 1]) / window_size)

    # Compute overall YTD averages early to make them prominent in chart labels/lines
    days_count = len(dates_2026)
    final_speed_25 = cumulative_2025 / days_count if days_count > 0 else 0.0
    final_speed_26 = cumulative_2026 / days_count if days_count > 0 else 0.0

    return {
        "current_year": current_year,
        "prev_year": prev_year,
        "date_series": date_series,
        "ma_2025": ma_2025,
        "ma_2026": ma_2026,
        "ytd_values_2025": ytd_values_2025,
        "ytd_values_2026": ytd_values_2026,
        "cumulative_2025": cumulative_2025,
        "cumulative_2026": cumulative_2026,
        "final_speed_25": final_speed_25,
        "final_speed_26": final_speed_26,
    }


def plot_ytd_growth(daily_counts_2025, daily_counts_2026, anchor_date_str, output_filename="cve_monthly_stats_comparison_ytd_growth.png"):
    """
    Plots YTD growth over the same date in 2025 for all days in 2026 up to anchor_date_str.
    """
    p = _prep_ytd_growth(daily_counts_2025, daily_counts_2026, anchor_date_str)
    current_year = p["current_year"]
    prev_year = p["prev_year"]
    date_series = p["date_series"]
    ma_2025 = p["ma_2025"]
    ma_2026 = p["ma_2026"]
    final_speed_25 = p["final_speed_25"]
    final_speed_26 = p["final_speed_26"]

    # The fastest curve sets the axis, and the axis sets the figure height — at a
    # scale that never changes until the picture is square. See _speed_layout.
    y_top, fig_h = _speed_layout(max(ma_2025 + ma_2026, default=0))

    plt.style.use("dark_background")
    fig, ax = plt.subplots(1, 1, figsize=(_SPEED_FIG_W, fig_h), facecolor="#1E1E1E")
    ax.set_facecolor("#1E1E1E")

    ax.plot(date_series, ma_2025, color=C_BLUE, label=f"{prev_year} Daily Speed (30-day MA)", linewidth=2.5, alpha=0.85)
    ax.plot(date_series, ma_2026, color="#FF4757", label=f"{current_year} Daily Speed (30-day MA)", linewidth=3)
    ax.fill_between(date_series, ma_2025, color=C_BLUE, alpha=0.08)
    ax.fill_between(date_series, ma_2026, color="#FF4757", alpha=0.08)

    # Highlight 2026 YTD Avg Speed prominently on the chart
    ax.axhline(
        y=final_speed_26,
        color="#FF4757",
        linestyle="--",
        linewidth=2.5,
        alpha=0.9,
        label=f"{current_year} YTD Avg Speed ({final_speed_26:.1f}/day)"
    )
    # Highlight 2025 YTD Avg Speed less prominently for reference
    ax.axhline(
        y=final_speed_25,
        color=C_BLUE,
        linestyle=":",
        linewidth=1.5,
        alpha=0.6,
        label=f"{prev_year} YTD Avg Speed ({final_speed_25:.1f}/day)"
    )

    ax.legend(loc="upper left", facecolor="#262626", edgecolor="#444444", fontsize=13)

    ax.set_ylabel("Publishing Speed (CVEs/day)", fontsize=16, fontweight="bold", color="#FFFFFF")
    ax.set_title("CVE Publishing Speed YoY (30-Day Moving Average)", fontsize=18, fontweight="bold", color="#FFFFFF", pad=12)
    ax.grid(True, color="#444444", linestyle="--", alpha=0.5)

    # Explicit, not autoscaled: the figure height was computed from this exact
    # top, and letting matplotlib pick its own would break the two apart. The
    # bottom stays at 0 so no curve can read as a negative speed.
    ax.set_ylim(0, y_top)

    ax.xaxis.set_major_locator(mdates.MonthLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
    plt.xticks(rotation=0)

    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    for spine in ["left", "bottom"]:
        ax.spines[spine].set_color("#777777")
    ax.tick_params(colors="#CCCCCC", labelsize=13)

    plt.figtext(
        0.5,
        0.07 / fig_h,  # 0.07in off the bottom, wherever the bottom now is
        f"{_stamp()} | Data Source: Vulners CVE Archive",
        ha="center",
        fontsize=12,
        color="#747D8C",
        style="italic",
        fontweight="bold"
    )

    plt.tight_layout(rect=[0, 0.03, 1, 0.98])
    _pin_axes_height(fig, ax, _SPEED_AXES_TOP_IN, _SPEED_AXES_BOTTOM_IN)

    _add_logo(fig)
    plt.savefig(
        output_filename,
        bbox_inches="tight",
        pad_inches=0.1,
        dpi=200,
        facecolor=fig.get_facecolor(),
        edgecolor="none"
    )
    plt.close()
    saved_files_log.append(f"YTD growth comparison chart saved to {os.path.abspath(output_filename)}")


def _prep_yearly_cumulative(daily_counts, anchor_date_str):
    """Everything ``plot_yearly_cumulative`` draws, before any layout. Shared
    with the slide renderer (``monthly_slides``)."""
    # Construct reference dates for X-axis using a leap year (2024) to cover Feb 29
    start_ref = datetime(2024, 1, 1)
    ref_dates = []
    curr = start_ref
    while curr.year == 2024:
        ref_dates.append(curr)
        curr += timedelta(days=1)

    # Get anchor date in 2026
    try:
        anchor_date_2026 = datetime.strptime(anchor_date_str, "%Y-%m-%d")
    except ValueError:
        anchor_date_2026 = datetime.strptime(anchor_date_str[:10], "%Y-%m-%d")

    anchor_month = anchor_date_2026.month
    anchor_day = anchor_date_2026.day
    # Corresponding date in reference year 2024
    anchor_ref = datetime(2024, anchor_month, anchor_day)

    years = ["2022", "2023", "2024", "2025", "2026"]
    cumulative_series = {y: [] for y in years}
    dates_series = {y: [] for y in years}
    totals = {y: 0 for y in years}

    for y in years:
        cum = 0
        for ref_dt in ref_dates:
            # For 2026, we only plot up to the anchor ref date
            if y == "2026" and ref_dt > anchor_ref:
                break

            month_day_str = ref_dt.strftime("%m-%d")
            count_day = daily_counts[y].get(month_day_str, 0)
            cum += count_day
            cumulative_series[y].append(cum)
            dates_series[y].append(ref_dt)
        totals[y] = cum

    # Calculate daily speeds
    days_in_year = {
        "2022": 365,
        "2023": 365,
        "2024": 366,
        "2025": 365,
    }
    days_2026 = (anchor_date_2026 - datetime(2026, 1, 1)).days + 1

    avg_speeds = {}
    for y in ["2022", "2023", "2024", "2025"]:
        avg_speeds[y] = totals[y] / days_in_year[y] if days_in_year[y] > 0 else 0.0
    avg_speeds["2026"] = totals["2026"] / days_2026 if days_2026 > 0 else 0.0

    # Determine crossover moments when 2026 surpassed any previous year's total
    surpassed_info = []
    for prev_y in ["2022", "2023", "2024", "2025"]:
        prev_total = totals[prev_y]
        surpassed_idx = None
        for idx, val in enumerate(cumulative_series["2026"]):
            if val > prev_total:
                surpassed_idx = idx
                break
        if surpassed_idx is not None:
            surpassed_dt = dates_series["2026"][surpassed_idx]
            surpass_date_2026 = datetime(2026, surpassed_dt.month, surpassed_dt.day)
            # Interpolate the exact intersection (where the 2026 line meets the
            # guide at y = prev_total) so the star sits on the crossing point.
            cross_x = surpassed_dt
            if surpassed_idx > 0:
                v0 = cumulative_series["2026"][surpassed_idx - 1]
                v1 = cumulative_series["2026"][surpassed_idx]
                x0 = dates_series["2026"][surpassed_idx - 1]
                x1 = dates_series["2026"][surpassed_idx]
                if v1 != v0:
                    frac = min(max((prev_total - v0) / (v1 - v0), 0.0), 1.0)
                    cross_x = x0 + (x1 - x0) * frac
            surpassed_info.append({
                "prev_year": prev_y,
                "prev_total": prev_total,
                "ref_date": surpassed_dt,
                "cross_x": cross_x,
                "cross_y": prev_total,
                "date_str": surpass_date_2026.strftime("%B %d, %Y"),
                "short_date_str": surpass_date_2026.strftime("%b %d"),
                "cumulative_2026_val": cumulative_series["2026"][surpassed_idx]
            })

    # Horizontal guiding lines: any previous year whose full-year total 2026 has
    # already reached OR is within 95% of. Surpassed years additionally get a
    # star + "Surpassed ... on <date>" annotation below; approaching years
    # (95%-100%) show the guiding line only. The totals themselves live in the
    # legend, where every year has one — the guides only mark the few that are
    # in play, so labelling them on the right told a partial story twice.
    final_2026 = cumulative_series["2026"][-1] if cumulative_series["2026"] else 0
    guide_years = [
        y for y in ["2022", "2023", "2024", "2025"]
        if totals[y] > 0 and final_2026 >= 0.95 * totals[y]
    ]
    # End the guides at the "Jan" (next-year) tick rather than spanning the whole
    # axis / the label margin.
    guide_xmax = datetime(ref_dates[-1].year + 1, 1, 1)

    # The forecast finish line must stay in view, so the axis peaks at whichever
    # is taller: the tallest curve or the forecast.
    axis_peak = max(max(totals.values()) if totals else 0, FIRST_FORECAST_TOTAL)

    return {
        "ref_dates": ref_dates,
        "anchor_date_2026": anchor_date_2026,
        "years": years,
        "cumulative_series": cumulative_series,
        "dates_series": dates_series,
        "totals": totals,
        "avg_speeds": avg_speeds,
        "surpassed_info": surpassed_info,
        "final_2026": final_2026,
        "guide_years": guide_years,
        "guide_xmax": guide_xmax,
        "forecast_total": FIRST_FORECAST_TOTAL,
        "forecast_label": FIRST_FORECAST_LABEL,
        "axis_peak": axis_peak,
    }


def plot_yearly_cumulative(daily_counts, anchor_date_str, output_filename="cve_monthly_stats_comparison_yearly_cumulative.png"):
    """
    Plots cumulative CVEs for each year from 2022 to 2025 (full year) and 2026 (YTD up to anchor_date_str).
    Includes the average daily speed in the legend and highlights the moment 2026 surpassed any previous years' totals.
    """
    p = _prep_yearly_cumulative(daily_counts, anchor_date_str)
    ref_dates = p["ref_dates"]
    cumulative_series = p["cumulative_series"]
    dates_series = p["dates_series"]
    totals = p["totals"]
    avg_speeds = p["avg_speeds"]
    surpassed_info = p["surpassed_info"]

    # The tallest curve sets the axis, and the axis sets the figure height — at a
    # scale that never changes until the picture is square. See _cumulative_layout.
    y_top, fig_h = _cumulative_layout(p["axis_peak"])

    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(_CUM_FIG_W, fig_h), facecolor="#1E1E1E")
    ax.set_facecolor("#1E1E1E")

    colors = {
        "2022": YEAR_COLORS["2022"],
        "2023": YEAR_COLORS["2023"],
        "2024": YEAR_COLORS["2024"],
        "2025": YEAR_COLORS["2025"],
        "2026": YEAR_COLORS["2026"]
    }

    # Plot 2022-2025 curves
    for y in ["2022", "2023", "2024", "2025"]:
        ax.plot(
            dates_series[y],
            cumulative_series[y],
            color=colors[y],
            linewidth=2.5,
            alpha=0.85,
            label=f"{y} (Total: {totals[y]:,} | Avg: {avg_speeds[y]:.1f}/day)"
        )

    # Plot 2026 curve
    ax.plot(
        dates_series["2026"],
        cumulative_series["2026"],
        color=colors["2026"],
        linewidth=4.5,
        label=(
            f"{int(anchor_date_str[:4])} YTD "
            f"(Total: {totals['2026']:,} | Avg: {avg_speeds['2026']:.1f}/day)"
        )
    )

    # Horizontal guiding lines: any previous year whose full-year total 2026 has
    # already reached OR is within 95% of. Surpassed years additionally get a
    # star + "Surpassed ... on <date>" annotation below; approaching years
    # (95%-100%) show the guiding line only. The totals themselves live in the
    # legend, where every year has one — the guides only mark the few that are
    # in play, so labelling them on the right told a partial story twice.
    guide_years = p["guide_years"]
    guide_xmax = p["guide_xmax"]
    for prev_y in guide_years:
        prev_total = totals[prev_y]
        ax.hlines(
            y=prev_total,
            xmin=ref_dates[0],
            xmax=guide_xmax,
            color=colors[prev_y],
            linestyle="--",
            linewidth=1.5,
            alpha=0.6,
            zorder=1
        )

    # The FIRST mid-year forecast as a dashed finish line, labelled above its
    # right end where the top-right of the chart is clear until the current
    # year's curve gets there.
    forecast_total = p["forecast_total"]
    ax.hlines(
        y=forecast_total,
        xmin=ref_dates[0],
        xmax=guide_xmax,
        color="#FFFFFF",
        linestyle=(0, (6, 4)),
        linewidth=2.0,
        alpha=0.85,
        zorder=1
    )
    ax.annotate(
        f"{forecast_total:,}  {p['forecast_label']}",
        xy=(guide_xmax, forecast_total),
        xytext=(0, 6),
        textcoords="offset points",
        ha="right",
        va="bottom",
        fontsize=12,
        fontweight="bold",
        color="#FFFFFF",
        zorder=2
    )

    ax.grid(True, color="#444444", linestyle="--", alpha=0.5)
    ax.set_ylabel("Cumulative CVE Count", fontsize=16, fontweight="bold", color="#FFFFFF")
    ax.set_title("Year-over-Year Cumulative CVE Publications Comparison", fontsize=18, fontweight="bold", color="#FFFFFF", pad=28)
    ax.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: f"{int(x):,}"))
    # Explicit, not autoscaled: the figure height was computed from this exact
    # top, and letting matplotlib pick its own would break the two apart.
    ax.set_ylim(0, y_top)

    # No right-margin labels any more, so only enough room for the "Jan" tick.
    ax.set_xlim(ref_dates[0], ref_dates[-1] + timedelta(days=6))

    # Format X-axis to show month names
    ax.xaxis.set_major_locator(mdates.MonthLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
    plt.xticks(rotation=0)

    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    for spine in ["left", "bottom"]:
        ax.spines[spine].set_color("#777777")
    ax.tick_params(colors="#CCCCCC", labelsize=13)

    # Add legend
    legend = ax.legend(loc="upper left", facecolor="#262626", edgecolor="#444444", fontsize=13)

    # Crossover stars + annotations for years 2026 has actually surpassed. These
    # come last: the callouts are measured against the legend and the axes
    # transform, so both must already be final.
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    legend_bbox = legend.get_window_extent(renderer)
    for info in surpassed_info:
        prev_y = info["prev_year"]
        # Plot crossover star marker at the exact 2026 x guide intersection
        ax.plot(
            info["cross_x"],
            info["cross_y"],
            marker="*",
            color="#FFBB33",
            markersize=14,
            markeredgecolor="#FFFFFF",
            zorder=5
        )

        # Offset the callout up and to the left: a uniform offset keeps the arrow
        # lines parallel and prevents them from crossing. A high crossing lands
        # that box under the upper-left legend, so it flips to the clear space on
        # the right instead (mirroring the arc so the arrow still bows outward).
        ann = ax.annotate(
            f"Surpassed {prev_y} Total on {info['short_date_str']}",
            xy=(info["cross_x"], info["cross_y"]),
            xytext=(-50, 35),
            textcoords="offset points",
            ha="right",
            va="bottom",
            fontsize=12,
            fontweight="bold",
            color="#FFFFFF",
            bbox=dict(boxstyle="round,pad=0.4", fc="#262626", ec=colors[prev_y], alpha=0.9, lw=1.5),
            arrowprops=dict(arrowstyle="->", connectionstyle="arc3,rad=0.2", color=colors[prev_y], lw=1.5)
        )
        # Pad the measured text box to cover the rounded bbox drawn around it.
        if ann.get_window_extent(renderer).expanded(1.08, 1.25).overlaps(legend_bbox):
            ann.xyann = (50, 35)
            ann.set_horizontalalignment("left")
            ann.arrow_patch.set_connectionstyle("arc3,rad=-0.2")

    plt.figtext(
        0.5,
        0.09 / fig_h,  # 0.09in off the bottom, wherever the bottom now is
        f"{_stamp()} | Data Source: Vulners CVE Archive",
        ha="center",
        fontsize=12,
        color="#747D8C",
        style="italic",
        fontweight="bold"
    )

    plt.tight_layout(rect=[0, 0.03, 1, 0.98])
    _pin_axes_height(fig, ax, _CUM_AXES_TOP_IN, _CUM_AXES_BOTTOM_IN)
    _add_logo(fig)
    plt.savefig(
        output_filename,
        bbox_inches="tight",
        pad_inches=0.1,
        dpi=200,
        facecolor=fig.get_facecolor(),
        edgecolor="none"
    )
    plt.close()
    saved_files_log.append(f"Yearly cumulative comparison chart saved to {os.path.abspath(output_filename)}")


def _prep_projections(stats, completed_month_strs, slope, intercept, partial_stats=None, current_month_str=None, current_month_yoy_growth=None, anchor_date=None):
    """Everything ``plot_monthly_projections`` draws, before any layout. Shared
    with the slide renderer (``monthly_slides``)."""
    # Display years derived from the data anchor (falls back to the clock if unset).
    current_year = int(anchor_date[:4]) if anchor_date else datetime.now().year
    prev_year = current_year - 1
    months_list = [f"{i:02d}" for i in range(1, 13)]
    months_names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

    n_comp = len(completed_month_strs)
    last_comp_idx = n_comp - 1
    y_2025 = []
    y_2026_actual = []

    for i in range(12):
        month_str = months_list[i]
        val_25 = sum(stats[month_str]["2025"].values()) if stats and month_str in stats else 0
        y_2025.append(val_25)
        if i <= last_comp_idx:
            val_26 = sum(stats[month_str]["2026"].values()) if stats and month_str in stats else 0
            y_2026_actual.append(val_26)
        else:
            y_2026_actual.append(None)

    # Calculate total actual 2026
    all_g26_real = sum(y_2026_actual[:n_comp])

    # Compute projection adjustment factor to land on exactly 100,000 total CVEs.
    # ``cur_month_idx`` marks the running partial month — the one month past the
    # actuals whose rate is measured, not forecast. There is none when the anchor
    # month has closed (a run on the 1st): then every month after the last actual
    # is a pure projection and is starred as one.
    cur_month_idx = (
        int(current_month_str) - 1
        if (current_month_str and current_month_yoy_growth is not None)
        else -1
    )
    unadj_proj_sum = 0
    remaining_2025_sum = 0
    for i in range(12):
        if i > last_comp_idx:
            month_str = months_list[i]
            m_idx = i + 1
            # Use actual partial YoY for the current month
            if i == cur_month_idx and current_month_yoy_growth is not None:
                g_m = current_month_yoy_growth
            elif n_comp >= 2:
                g_m = slope * m_idx + intercept
            elif n_comp == 1:
                g_m = intercept
            else:
                g_m = 0.0
            g_m = clamp_growth(g_m)
            
            g25 = y_2025[i]
            unadj_proj_sum += g25 * (1 + g_m)
            remaining_2025_sum += g25
            
    total_unadj = all_g26_real + unadj_proj_sum
    diff = 100000 - total_unadj
    d_adj = diff / remaining_2025_sum if remaining_2025_sum > 0 else 0.0

    # Calculate actual and projected counts with adjustment and rounding correction
    temp_sum = all_g26_real
    remaining_indices = list(range(n_comp, 12))
    
    y_2026_full = list(y_2026_actual[:n_comp])
    yoy_2026 = []
    
    # Calculate YoY for completed months
    for i in range(n_comp):
        v25 = y_2025[i]
        v26 = y_2026_actual[i]
        yoy_2026.append(((v26 - v25) / v25 * 100) if v25 > 0 else 0.0)
        
    for idx, i in enumerate(remaining_indices):
        month_str = months_list[i]
        m_idx = i + 1
        # Use actual partial YoY for the current month
        if i == cur_month_idx and current_month_yoy_growth is not None:
            g_m = current_month_yoy_growth
        elif n_comp >= 2:
            g_m = slope * m_idx + intercept
        elif n_comp == 1:
            g_m = intercept
        else:
            g_m = 0.0
        g_m = clamp_growth(g_m) + d_adj
        
        g25 = y_2025[i]
        g26_proj = int(round(g25 * (1 + g_m)))
        
        # Rounding correction on the last month to land exactly on 100,000
        if idx == len(remaining_indices) - 1:
            g26_proj = 100000 - temp_sum
            g_m = (g26_proj - g25) / g25 if g25 > 0 else 0.0
            
        temp_sum += g26_proj
        y_2026_full.append(g26_proj)
        yoy_2026.append(g_m * 100)

    # Calculate Run-rate projection using completed (full) months' data
    y_2026_runrate = list(y_2026_actual[:n_comp])
    yoy_2026_runrate = list(yoy_2026[:n_comp])
    for i in range(n_comp, 12):
        m_idx = i + 1
        # Use actual partial YoY for the current month
        if i == cur_month_idx and current_month_yoy_growth is not None:
            g_m = current_month_yoy_growth
        elif n_comp >= 2:
            g_m = slope * m_idx + intercept
        elif n_comp == 1:
            g_m = intercept
        else:
            g_m = 0.0
        g_m = clamp_growth(g_m)
        g25 = y_2025[i]
        g26_proj = int(round(g25 * (1 + g_m)))
        y_2026_runrate.append(g26_proj)
        yoy_2026_runrate.append(g_m * 100)

    # Convert to cumulative counts for plotting
    y_2025_cum = []
    cum = 0
    for val in y_2025:
        cum += val
        y_2025_cum.append(cum)

    y_2026_full_cum = []
    cum = 0
    for val in y_2026_full:
        cum += val
        y_2026_full_cum.append(cum)

    y_2026_runrate_cum = []
    cum = 0
    for val in y_2026_runrate:
        cum += val
        y_2026_runrate_cum.append(cum)

    y_2026_actual_cum = []
    y_2026_proj_cum = [None] * 12
    y_2026_runrate_proj_cum = []
    yoy_2026_green = list(yoy_2026)
    
    for i in range(12):
        if i <= last_comp_idx:
            y_2026_actual_cum.append(y_2026_full_cum[i])
            if i == last_comp_idx:
                y_2026_runrate_proj_cum.append(y_2026_runrate_cum[i])
            else:
                y_2026_runrate_proj_cum.append(None)
        else:
            y_2026_runrate_proj_cum.append(y_2026_runrate_cum[i])
            y_2026_actual_cum.append(None)

    start_proj_idx = min(_BASELINE_PROJ_IDX - 1, last_comp_idx)
    # The green curve rides the actuals up to the month before _BASELINE_PROJ_IDX,
    # then projects with REFERENCE_PREDICTIONS from there to December.
    for i in range(start_proj_idx, _BASELINE_PROJ_IDX):
        y_2026_proj_cum[i] = y_2026_full_cum[i]

    anchor_i = _BASELINE_PROJ_IDX - 1
    cum_proj = (
        y_2026_proj_cum[anchor_i]
        if y_2026_proj_cum[anchor_i] is not None
        else y_2026_full_cum[anchor_i]
    )
    for i in range(_BASELINE_PROJ_IDX, 12):
        month_str = months_list[i]
        pred_val = REFERENCE_PREDICTIONS.get(month_str, 0)
        cum_proj += pred_val
        y_2026_proj_cum[i] = cum_proj
        
        v25 = y_2025[i]
        yoy_2026_green[i] = ((pred_val - v25) / v25 * 100) if v25 > 0 else 0.0

    # Hardcode December value to land exactly on 100,000 baseline target
    y_2026_proj_cum[11] = 100000


    return {
        "current_year": current_year,
        "prev_year": prev_year,
        "months_list": months_list,
        "months_names": months_names,
        "n_comp": n_comp,
        "last_comp_idx": last_comp_idx,
        "cur_month_idx": cur_month_idx,
        "start_proj_idx": start_proj_idx,
        "y_2025": y_2025,
        "y_2025_cum": y_2025_cum,
        "y_2026_actual_cum": y_2026_actual_cum,
        "y_2026_full_cum": y_2026_full_cum,
        "y_2026_runrate_cum": y_2026_runrate_cum,
        "y_2026_runrate_proj_cum": y_2026_runrate_proj_cum,
        "y_2026_proj_cum": y_2026_proj_cum,
        "yoy_2026": yoy_2026,
        "yoy_2026_runrate": yoy_2026_runrate,
        "yoy_2026_green": yoy_2026_green,
    }


def plot_monthly_projections(stats, completed_month_strs, slope, intercept, partial_stats=None, current_month_str=None, current_month_yoy_growth=None, anchor_date=None, output_filename="cve_monthly_stats_comparison_projection.png"):
    """
    Generates a cumulative monthly publication comparison chart for 2025 vs 2026,
    including trend projections for remaining 2026 months and MoM growth annotations.
    """
    p = _prep_projections(
        stats, completed_month_strs, slope, intercept,
        partial_stats=partial_stats, current_month_str=current_month_str,
        current_month_yoy_growth=current_month_yoy_growth, anchor_date=anchor_date,
    )
    current_year = p["current_year"]
    prev_year = p["prev_year"]
    months_list = p["months_list"]
    months_names = p["months_names"]
    n_comp = p["n_comp"]
    last_comp_idx = p["last_comp_idx"]
    cur_month_idx = p["cur_month_idx"]
    start_proj_idx = p["start_proj_idx"]
    y_2025_cum = p["y_2025_cum"]
    y_2026_actual_cum = p["y_2026_actual_cum"]
    y_2026_full_cum = p["y_2026_full_cum"]
    y_2026_runrate_cum = p["y_2026_runrate_cum"]
    y_2026_runrate_proj_cum = p["y_2026_runrate_proj_cum"]
    y_2026_proj_cum = p["y_2026_proj_cum"]
    yoy_2026 = p["yoy_2026"]
    yoy_2026_runrate = p["yoy_2026_runrate"]
    yoy_2026_green = p["yoy_2026_green"]

    # Plot
    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(20, 10), facecolor="#1E1E1E")
    ax.set_facecolor("#1E1E1E")

    # Plot 2025 as baseline
    ax.plot(months_names, y_2025_cum, color=C_BLUE, marker="o", linestyle="-", linewidth=3.0, alpha=0.7, zorder=2, label=f"{prev_year} Cumulative")
    
    # Plot 2026 Projected (100k Target Baseline) from May (or earlier if comp < May) onwards
    x_proj_green = months_names[start_proj_idx:]
    y_proj_green = y_2026_proj_cum[start_proj_idx:]
    
    ax.plot(x_proj_green, y_proj_green, color="#2ED573", marker="o", markerfacecolor="none", linestyle="--", linewidth=4.5, zorder=3, label=f"{current_year} Projected (100k Baseline)")

    # Plot 2026 Run-rate Projected
    x_proj_rr = months_names[last_comp_idx:]
    y_runrate_proj_plot = y_2026_runrate_proj_cum[last_comp_idx:]
    ax.plot(x_proj_rr, y_runrate_proj_plot, color="#FF4757", marker="o", markerfacecolor="none", linestyle="-.", linewidth=4.5, zorder=4, label=f"{current_year} Projected (Run-rate)")

    # Plot 2026 Actual (Z-order 5 to keep on top)
    x_actual = months_names[:n_comp]
    ax.plot(x_actual, y_2026_actual_cum[:n_comp], color="#FF4757", marker="o", linestyle="-", linewidth=4.5, zorder=5, label=f"{current_year} Cumulative (Actual)")

    # Annotate YoY percentages and values
    for i in range(12):
        is_proj = i > last_comp_idx
        
        if not is_proj:
            val = y_2026_actual_cum[i]
            yoy_val = yoy_2026[i]
            color = "#FF4757"
            
            month_str = months_list[i]
            ref_pred = REFERENCE_PREDICTIONS.get(month_str)
            
            # Adjust label offsets to prevent overlapping in early months
            if val >= y_2025_cum[i]:
                offset_25, va_25 = -18, "top"
                offset_yoy, va_yoy = 42, "bottom"
                offset_26, va_26 = 12, "bottom"
            else:
                offset_25, va_25 = 12, "bottom"
                offset_yoy, va_yoy = -48, "top"
                offset_26, va_26 = -18, "top"
            
            ax.annotate(
                f"{yoy_val:+5.1f}%",
                xy=(i, val),
                xytext=(0, offset_yoy),
                textcoords="offset points",
                ha="center",
                va=va_yoy,
                fontsize=15,
                fontweight="bold",
                color=color,
                bbox=dict(boxstyle="round,pad=0.2", fc="#262626", ec=color, alpha=0.8, lw=1.5, linestyle="solid")
            )
            
            # Also print cumulative values on top of points
            ax.annotate(
                f"{val:,}",
                xy=(i, val),
                xytext=(0, offset_26),
                textcoords="offset points",
                ha="center",
                va=va_26,
                fontsize=15,
                color="#FFFFFF"
            )
            
            # Print 2025 cumulative values as small text
            ax.annotate(
                f"{y_2025_cum[i]:,}",
                xy=(i, y_2025_cum[i]),
                xytext=(0, offset_25),
                textcoords="offset points",
                ha="center",
                va=va_25,
                fontsize=13.5,
                color="#A0A0A0"
            )

            # The baseline curve is a forecast for every month from
            # _BASELINE_PROJ_IDX on, including the ones the calendar has since
            # overtaken — that is the whole point of a fixed reference: you can
            # still see what it called for July once July has been and gone, and
            # how far the actual ran ahead of it. So each of those months keeps
            # its own label under the curve, not just the newest one.
            if i >= _BASELINE_PROJ_IDX:
                color_100k = "#2ED573"
                val_100k = y_2026_proj_cum[i]
                yoy_100k_val = yoy_2026_green[i]
                
                ax.annotate(
                    f"{yoy_100k_val:+5.1f}%*",
                    xy=(i, val_100k),
                    xytext=(0, -48),
                    textcoords="offset points",
                    ha="center",
                    va="top",
                    fontsize=15,
                    fontweight="bold",
                    color=color_100k,
                    bbox=dict(boxstyle="round,pad=0.2", fc="#262626", ec=color_100k, alpha=0.8, lw=1.5, linestyle="dashed")
                )
                
                ax.annotate(
                    f"{val_100k:,}*",
                    xy=(i, val_100k),
                    xytext=(0, -18),
                    textcoords="offset points",
                    ha="center",
                    va="top",
                    fontsize=15,
                    color="#FFFFFF"
                )
        else:
            val_runrate = y_2026_runrate_cum[i]
            yoy_runrate = yoy_2026_runrate[i]
            val_100k = y_2026_proj_cum[i]
            
            month_str = months_list[i]
            ref_pred = REFERENCE_PREDICTIONS.get(month_str)

            # Print 2025 cumulative values as small text
            if val_runrate >= y_2025_cum[i]:
                offset_25, va_25 = -18, "top"
            else:
                offset_25, va_25 = 12, "bottom"
            ax.annotate(
                f"{y_2025_cum[i]:,}",
                xy=(i, y_2025_cum[i]),
                xytext=(0, offset_25),
                textcoords="offset points",
                ha="center",
                va=va_25,
                fontsize=13.5,
                color="#A0A0A0"
            )

            # For projected months, annotate both Run-rate and Baseline labels centered above/below
            # Dynamically place the higher line's labels above, lower line's below
            yoy_100k_val = yoy_2026_green[i]
            color_rr = "#FF4757"
            color_100k = "#2ED573"

            # Both projected series ride the same steeply climbing segment, so a
            # label centred on its own point gets crossed by the curve arriving
            # from the lower left — and when the two curves nearly coincide their
            # four labels pile into one stack that says nothing about which line
            # owns which number. The two empty wedges around a rising point are
            # above-left and below-right: put the upper series' labels in the
            # first and the lower series' in the second. That clears the line and
            # separates the two series horizontally as well as vertically.
            LBL_DX = 12  # horizontal nudge, points
            if val_runrate >= val_100k:
                # Run-rate is higher (or equal) -> run-rate above-left, baseline below-right
                rr_dx, rr_ha = -LBL_DX, "right"
                rr_offset_yoy, rr_va_yoy = 42, "bottom"
                rr_offset_val, rr_va_val = 12, "bottom"
                bsl_dx, bsl_ha = LBL_DX, "left"
                bsl_offset_yoy, bsl_va_yoy = -48, "top"
                bsl_offset_val, bsl_va_val = -18, "top"
            else:
                # Baseline is higher -> baseline above-left, run-rate below-right
                bsl_dx, bsl_ha = -LBL_DX, "right"
                bsl_offset_yoy, bsl_va_yoy = 42, "bottom"
                bsl_offset_val, bsl_va_val = 12, "bottom"
                rr_dx, rr_ha = LBL_DX, "left"
                rr_offset_yoy, rr_va_yoy = -48, "top"
                rr_offset_val, rr_va_val = -18, "top"

            # Run-rate YoY% label. The current month's rate is measured against the
            # same slice of last year (see current_month_yoy_growth), so it is an
            # incomplete actual, not a forecast: keep the dotted frame to mark it
            # partial, but drop the '*', which the footer defines as a projection.
            # Later months' rates come off the regression and stay starred.
            yoy_rr_text = f"{yoy_runrate:+5.1f}%" if i == cur_month_idx else f"{yoy_runrate:+5.1f}%*"
            ax.annotate(
                yoy_rr_text,
                xy=(i, val_runrate),
                xytext=(rr_dx, rr_offset_yoy),
                textcoords="offset points",
                ha=rr_ha,
                va=rr_va_yoy,
                fontsize=15,
                fontweight="bold",
                color=color_rr,
                bbox=dict(boxstyle="round,pad=0.2", fc="#262626", ec="#FF4757", alpha=0.8, lw=1.5, linestyle="dotted")
            )

            # Run-rate value label
            ax.annotate(
                f"{val_runrate:,}*",
                xy=(i, val_runrate),
                xytext=(rr_dx, rr_offset_val),
                textcoords="offset points",
                ha=rr_ha,
                va=rr_va_val,
                fontsize=15,
                fontweight="bold" if i == 11 else "normal",
                color="#FFFFFF"
            )

            # Baseline YoY% label
            ax.annotate(
                f"{yoy_100k_val:+5.1f}%*",
                xy=(i, val_100k),
                xytext=(bsl_dx, bsl_offset_yoy),
                textcoords="offset points",
                ha=bsl_ha,
                va=bsl_va_yoy,
                fontsize=15,
                fontweight="bold",
                color=color_100k,
                bbox=dict(boxstyle="round,pad=0.2", fc="#262626", ec=color_100k, alpha=0.8, lw=1.5, linestyle="dashed")
            )

            # Baseline value label
            ax.annotate(
                f"{val_100k:,}*",
                xy=(i, val_100k),
                xytext=(bsl_dx, bsl_offset_val),
                textcoords="offset points",
                ha=bsl_ha,
                va=bsl_va_val,
                fontsize=15,
                color="#FFFFFF"
            )

    ax.set_ylabel("Cumulative CVE Count", fontsize=22.5, fontweight="bold", color="#FFFFFF")  # 150% of 15
    ax.set_title(f"Cumulative Monthly CVE Publications: {prev_year} vs {current_year} Projections", fontsize=27, fontweight="bold", color="#FFFFFF", pad=20)
    ax.grid(True, color="#444444", linestyle="--", alpha=0.5)
    ax.legend(loc="upper left", facecolor="#262626", edgecolor="#444444", fontsize=18)  # 150% of 12
    ax.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: f"{int(x):,}"))
    
    # Increase the y-axis limit by 15% to leave headroom at the top for labels, preventing overlap with the title.
    # The baseline curve has to be in the max as well: while any month is still
    # projected the two agree at December, but once every month is actual (the
    # frozen full-year run) the baseline is the only line reaching 100k and would
    # otherwise be cropped out of the frame.
    max_val = max(
        [*y_2026_full_cum, *y_2026_runrate_cum]
        + [v for v in y_2026_proj_cum if v is not None]
    )
    ax.set_ylim(bottom=0, top=max_val * 1.15)
    # Tight x-axis limits to use the full width, with enough room on the right
    # for December's below-right labels to stay inside the plot rather than hang
    # off the edge (and quietly widen the saved canvas via bbox_inches="tight").
    ax.set_xlim(-0.3, 11.8)

    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    for spine in ["left", "bottom"]:
        ax.spines[spine].set_color("#777777")
    ax.tick_params(colors="#CCCCCC", labelsize=18)  # 150% of 12

    # Two lines: the legend notes already fill the width at this font size, so
    # the date stamp gets its own line rather than overflowing the figure.
    footer_text = (
        f"* Dashed/dash-dotted lines and '*' values = projections | "
        f"YoY = Year-over-Year monthly growth\n"
        f"{_stamp()}"
    )
    fig.text(
        0.5, 0.01,
        footer_text,
        ha="center",
        va="bottom",
        fontsize=16.5,
        color="#747D8C",
        style="italic",
        fontweight="bold"
    )

    plt.tight_layout(rect=[0, 0.07, 1, 1])  # room for the two-line footer
    _add_logo(fig)
    plt.savefig(
        output_filename,
        bbox_inches="tight",
        pad_inches=0.1,
        dpi=200,
        facecolor=fig.get_facecolor(),
        edgecolor="none"
    )
    plt.close()
    saved_files_log.append(f"Monthly projection chart saved to {os.path.abspath(output_filename)}")

def plot_cumulative_contribution_2026(daily_cna_counts_2026, anchor_date_str, output_filename="cve_monthly_stats_comparison_cna_cumulative.png"):
    """
    Generates a stacked area chart showing the cumulative contribution of the top 2026 CNAs
    to the total set of CVEs in 2026, with "Others" at the bottom.
    """
    start_date = datetime(2026, 1, 1)
    try:
        end_date = datetime.strptime(anchor_date_str, "%Y-%m-%d")
    except ValueError:
        end_date = datetime.strptime(anchor_date_str[:10], "%Y-%m-%d")

    dates_2026 = []
    curr = start_date
    while curr <= end_date:
        dates_2026.append(curr)
        curr += timedelta(days=1)

    # Determine top CNAs by total volume in 2026
    cna_totals = {}
    for cna, counts in daily_cna_counts_2026.items():
        cna_totals[cna] = sum(counts.values())

    # Sort in descending order of volume
    sorted_cnas = sorted(cna_totals.items(), key=lambda x: x[1], reverse=True)
    
    # We use the same TOP_N (15) as the rest of the script
    top_cnas = [cna for cna, total in sorted_cnas[:TOP_N]]

    # Initialize running cumulative counts
    cumulative_counts = {cna: 0 for cna in top_cnas}
    cumulative_others = 0

    y_data = {cna: [] for cna in top_cnas}
    y_others = []

    for dt in dates_2026:
        day_key = dt.strftime("%m-%d")
        
        # Cumulative for top CNAs
        for cna in top_cnas:
            cumulative_counts[cna] += daily_cna_counts_2026[cna].get(day_key, 0)
            y_data[cna].append(cumulative_counts[cna])
            
        # Cumulative for Others
        daily_others = 0
        for cna, counts in daily_cna_counts_2026.items():
            if cna not in top_cnas:
                daily_others += counts.get(day_key, 0)
        cumulative_others += daily_others
        y_others.append(cumulative_others)

    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(14, 8), facecolor="#1E1E1E")
    ax.set_facecolor("#1E1E1E")

    # Vibrant dark-theme friendly palette of 16 colors (Others + 15 top CNAs)
    colors = [
        "#57606F",  # Others (sleek dark grey at the bottom)
        "#FF4757",  # Red
        "#1E90FF",  # Blue
        "#2ED573",  # Green
        "#FFA502",  # Orange
        "#D980FA",  # Lavender
        "#12CBC4",  # Cyan
        "#FDA7DF",  # Pink
        "#ECCC68",  # Gold
        "#3742FA",  # Indigo
        "#70A1FF",  # Light Blue
        "#FA8231",  # Salmon
        "#A3CB38",  # Lime
        "#ED4C67",  # Magenta
        "#9B59B6",  # Amethyst Purple
        "#1abc9c",  # Turquoise
    ]

    # Stack layers: Others at the bottom, then top CNAs
    # To match stack order visually (bottom to top), we pass:
    # y_others, then y_data for each CNA in top_cnas
    stack_y = [y_others] + [y_data[cna] for cna in top_cnas]
    stack_labels = [f"Others ({cumulative_others:,})"] + [f"{cna} ({cumulative_counts[cna]:,})" for cna in top_cnas]

    ax.stackplot(
        dates_2026,
        stack_y,
        labels=stack_labels,
        colors=colors[:len(top_cnas) + 1],
        alpha=0.85
    )

    ax.set_ylabel("Cumulative CVE Count", fontsize=16, fontweight="bold", color="#FFFFFF")
    ax.set_title("2026 Cumulative Contribution of CNAs to Total CVEs", fontsize=18, fontweight="bold", color="#FFFFFF", pad=20)
    ax.grid(True, color="#444444", linestyle="--", alpha=0.5)

    # Place legend on the right side
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1), facecolor="#262626", edgecolor="#444444", fontsize=11)
    
    # Format Y axis with commas
    ax.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: f"{int(x):,}"))
    ax.set_ylim(bottom=0)

    # X axis formatting (months)
    ax.xaxis.set_major_locator(mdates.MonthLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
    plt.xticks(rotation=0)

    # Adjust spines
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    for spine in ["left", "bottom"]:
        ax.spines[spine].set_color("#777777")
    ax.tick_params(colors="#CCCCCC", labelsize=13)

    plt.figtext(
        0.5,
        0.01,
        f"{_stamp()} | Data Source: Vulners CVE Archive",
        ha="center",
        fontsize=12,
        color="#747D8C",
        style="italic",
        fontweight="bold"
    )

    plt.tight_layout(rect=[0, 0.03, 1, 0.98])
    _add_logo(fig)
    plt.savefig(
        output_filename,
        bbox_inches="tight",
        pad_inches=0.1,
        dpi=200,
        facecolor=fig.get_facecolor(),
        edgecolor="none"
    )
    plt.close()
    saved_files_log.append(f"Yearly cumulative contribution chart saved to {os.path.abspath(output_filename)}")


# ── NVD status charts ────────────────────────────────────────────────────────

def _prep_status_yearly(status_yearly, anchor_date):
    """Everything ``plot_status_yearly_bar`` draws, before any layout; ``None``
    when there is nothing to draw. Shared with the slide renderer."""
    years = sorted(int(y) for y in status_yearly if y.isdigit() and int(y) >= STATUS_START_YEAR)
    if not years:
        return None
    values = {
        s: [status_yearly[str(y)].get(s, 0) for y in years] for s in STATUS_BAR_ORDER
    }
    totals = [sum(values[s][i] for s in STATUS_BAR_ORDER) for i in range(len(years))]
    anchor_year = int(anchor_date[:4])
    # The last bar is a running total unless the anchor closed its year.
    year_complete = anchor_date[5:10] == "12-31"
    end_label = f"{years[-1]} YTD" if years[-1] == anchor_year and not year_complete else str(years[-1])
    return {
        "years": years,
        "values": values,
        "totals": totals,
        "start_year": years[0],
        "end_label": end_label,
        "anchor_year": anchor_year,
        "statuses": list(STATUS_BAR_ORDER),
        "colors": [STATUS_COLORS[s] for s in STATUS_BAR_ORDER],
    }


def _prep_status_weekly(status_weekly, anchor_date):
    """Everything ``plot_status_stacked_charts`` draws, before any layout;
    ``None`` when there is nothing to draw. Shared with the slide renderer.

    Weeks run Monday to Sunday. The picture starts on the first Monday on or
    after ``STATUS_WEEKLY_START`` and ends on the Sunday of the last week that
    is *entirely* on or before the anchor — a week still running is never drawn.
    """
    anchor = date.fromisoformat(anchor_date[:10])
    first = date.fromisoformat(STATUS_WEEKLY_START)
    first += timedelta(days=(7 - first.weekday()) % 7)      # first Monday on/after
    last_sunday = anchor - timedelta(days=(anchor.weekday() + 1) % 7)
    last_start = last_sunday - timedelta(days=6)
    weeks = []
    w = first
    while w <= last_start:
        weeks.append(w)
        w += timedelta(days=7)
    if not weeks:
        return None

    counts = [status_weekly.get(w.isoformat(), {}) for w in weeks]
    y_absolute = [[c.get(s, 0) for c in counts] for s in STATUS_STACK_ORDER]
    week_totals = [sum(col) for col in zip(*y_absolute)]
    y_normalized = [
        [(v / t * 100.0) if t > 0 else 0.0 for v, t in zip(series, week_totals)]
        for series in y_absolute
    ]
    return {
        "weeks": weeks,
        "dates": [datetime(w.year, w.month, w.day) for w in weeks],
        "statuses": list(STATUS_STACK_ORDER),
        "colors": [STATUS_COLORS[s] for s in STATUS_STACK_ORDER],
        "y_absolute": y_absolute,
        "y_normalized": y_normalized,
        "week_totals": week_totals,
        "start_str": weeks[0].isoformat(),
        "end_str": (weeks[-1] + timedelta(days=6)).isoformat(),
    }


def _write_status_csvs(status_yearly, status_weekly):
    """Local-only CSV companions of the two status charts (all statuses, every
    week/year counted, the way the standalone script wrote them)."""
    all_statuses = sorted({s for c in status_yearly.values() for s in c} | {s for c in status_weekly.values() for s in c})
    with open("cve_monthly_stats_comparison_status_yearly_counts.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["year"] + all_statuses + ["total"])
        writer.writeheader()
        for year in sorted(status_yearly):
            counts = status_yearly[year]
            row = {"year": year, "total": sum(counts.values())}
            row.update({s: counts.get(s, 0) for s in all_statuses})
            writer.writerow(row)
    with open("cve_monthly_stats_comparison_status_weekly_counts.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["week_start"] + all_statuses + ["total"])
        writer.writeheader()
        for week in sorted(status_weekly):
            counts = status_weekly[week]
            row = {"week_start": week, "total": sum(counts.values())}
            row.update({s: counts.get(s, 0) for s in all_statuses})
            writer.writerow(row)
    saved_files_log.append(f"Saved status CSVs to {os.path.abspath('cve_monthly_stats_comparison_status_weekly_counts.csv')} and cve_monthly_stats_comparison_status_yearly_counts.csv")


def _write_fanout_csv(fanout_records, output_filename="cve_monthly_stats_comparison_fanout_downstream.csv"):
    """The shortlist's downstream counts, so the pick can be sanity-checked:
    one row per candidate with distinct records, issuers, and the top issuers."""
    rows = []
    for cve_id in FANOUT_SHORTLIST:
        rec = fanout_records.get(cve_id)
        if rec is None:
            rows.append({"cve": cve_id, "note": "not in archive"})
            continue
        groups = fanout_breakdown(rec["references"])
        counts = sorted(((g, len(ids)) for g, ids in groups.items()), key=lambda gc: (-gc[1], gc[0]))
        audit_rows, audit_totals = fanout_packages(fetch_audit_cve(cve_id))
        rows.append({
            "audit_package_updates": audit_totals["updates"] if audit_rows else "",
            "audit_products": audit_totals["products"] if audit_rows else "",
            "audit_releases": audit_totals["releases"] if audit_rows else "",
            "audit_advisories": audit_totals["advisories"] if audit_rows else "",
            "audit_top_products": "; ".join(f"{r['product']}={r['updates']}" for r in audit_rows[:6]),
            "cve": cve_id,
            "published": rec["published"],
            "reporter": rec["reporter"],
            "software": "; ".join(rec["software"][:3]),
            "kev_vulncheck": rec["kev"],
            "downstream_records": sum(c for _, c in counts),
            "issuers": len(counts),
            "raw_reference_ids": sum(len(r["idList"]) for r in rec["references"]),
            "top_issuers": "; ".join(f"{g}={c}" for g, c in counts[:8]),
            "picked": cve_id == FANOUT_CVE,
            "note": rec["short"][:120],
        })
    fields = ["cve", "published", "reporter", "software", "kev_vulncheck",
              "audit_package_updates", "audit_products", "audit_releases", "audit_advisories", "audit_top_products",
              "downstream_records", "issuers", "raw_reference_ids", "top_issuers", "picked", "note"]
    with open(output_filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})
    saved_files_log.append(f"Saved fan-out shortlist CSV to {os.path.abspath(output_filename)}")


def plot_status_yearly_bar(status_yearly, anchor_date, output_filename="cve_monthly_stats_comparison_status_yearly.png"):
    """Yearly stacked bar chart of NVD statuses, ``STATUS_START_YEAR`` through
    the anchor year. Ported from cve_status_stats.py; the years run to the
    anchor (the last full day) like every other chart here."""
    p = _prep_status_yearly(status_yearly, anchor_date)
    if p is None:
        return
    sorted_years, statuses, colors = p["years"], p["statuses"], p["colors"]

    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(15, 9.5), facecolor="#1E1E1E")
    ax.set_facecolor("#1E1E1E")

    x = np.arange(len(sorted_years))
    bar_width = 0.76

    bottoms = np.zeros(len(sorted_years))
    for status, color in zip(statuses, colors):
        vals = np.array(p["values"][status])
        ax.bar(
            x, vals, bar_width, bottom=bottoms, label=status, color=color,
            edgecolor="#1E1E1E", linewidth=1.2, alpha=0.92,
        )
        bottoms += vals

    # Annotate total counts above each bar
    for i, total in enumerate(bottoms):
        ax.annotate(
            f"{int(total):,}", xy=(x[i], total), xytext=(0, 8), textcoords="offset points",
            ha="center", va="bottom", fontsize=15.5, fontweight="bold", color="#FFFFFF",
        )

    ax.set_xticks(x)
    ax.set_xticklabels([str(y) for y in sorted_years], fontsize=16, fontweight="bold", color="#E0E0E0")
    ax.tick_params(colors="#CCCCCC", labelsize=14, pad=8)
    ax.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda val, pos: f"{int(val):,}"))
    for label in ax.get_yticklabels():
        label.set_fontweight("bold")

    ax.set_ylabel("Number of CVEs", fontsize=17, fontweight="bold", color="#FFFFFF", labelpad=12)
    ax.set_title(
        f"CVE Publication Volume by NVD Status ({p['start_year']} – {p['end_label']})",
        fontsize=22, fontweight="bold", color="#FFFFFF", pad=20,
    )
    ax.grid(True, axis="y", color="#444444", linestyle="--", alpha=0.6, linewidth=0.9)
    ax.set_axisbelow(True)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    for spine in ["left", "bottom"]:
        ax.spines[spine].set_color("#555555")

    # Legend across the bottom, starting right of the logo's corner.
    handles, labels = ax.get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="lower center", bbox_to_anchor=(0.08, 0.045, 0.90, 0.05),
        mode="expand", ncol=6, facecolor="#262626", edgecolor="#444444", fontsize=16,
        handletextpad=0.6, borderpad=0.5, framealpha=0.95,
    )
    ax.set_ylim(0, max(bottoms) * 1.08)

    plt.figtext(
        0.5, 0.008, f"{_stamp()} | Data Source: Vulners CVE Archive",
        ha="center", fontsize=12, color="#747D8C", style="italic", fontweight="bold",
    )
    plt.tight_layout(rect=[0.01, 0.11, 0.99, 0.98])
    fig.subplots_adjust(bottom=0.16)
    _add_logo(fig)
    plt.savefig(output_filename, dpi=200, bbox_inches="tight", facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close()
    saved_files_log.append(f"Yearly status bar chart saved to {os.path.abspath(output_filename)}")


def plot_status_stacked_charts(status_weekly, anchor_date, output_filename="cve_monthly_stats_comparison_status_weekly.png"):
    """Absolute and normalized weekly stacked-area charts of NVD statuses in one
    figure, sharing a legend. Ported from cve_status_stats.py; the weeks run
    from the first full week of ``STATUS_WEEKLY_START`` to the last full week
    before the anchor (see ``_prep_status_weekly``)."""
    p = _prep_status_weekly(status_weekly, anchor_date)
    if p is None:
        return
    dates, statuses, colors = p["dates"], p["statuses"], p["colors"]

    plt.style.use("dark_background")
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 18), facecolor="#1E1E1E")
    ax1.set_facecolor("#1E1E1E")
    ax2.set_facecolor("#1E1E1E")

    def _style(ax):
        ax.grid(True, color="#444444", linestyle="--", alpha=0.5)
        ax.set_xlim(dates[0], dates[-1])
        ax.xaxis.set_major_locator(mdates.MonthLocator(bymonth=(1, 4, 7, 10)))
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %Y"))
        for label in ax.get_xticklabels():
            label.set_rotation(40)
            label.set_horizontalalignment("right")
            label.set_fontweight("bold")
        for label in ax.get_yticklabels():
            label.set_fontweight("bold")
        for spine in ["top", "right"]:
            ax.spines[spine].set_visible(False)
        for spine in ["left", "bottom"]:
            ax.spines[spine].set_color("#777777")
        ax.tick_params(colors="#CCCCCC", labelsize=16.5)

    # 1. Absolute Stacked Area Chart (Top Subplot)
    ax1.stackplot(dates, p["y_absolute"], labels=statuses, colors=colors, alpha=0.85, edgecolor="#1E1E1E", linewidth=0.5)
    ax1.set_title("Absolute Status Counts", fontsize=20, fontweight="bold", color="#FFFFFF", pad=15)
    ax1.set_ylabel("Number of CVEs", fontsize=21, fontweight="bold", color="#FFFFFF")
    ax1.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: f"{int(x):,}"))
    _style(ax1)

    # 2. Normalized Stacked Area Chart (Bottom Subplot)
    ax2.stackplot(dates, p["y_normalized"], labels=statuses, colors=colors, alpha=0.85, edgecolor="#1E1E1E", linewidth=0.5)
    ax2.set_title("Normalized Status Distribution", fontsize=20, fontweight="bold", color="#FFFFFF", pad=15)
    ax2.set_ylabel("Percentage (%)", fontsize=21, fontweight="bold", color="#FFFFFF")
    ax2.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: f"{int(x)}%"))
    ax2.set_ylim(0, 100)
    _style(ax2)

    fig.suptitle(
        f"CVE Weekly Status Analysis: Absolute vs. Normalized Stacked Trends\n({p['start_str']} to {p['end_str']})",
        fontsize=26, fontweight="bold", color="#FFFFFF", y=0.98,
    )

    # Shared legend at the bottom, nudged right of the logo's corner.
    handles, labels = ax1.get_legend_handles_labels()
    fig.legend(
        reversed(handles), reversed(labels), loc="lower center", ncol=6,
        facecolor="#262626", edgecolor="#444444", fontsize=17.5, bbox_to_anchor=(0.53, 0.025),
    )
    plt.figtext(
        0.5, 0.005, f"{_stamp()} | Data Source: Vulners CVE Archive",
        ha="center", fontsize=13, color="#747D8C", style="italic", fontweight="bold",
    )

    plt.tight_layout(rect=[0.01, 0.06, 0.99, 0.98])
    fig.subplots_adjust(top=0.89)
    _add_logo(fig)
    plt.savefig(output_filename, bbox_inches="tight", pad_inches=0.1, dpi=200, facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close()
    saved_files_log.append(f"Combined stacked status chart saved to {os.path.abspath(output_filename)}")


# Top sources (by overall reach) shown as rows in the candidate heatmap; the
# long tail is aggregated into an "other sources" row so nothing is dropped.
_CAND_TOP_SOURCES = 12


def _prep_candidate_track(candidate_stats):
    """Everything ``plot_candidate_track`` draws, before any layout; ``None``
    when there is nothing to draw. Shared with the slide renderer
    (``monthly_slides``)."""
    months = sorted(candidate_stats.keys())
    if not months:
        return None

    totals = {m: candidate_stats[m]["active"] + candidate_stats[m]["rejected"] for m in months}
    grand_total = sum(totals.values())
    overall = collections.Counter()
    for m in months:
        overall.update(candidate_stats[m]["ref_types"])

    top_sources = [s for s, _ in overall.most_common(_CAND_TOP_SOURCES)]
    top_set = set(top_sources)
    other_per_month = {
        m: sum(v for s, v in candidate_stats[m]["ref_types"].items() if s not in top_set)
        for m in months
    }
    rows = list(top_sources)
    if any(other_per_month.values()):
        rows.append("other sources")

    def cell(source, m):
        return other_per_month[m] if source == "other sources" else candidate_stats[m]["ref_types"].get(source, 0)

    mat = np.array([[cell(s, m) for m in months] for s in rows], dtype=float)
    # Anchor the colour scale to individual top sources (not the aggregated
    # "other" row) so one big residual doesn't wash everything else out.
    vmax = max(1.0, mat[:len(top_sources)].max() if top_sources else mat.max())

    return {
        "months": months,
        "totals": totals,
        "grand_total": grand_total,
        "top_sources": top_sources,
        "rows": rows,
        "mat": mat,
        "vmax": vmax,
        "year": months[0][:4],
    }


def plot_candidate_track(candidate_stats, output_filename="cve_monthly_stats_comparison_candidate_track.png"):
    """Heatmap of the hidden reserved/candidate CVE backlog. Rows are the top
    sources feeding it (ranked by how many reserved CVEs each touches overall),
    columns are months, and each cell is the reserved CVEs that source touches
    that month. A new source shows up as a row that stays dark until it lights up.
    Scales to any number of months (each month is one more column)."""
    p = _prep_candidate_track(candidate_stats)
    if p is None:
        return
    months = p["months"]
    totals = p["totals"]
    grand_total = p["grand_total"]
    rows = p["rows"]
    mat = p["mat"]
    vmax = p["vmax"]

    plt.style.use("dark_background")
    fig, ax = plt.subplots(
        figsize=(max(13, len(months) * 1.35 + 3.5), len(rows) * 0.62 + 3.2),
        facecolor="#1E1E1E",
    )
    ax.set_facecolor("#1E1E1E")
    ax.imshow(mat, aspect="auto", cmap="inferno", vmin=0, vmax=vmax)

    mlabels = [f"{datetime.strptime(m, '%Y-%m').strftime('%b')}\n{totals[m]:,} CVEs" for m in months]
    ax.set_xticks(range(len(months)))
    ax.set_xticklabels(mlabels, fontsize=19.5, fontweight="bold", color="#FFFFFF")
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(rows, fontsize=12.5, fontweight="bold", color="#FFFFFF")
    # Months and monthly totals across the top of the chart.
    ax.xaxis.set_ticks_position("top")
    ax.tick_params(axis="x", labeltop=True, labelbottom=False, length=0)
    ax.tick_params(axis="y", length=0)

    for i in range(len(rows)):
        for j in range(len(months)):
            v = int(mat[i, j])
            if v > 0:
                ax.text(
                    j, i, f"{v}", ha="center", va="center", fontsize=16, fontweight="bold",
                    color="#111111" if mat[i, j] > vmax * 0.5 else "#EAEAEA",
                )

    year = p["year"]
    ax.set_title(
        f"Hidden Volume: Who Feeds the Reserved (Candidate) Backlog  ·  {grand_total:,} CVEs in {year}\n"
        "cell = reserved CVEs each source touches that month",
        color="#FFFFFF", fontsize=18, fontweight="bold", pad=64,
    )
    for s in ("top", "right", "left", "bottom"):
        ax.spines[s].set_visible(False)
    ax.set_xticks(np.arange(-0.5, len(months), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(rows), 1), minor=True)
    ax.grid(which="minor", color="#1E1E1E", linewidth=3)
    ax.tick_params(which="minor", length=0)

    plt.figtext(
        0.5, 0.02,
        f"{_stamp()} | Data Source: Vulners CVE Archive",
        ha="center", fontsize=12, color="#747D8C", style="italic", fontweight="bold",
    )
    plt.tight_layout(rect=[0, 0.04, 1, 1])
    _add_logo(fig)
    plt.savefig(output_filename, dpi=200, bbox_inches="tight", facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close()
    saved_files_log.append(f"Saved candidate track chart to {os.path.abspath(output_filename)}")


def generate(archive_path, out_dir):
    """Run the monthly analysis and build its charts + report.

    Reads the already-downloaded ``archive_path`` (never downloads), writes the
    six chart PNGs into ``out_dir``, captures the aligned-table report to a
    string, and returns a :class:`DashboardResult`. No CSV/TXT/Sankey-text files
    and no data acquisition happen here — those are the orchestrator's job.
    """
    archive_path = os.path.abspath(archive_path)
    os.makedirs(out_dir, exist_ok=True)

    results = count_monthly_cves(archive_path, cut_off_date=CUT_OFF_DATE)
    if not results:
        return None

    report_buf = io.StringIO()
    prev_cwd = os.getcwd()
    os.chdir(out_dir)  # charts use relative filenames -> land in out_dir
    try:
        _run_monthly(results, report_buf)
    finally:
        os.chdir(prev_cwd)

    captions = dict(CHART_CAPTIONS)
    if results.get("anchor_month_complete"):
        captions["cve_monthly_stats_comparison_incomplete_month.png"] = COMPLETE_MONTH_CAPTION

    charts = [
        {
            "file": os.path.join(out_dir, name),
            "caption": captions.get(name, ""),
            "anchor": CHART_LINKS.get(name, ("", ""))[0],
            "label": CHART_LINKS.get(name, ("", ""))[1],
        }
        for name in CHART_FILES
        if os.path.exists(os.path.join(out_dir, name))
    ]
    return DashboardResult(
        slug="monthly",
        title="Monthly CVE Statistics by CNA",
        blurb=MONTHLY_BLURB,
        charts=charts,
        report_text=report_buf.getvalue(),
    )


class MonthlyDashboard(Dashboard):
    slug = "monthly"
    title = "Monthly CVE Statistics by CNA"

    def generate(self, archive_path, out_dir):
        return generate(archive_path, out_dir)


def _run_monthly(results, report_buf):
    """The original main() body: builds data, prints tables (captured into
    ``report_buf``), and generates the six charts into the current directory."""
    stats = results["stats"]
    partial_stats = results["partial_stats"]
    current_month_str = results["current_month"]
    current_day = results["current_day"]
    anchor_date = results["anchor_date"]
    anchor_month_complete = results.get("anchor_month_complete", False)
    daily_counts_2025 = results["daily_counts_2025"]
    daily_counts_2026 = results["daily_counts_2026"]
    daily_counts = results["daily_counts"]

    # Month names mapping
    months_map = {
        "01": "January",
        "02": "February",
        "03": "March",
        "04": "April",
        "05": "May",
        "06": "June",
        "07": "July",
        "08": "August",
        "09": "September",
        "10": "October",
        "11": "November",
        "12": "December",
    }

    # Track YTD progress
    ytd_2025 = collections.Counter()
    ytd_2026 = collections.Counter()
    incomplete_month_print_fn = None

    anchor_month_str = anchor_date[5:7]  # e.g. "02" when anchor is Feb 28

    full_month_data = []  # collects (month_str, month_name, data_2025, data_2026)
    # The arguments every chart below is drawn from, kept so the slide renderer
    # can redraw the same pictures from the same inputs (local runs only).
    slide_inputs = {}

    # The anchor month is the running (partial) month only while it still has
    # days left. When the anchor is its last day — a run on the 1st, or the
    # pinned year-end cut-off — it is a finished month like any other, so it
    # counts as fact in the YTD totals, the tables and the projection.
    incomplete_month_str = None if anchor_month_complete else anchor_month_str

    sorted_months = sorted(stats.keys())
    for month_str in sorted_months:
        # Nothing after the anchor month is in play: the anchor is the last full
        # day, so on the 1st the new month has no data to show yet.
        if month_str > anchor_month_str:
            continue

        month_name = months_map.get(month_str, month_str)

        if month_str != incomplete_month_str:
            # Full month — collect data and accumulate YTD
            data_2025 = stats[month_str].get("2025", {})
            data_2026 = stats[month_str].get("2026", {})

            for cna, count in data_2025.items():
                ytd_2025[cna] += count
            for cna, count in data_2026.items():
                ytd_2026[cna] += count

            full_month_data.append((month_str, month_name, data_2025, data_2026))
        else:
            # Current (incomplete) month
            data_2025_full = stats[month_str].get("2025", {})
            data_2025_partial = partial_stats[month_str].get("2025", {})
            data_2026_partial = partial_stats[month_str].get("2026", {})

            curr_ytd_2025 = ytd_2025.copy()
            curr_ytd_2026 = ytd_2026.copy()

            for cna, count in data_2025_partial.items():
                curr_ytd_2025[cna] += count
            for cna, count in data_2026_partial.items():
                curr_ytd_2026[cna] += count

            range_label = (
                f"Feb 1-{current_day}"
                if month_str == "02"
                else f"{month_name[:3]} 1-{current_day}"
            )

            prev_month_int = int(month_str) - 1
            if prev_month_int < 1:
                prev_month_str = "12"
                prev_year_str = "2025"
            else:
                prev_month_str = f"{prev_month_int:02d}"
                prev_year_str = "2026"

            # Use partial_stats for MoM: compare same date range (day 1-N) of the previous month
            # If the previous month has fewer days than current_day, partial_stats
            # naturally includes all its records (equivalent to full month on its last day)
            prev_data_2026_partial = partial_stats.get(prev_month_str, {}).get(prev_year_str, {})
            # Calculate the actual "Others" count for the previous month (category-to-category comparison)
            prev_others_count = 0
            prev_month_top_names = set()
            if prev_data_2026_partial:
                prev_data_2025_full = stats.get(prev_month_str, {}).get("2025", {})
                prev_month_cnas = set(prev_data_2025_full.keys()) | set(prev_data_2026_partial.keys())
                prev_month_rows = []
                for cna in prev_month_cnas:
                    prev_month_rows.append({
                        "name": cna,
                        "v25": prev_data_2025_full.get(cna, 0),
                        "v26": prev_data_2026_partial.get(cna, 0)
                    })
                prev_top_25 = sorted(prev_month_rows, key=lambda x: x["v25"], reverse=True)[:TOP_N]
                prev_top_26 = sorted(prev_month_rows, key=lambda x: x["v26"], reverse=True)[:TOP_N]
                prev_month_top_names = set()
                prev_month_top_names |= {r["name"] for r in prev_top_25 if r["v25"] > 0}
                prev_month_top_names |= {r["name"] for r in prev_top_26 if r["v26"] > 0}
                prev_others_count = sum(prev_data_2026_partial.get(cna, 0) for cna in prev_month_cnas if cna not in prev_month_top_names)

            top_names = print_combined_incomplete_month_table(
                f"Combined Stats for {month_name} (Incomplete)",
                data_2025_full,
                data_2025_partial,
                data_2026_partial,
                curr_ytd_2025,
                curr_ytd_2026,
                f"{month_name} '25",
                f"2025 ({range_label})",
                f"2026 ({range_label})",
                anchor_date,
                print_table=False,
                prev_data_2026_full=prev_data_2026_partial,
                prev_others_count=prev_others_count,
            )

            # Generate printing callback to be called later
            incomplete_month_print_fn = make_incomplete_month_printer(
                month_name=month_name,
                data_2025_full=data_2025_full,
                data_2025_partial=data_2025_partial,
                data_2026_partial=data_2026_partial,
                curr_ytd_2025=curr_ytd_2025,
                curr_ytd_2026=curr_ytd_2026,
                range_label=range_label,
                anchor_date=anchor_date,
                prev_data_2026_full=prev_data_2026_partial,
                prev_others_count=prev_others_count,
            )

            # Generate the incomplete-month Sankey chart (PNG). It shows exactly
            # three partial periods: previous month (left), current month (center)
            # and last year's same range (right). Name a CNA only if it is a top-N
            # contributor in one of those THREE DISPLAYED periods. `top_names`
            # already covers the current-month and last-year columns; add the top
            # CNAs of the displayed previous-month column (this year, same range).
            # Do NOT use prev_month_top_names here — it includes the previous
            # month's *full prior-year* leaders, which the chart never shows.
            prev_month_name = months_map.get(prev_month_str, prev_month_str)
            prev_range_label = f"{prev_month_name[:3]} 1-{current_day}"
            prev_shown_top = {
                k for k, v in sorted(
                    prev_data_2026_partial.items(), key=lambda kv: kv[1], reverse=True
                )[:TOP_N] if v > 0
            }
            sankey_named_cnas = set(top_names) | prev_shown_top
            slide_inputs["incomplete_month"] = dict(
                data_2025_partial=data_2025_partial,
                data_2026_partial=data_2026_partial,
                prev_data_partial=prev_data_2026_partial,
                top_names=sankey_named_cnas,
                range_label=range_label,
                prev_range_label=prev_range_label,
                prev_year_str=prev_year_str,
                anchor_date=anchor_date,
                rank_colors=sankey_rank_color_map(
                    stats, partial_stats, curr_ytd_2026,
                    anchor_month_str, anchor_month_complete,
                ),
            )
            plot_incomplete_month_sankey(
                data_2025_partial,
                data_2026_partial,
                prev_data_2026_partial,
                sankey_named_cnas,
                range_label,
                prev_range_label,
                prev_year_str,
                anchor_date,
                output_filename="cve_monthly_stats_comparison_incomplete_month.png",
                rank_colors=slide_inputs["incomplete_month"]["rank_colors"],
            )

    # A finished anchor month still gets the same three-column comparison chart —
    # it is just no longer a slice of anybody's month: every column is a whole
    # month (previous month | this month | the same month a year ago), so nothing
    # has to be cut back to a shared day range.
    if anchor_month_complete and anchor_month_str in stats:
        month_name = months_map.get(anchor_month_str, anchor_month_str)
        anchor_year_str = anchor_date[:4]
        prev_display_year_str = str(int(anchor_year_str) - 1)

        data_2025_full = stats[anchor_month_str].get(prev_display_year_str, {})
        data_2026_full = stats[anchor_month_str].get(anchor_year_str, {})

        prev_month_int = int(anchor_month_str) - 1
        if prev_month_int < 1:
            prev_month_str = "12"
            prev_year_str = prev_display_year_str
        else:
            prev_month_str = f"{prev_month_int:02d}"
            prev_year_str = anchor_year_str
        prev_month_name = months_map.get(prev_month_str, prev_month_str)
        prev_data_full = stats.get(prev_month_str, {}).get(prev_year_str, {})

        # Same top-N union rule as the partial-month path: name a CNA if it leads
        # any of the three columns actually drawn.
        top_names = print_combined_incomplete_month_table(
            f"Combined Stats for {month_name}",
            data_2025_full,
            data_2025_full,
            data_2026_full,
            ytd_2025,
            ytd_2026,
            f"{month_name[:3]} ’25",
            f"{prev_display_year_str} ({month_name})",
            f"{anchor_year_str} ({month_name})",
            anchor_date,
            print_table=False,
            prev_data_2026_full=prev_data_full,
        )
        prev_shown_top = {
            k for k, v in sorted(
                prev_data_full.items(), key=lambda kv: kv[1], reverse=True
            )[:TOP_N] if v > 0
        }
        slide_inputs["incomplete_month"] = dict(
            data_2025_partial=data_2025_full,
            data_2026_partial=data_2026_full,
            prev_data_partial=prev_data_full,
            top_names=set(top_names) | prev_shown_top,
            range_label=month_name,
            prev_range_label=prev_month_name,
            prev_year_str=prev_year_str,
            anchor_date=anchor_date,
            center_is_complete=True,
            rank_colors=sankey_rank_color_map(
                stats, partial_stats, ytd_2026,
                anchor_month_str, anchor_month_complete,
            ),
        )
        plot_incomplete_month_sankey(
            data_2025_full,
            data_2026_full,
            prev_data_full,
            set(top_names) | prev_shown_top,
            month_name,
            prev_month_name,
            prev_year_str,
            anchor_date,
            output_filename="cve_monthly_stats_comparison_incomplete_month.png",
            center_is_complete=True,
            rank_colors=slide_inputs["incomplete_month"]["rank_colors"],
        )

    # Resolve the final cumulative YTD dictionary to use
    target_ytd_2025 = curr_ytd_2025 if "curr_ytd_2025" in locals() else ytd_2025
    target_ytd_2026 = curr_ytd_2026 if "curr_ytd_2026" in locals() else ytd_2026

    # Ensure global YTD top CNAs are strictly the top 15 from 2026 YTD
    ytd_top_cnas = [c for c, _ in collections.Counter(target_ytd_2026).most_common(TOP_N)]

    # Print the tables into the report buffer (this text is what the tables page
    # shows verbatim — the same content the old console report produced).
    with redirect_stdout(report_buf):
        if full_month_data:
            print_all_months_table(
                full_month_data,
                anchor_date,
                stats,
                partial_stats,
                current_month_str,
                incomplete_month_print_fn=incomplete_month_print_fn,
                current_month_is_partial=not anchor_month_complete,
            )

        # Final Summary
        print(f"\n{'=' * 30} FINAL YEAR-TO-DATE SUMMARY {'=' * 30}")
        print_summary_table(
            "Cumulative YTD Stats (Top CNAs from 2025 and 2026 YTD)",
            target_ytd_2025,
            target_ytd_2026,
            ytd_top_cnas,
            anchor_date,
        )

    # Every Chrome release of the year with its CVE count, for the fan-in slide (local only).
    slide_inputs["fanin_chrome"] = dict(chrome_cves=results.get("chrome_cves", []), anchor_date=anchor_date)
    # EPSS recency penalty and recall (local only).
    slide_inputs["epss"] = dict(epss_rows=results.get("epss_rows", []), anchor_date=anchor_date)
    # Kernel bug-fix discovery against CVE publishing (local only).
    slide_inputs["kernel_fixes"] = dict(daily_counts_kernel=results.get("daily_counts_kernel", {}), anchor_date=anchor_date)
    # Exploitation signals against publication volume (local only).
    slide_inputs["exploitation_vs_volume"] = dict(
        stats=stats, anchor_date=anchor_date, anchor_month_complete=anchor_month_complete,
    )
    # One CVE's downstream advisories, for the fan-out slide (local only).
    fanout_records = results.get("fanout_records", {})
    slide_inputs["fanout_downstream"] = dict(record=fanout_records.get(FANOUT_CVE))
    if _WRITE_CSV:
        _write_fanout_csv(fanout_records)

    # Generate custom monthly flow Sankey chart
    slide_inputs["sankey_flow"] = dict(
        stats=stats,
        partial_stats=partial_stats,
        top_names=ytd_top_cnas,
        anchor_date=anchor_date,
        anchor_month_complete=anchor_month_complete,
    )
    plot_custom_sankey_flow(
        stats,
        partial_stats,
        ytd_top_cnas,
        anchor_date,
        anchor_month_complete=anchor_month_complete,
    )

    # Generate YTD growth chart
    slide_inputs["ytd_growth"] = dict(
        daily_counts_2025=daily_counts_2025,
        daily_counts_2026=daily_counts_2026,
        anchor_date_str=anchor_date,
    )
    plot_ytd_growth(daily_counts_2025, daily_counts_2026, anchor_date)

    # Generate Yearly Cumulative YoY comparison chart (2022-2025 full year, 2026 YTD)
    slide_inputs["yearly_cumulative"] = dict(daily_counts=daily_counts, anchor_date_str=anchor_date)
    plot_yearly_cumulative(daily_counts, anchor_date)

    # Generate Monthly Projections comparison chart
    completed_month_strs = [m[0] for m in full_month_data]
    n_comp = len(completed_month_strs)
    x_coords = []
    y_coords = []
    for idx, month_str in enumerate(completed_month_strs, 1):
        g25 = sum(stats[month_str]["2025"].values()) if month_str in stats else 0
        g26 = sum(stats[month_str]["2026"].values()) if month_str in stats else 0
        x_coords.append(idx)
        y_coords.append((g26 - g25) / g25 if g25 > 0 else 0.0)

    # If the current month has partial data, compute its actual YoY factor
    # and include it as a data point in the trend-line regression
    # ...unless the anchor month has closed, in which case it is already one of
    # the completed months above and must not be counted a second time.
    current_month_yoy_growth = None
    current_month_has_data_for_chart = (
        not anchor_month_complete
        and current_month_str and stats
        and current_month_str in stats
        and "2026" in stats[current_month_str]
        and sum(stats[current_month_str]["2026"].values()) > 0
    )
    if current_month_has_data_for_chart and partial_stats:
        p25 = sum(partial_stats[current_month_str]["2025"].values()) if (current_month_str in partial_stats and "2025" in partial_stats[current_month_str]) else 0
        p26 = sum(partial_stats[current_month_str]["2026"].values()) if (current_month_str in partial_stats and "2026" in partial_stats[current_month_str]) else 0
        if p25 > 0:
            current_month_yoy_growth = (p26 - p25) / p25  # e.g. 1.151 for +115.1%
            # Add to regression data points
            x_coords.append(int(current_month_str))
            y_coords.append(current_month_yoy_growth)

    n_reg = len(x_coords)
    slope = 0.0
    intercept = 0.0
    if n_reg >= 2:
        mean_x = sum(x_coords) / n_reg
        mean_y = sum(y_coords) / n_reg
        num = sum((x_coords[i] - mean_x) * (y_coords[i] - mean_y) for i in range(n_reg))
        den = sum((x_coords[i] - mean_x) ** 2 for i in range(n_reg))
        if den != 0:
            slope = num / den
            intercept = mean_y - slope * mean_x
        else:
            intercept = mean_y
    elif n_reg == 1:
        intercept = y_coords[0]

    slide_inputs["projections"] = dict(
        stats=stats,
        completed_month_strs=completed_month_strs,
        slope=slope,
        intercept=intercept,
        partial_stats=partial_stats,
        current_month_str=current_month_str,
        current_month_yoy_growth=current_month_yoy_growth,
        anchor_date=anchor_date,
    )
    plot_monthly_projections(
        stats,
        completed_month_strs,
        slope,
        intercept,
        partial_stats=partial_stats,
        current_month_str=current_month_str,
        current_month_yoy_growth=current_month_yoy_growth,
        anchor_date=anchor_date,
    )

    # NVD status of what was published: by year, then by week.
    status_yearly = results.get("status_yearly", {})
    status_weekly = results.get("status_weekly", {})
    slide_inputs["status_yearly"] = dict(status_yearly=status_yearly, anchor_date=anchor_date)
    slide_inputs["status_weekly"] = dict(status_weekly=status_weekly, anchor_date=anchor_date)
    plot_status_yearly_bar(status_yearly, anchor_date)
    plot_status_stacked_charts(status_weekly, anchor_date)
    if _WRITE_CSV:
        _write_status_csvs(status_yearly, status_weekly)

    # Hidden volume: reserved/candidate CVEs (last chart on the dashboard).
    slide_inputs["candidate_track"] = dict(candidate_stats=results.get("candidate_stats", {}))
    plot_candidate_track(results.get("candidate_stats", {}))

    # The same six pictures again, rethought as 16:9 presentation slides. Local
    # runs only — the published page never sees these files.
    if _SLIDES:
        from . import monthly_slides
        monthly_slides.render_all(slide_inputs)
