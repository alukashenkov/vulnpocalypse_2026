'''Monthly CVE/CNA statistics dashboard.

Generation logic extracted verbatim from the original
cve_monthly_stats_comparison.py so both the site orchestrator (``python -m src``)
and the thin local wrapper drive one copy of the code. Produces the six charts
and the aligned-table report; no CSV/TXT outputs, no tqdm, no stdout-teeing on the
published path.
'''
import collections
import csv
import io
import os
import time
from contextlib import redirect_stdout
from datetime import datetime, timedelta

import ijson
import numpy as np
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

# Charts, in the order they appear on the page (written into the out_dir given
# to generate()). These filenames match what the plotting functions emit.
CHART_FILES = [
    "cve_monthly_stats_comparison_yearly_cumulative.png",
    "cve_monthly_stats_comparison_ytd_growth.png",
    "cve_monthly_stats_comparison_incomplete_month.png",
    "cve_monthly_stats_comparison_sankey_monthly.png",
    "cve_monthly_stats_comparison_projection.png",
]

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
    "cve_monthly_stats_comparison_incomplete_month.png": (
        "Three snapshots of the exact same slice of the calendar, lined up side "
        "by side: this month so far in the middle, the same days of last month on "
        "the left, and the same stretch a year ago on the right. Same window, "
        "three different levels of pain. It answers two questions at a glance, "
        "whether the current month is already outrunning the one before it, and "
        "how much further ahead of last year the whole pipeline has drifted. The "
        "current column is rarely the short one."
    ),
    "cve_monthly_stats_comparison_sankey_monthly.png": (
        "The same firehose, sliced by month, so you can watch the ribbons swell. "
        "Each column is a month; the taller it stacks, the more CVEs that month "
        "shipped. Trace any single CNA's band across the months to see how its "
        'output rises and falls. This is what "more of everything, from everyone" '
        "looks like when you actually draw it."
    ),
    "cve_monthly_stats_comparison_projection.png": (
        "Two ways to guess where this ends, and neither one lets you sleep. One "
        "line runs the current rate forward; the other draws the rounder "
        "baseline. Both land well above where the prior year finished, which "
        "already reads like the good old days. The asterisks mean projection. The "
        "slope means call the cavalry."
    ),
}

# ── Shared chart palette ─────────────────────────────────────────────────────
# Every chart draws its series colors from the Sankey "premium" palette so the
# whole dashboard reads as one system. #FF4757 (the Sankey's first red) is the
# anchor; the rest are pulled from the same palette. Colorblind separation on the
# dark (#1E1E1E) surface is validated with the dataviz palette validator.
C_RED = "#FF4757"     # current year / primary emphasis  (Sankey GitHub_M)
C_BLUE = "#2E86DE"    # previous year / reference         (Sankey Linux)
C_GREEN = "#2ED573"   # positive / baseline projection    (Sankey ibm)
C_YELLOW = "#F1C40F"  # (Sankey mitre)
C_GRAY = "#747D8C"    # oldest year / neutral data        (Sankey Others)

# Fixed color per calendar year for the multi-year comparison charts.
YEAR_COLORS = {
    "2022": C_GRAY,
    "2023": C_YELLOW,
    "2024": C_GREEN,
    "2025": C_BLUE,
    "2026": C_RED,
}

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


# Plotting functions below append their saved-file messages here. Kept so those
# functions stay byte-for-byte identical to the original; not shown on the site.
saved_files_log = []


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

                if vuln_status and vuln_status.lower() == "rejected":
                    continue
                if reporter and reporter.lower() == "candidate":
                    continue

                if published_date and len(published_date) >= 10:
                    year = published_date[:4]
                    month = published_date[5:7]
                    day = int(published_date[8:10])
                    record_date_str = published_date[:10]

                    if record_date_str > anchor_date_str:
                        continue

                    if year in ["2022", "2023", "2024", "2025", "2026"]:
                        cna_name = item.get("cna") or reporter or "Unknown"

                        # Store in full monthly stats
                        stats[month][year][cna_name] += 1

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
        "daily_counts_2025": daily_counts_2025,
        "daily_counts_2026": daily_counts_2026,
        "daily_counts": daily_counts,
        "daily_cna_counts_2026": daily_cna_counts_2026,
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
):
    """
    Prints one compact 4-column sub-table per month (CNA | 2025 | 2026 | YoY%)
    followed by a cross-month totals summary.
    full_months: list of (month_str, month_name, data_2025, data_2026)
    """
    if not full_months:
        return set()

    # Check if the current month actually has any 2026 records. If not, suppress incomplete month logic.
    current_month_has_data = False
    if current_month_str and stats and current_month_str in stats and "2026" in stats[current_month_str]:
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

    # If the current month has data, compute its actual partial YoY factor
    # and include it as a "fact" in the acceleration trend calculation
    cur_month_str = current_month_str or "13"
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
        g_m = max(-0.9, min(3.0, g_m))
        
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
        g_m = max(-0.9, min(3.0, g_m)) + d_adj
        
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
        g_m = max(-0.9, min(3.0, g_m)) + d_adj
        
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



def plot_custom_sankey_flow(
    stats,
    partial_stats,
    top_names,
    anchor_date,
    output_filename="cve_monthly_stats_comparison_sankey_monthly.png",
):
    """
    Plots a custom Sankey flow visualization of CVE contributions for top YTD CNAs,
    starting from December 2025, flowing through each month of 2026, and ending at June 2026.
    Only labels CNAs at the first column (December 2025).
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
    for m_int in range(1, int(anchor_month_str) + 1):
        m_str = f"{m_int:02d}"
        m_label = months_abbrev[m_str]

        if m_str < anchor_month_str:
            m_data = stats.get(m_str, {}).get("2026", {})
        else:
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
    all_items = sorted_top_names + ["Others"]

    # Month headers
    stage_labels = [s["label"] for s in stages]

    # Calculate raw volumes and total volumes for each stage
    raw_data = []
    totals = []
    for stage in stages:
        stage_data = stage["data"]
        volumes = {}
        for cna in sorted_top_names:
            volumes[cna] = max(5, stage_data.get(cna, 0))
        others_val = sum(v for k, v in stage_data.items() if k not in sorted_top_names)
        volumes["Others"] = max(5, others_val)
        
        raw_data.append(volumes)
        totals.append(sum(volumes.values()))

    max_total_vol = max(totals) if totals else 1.0

    # Compute stacked positions centered at y = 500, scaled by absolute volumes
    gap = 12
    num_items = len(all_items)
    max_avail_height = 1000 - (num_items - 1) * gap

    stage_positions = []
    for s, stage in enumerate(stages):
        volumes = raw_data[s]
        total_vol = totals[s]
        
        # Scale available height for this stage based on its absolute volume relative to the max month
        avail_height = (total_vol / max_total_vol) * max_avail_height
        stage_total_height = avail_height + (num_items - 1) * gap
        
        pos = {}
        # Center the stack vertically at y = 500
        curr_y = 500.0 + stage_total_height / 2.0
        for item in all_items:
            # Item's height is proportional to its absolute volume
            h = (volumes[item] / total_vol) * avail_height
            y_start = curr_y - h
            y_end = curr_y
            pos[item] = (y_start, y_end)
            curr_y = y_start - gap
        stage_positions.append(pos)

    # Premium color palette
    # Premium color palette for all 15 CNAs and Others (shuffled to maximize contrast between neighbors)
    colors = {
        "GitHub_M": "#FF4757",       # Vibrant Coral Red
        "VulDB": "#E84393",          # Deep Pink
        "VulnCheck": "#FF9F43",      # Bright Orange
        "Patchstack": "#10AC84",     # Teal Green
        "Linux": "#2E86DE",          # Dodger Blue
        "mitre": "#F1C40F",          # Yellow
        "Wordfence": "#9B59B6",      # Amethyst Purple
        "Chrome": "#EE5253",         # Red
        "microsoft": "#1DD1A1",      # Lime Green
        "oracle": "#341F97",         # Indigo Blue
        "adobe": "#00D2D3",          # Cyan
        "redhat": "#FFBE1A",         # Amber/Yellow
        "apache": "#A55EEA",         # Lavender Purple
        "apple": "#FF6B6B",          # Light Coral Red
        "ibm": "#2ED573",            # Light Green
        "Others": "#747D8C",         # Sleek Gray
    }

    # Plot
    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(19.25, 17.5), facecolor="#1E1E1E")
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
            
            # Get actual raw monthly contribution count
            if item == "Others":
                val = sum(v for k, v in stage_data.items() if k not in sorted_top_names)
            else:
                val = stage_data.get(item, 0)
            
            # Draw block
            rect = plt.Rectangle((x_pos - 0.04, y_start), 0.08, y_end - y_start, facecolor=colors.get(item, "#747D8C"), edgecolor="none", zorder=3)
            ax.add_patch(rect)
            
            # Label contribution value if it is > 0 (placed to the left of the block)
            if val > 0:
                if item == "Others":
                    cna_count = sum(1 for k, v in stage_data.items() if k not in sorted_top_names and v > 0)
                    label_text = f"{val}\n[{cna_count}]"
                else:
                    label_text = f"{val}"
                txt = ax.text(
                    x_pos - 0.06,
                    y_center,
                    label_text,
                    ha="right",
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
            
            # Only label CNA name at the first column (lane), printed inside the starting flow to save margin space
            if s == 0:
                ax.text(
                    x_pos + 0.06,
                    y_center,
                    item,
                    ha="left",
                    va="center",
                    color="#FFFFFF",
                    fontsize=18,
                    fontweight="bold"
                )

        # Label month header with month name and total count below it
        ax.text(s, 1040, stage_labels[s], ha="center", va="bottom", color="#FFFFFF", fontsize=22.5, fontweight="bold")
        ax.text(s, 1012, f"({totals[s]:,})", ha="center", va="bottom", color="#A4B0BE", fontsize=18, fontweight="normal")

    # Title & Subtitle
    ax.text(
        3.0, 1090,
        f"Monthly CVE Contributions of Top CNAs (Dec {prev_year} - {months_abbrev[anchor_month_str]} {current_year})",
        ha="center",
        va="bottom",
        color="#FFFFFF",
        fontsize=27,
        fontweight="bold"
    )
    ax.text(
        3.0, 1065,
        f"Visualizing monthly CVE publications. Sized by absolute volume contribution. Sorted by total number of CVEs in {current_year}.",
        ha="center",
        va="bottom",
        color="#A4B0BE",
        fontsize=19.5,
        style="italic"
    )

    ax.set_xlim(-0.35, len(stages) - 0.65)
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
    saved_files_log.append(f"Saved custom monthly flow Sankey chart to {os.path.abspath(output_filename)}")


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
):
    """
    Plots a custom Sankey flow visualization of the incomplete (current) month
    across three stops:
      1. previous month, same day-range (MoM)          — leftmost
      2. 2026, current incomplete month                — center (pivot)
      3. 2025, same day-range (YoY reference)          — rightmost

    So the previous month flows into the current month, which is then compared to
    the same range in 2025. This mirrors the visual style of
    ``plot_custom_sankey_flow`` (stacked columns joined by tapering flow bands,
    sized by absolute volume). ``top_names`` should already include every top CNA
    of the previous month so that MoM contributors appear as their own lanes in
    all three stops rather than folded into "Others".
    """
    current_year = int(anchor_date[:4])  # display year, derived from the data anchor
    prev_year = current_year - 1

    # Three stages: previous month (MoM) -> current year -> previous year (YoY).
    stages = [
        {"label": f"{prev_year_str} ({prev_range_label})", "data": prev_data_partial},
        {"label": f"{current_year} ({range_label})", "data": data_2026_partial},
        {"label": f"{prev_year} ({range_label})", "data": data_2025_partial},
    ]

    # Sort top CNAs by their current-month (pivot) volume.
    sorted_top_names = sorted(
        top_names, key=lambda c: data_2026_partial.get(c, 0), reverse=True
    )
    all_items = sorted_top_names + ["Others"]

    stage_labels = [s["label"] for s in stages]

    # Calculate raw volumes and total volumes for each stage
    raw_data = []
    totals = []
    for stage in stages:
        stage_data = stage["data"]
        volumes = {}
        for cna in sorted_top_names:
            volumes[cna] = max(5, stage_data.get(cna, 0))
        others_val = sum(v for k, v in stage_data.items() if k not in sorted_top_names)
        volumes["Others"] = max(5, others_val)

        raw_data.append(volumes)
        totals.append(sum(volumes.values()))

    max_total_vol = max(totals) if totals else 1.0

    # Compute stacked positions centered at y = 500, scaled by absolute volumes
    gap = 12
    num_items = len(all_items)
    max_avail_height = 1000 - (num_items - 1) * gap

    stage_positions = []
    for s, stage in enumerate(stages):
        volumes = raw_data[s]
        total_vol = totals[s]

        avail_height = (total_vol / max_total_vol) * max_avail_height
        stage_total_height = avail_height + (num_items - 1) * gap

        pos = {}
        curr_y = 500.0 + stage_total_height / 2.0
        for item in all_items:
            h = (volumes[item] / total_vol) * avail_height
            y_start = curr_y - h
            y_end = curr_y
            pos[item] = (y_start, y_end)
            curr_y = y_start - gap
        stage_positions.append(pos)

    # Same premium palette as the monthly-flow chart
    colors = {
        "GitHub_M": "#FF4757",
        "VulDB": "#E84393",
        "VulnCheck": "#FF9F43",
        "Patchstack": "#10AC84",
        "Linux": "#2E86DE",
        "mitre": "#F1C40F",
        "Wordfence": "#9B59B6",
        "Chrome": "#EE5253",
        "microsoft": "#1DD1A1",
        "oracle": "#341F97",
        "adobe": "#00D2D3",
        "redhat": "#FFBE1A",
        "apache": "#A55EEA",
        "apple": "#FF6B6B",
        "ibm": "#2ED573",
        "Others": "#747D8C",
    }

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
                    x_pos - 0.06,
                    y_center,
                    label_text,
                    ha="right",
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

            # Label the CNA name once, at the first (2025) column.
            if s == 0:
                ax.text(
                    x_pos + 0.06,
                    y_center,
                    item,
                    ha="left",
                    va="center",
                    color="#FFFFFF",
                    fontsize=18,
                    fontweight="bold"
                )

        ax.text(s, 1040, stage_labels[s], ha="center", va="bottom", color="#FFFFFF", fontsize=22.5, fontweight="bold")
        ax.text(s, 1012, f"({totals[s]:,})", ha="center", va="bottom", color="#A4B0BE", fontsize=18, fontweight="normal")

    # Title & Subtitle
    title_x = (len(stages) - 1) / 2.0
    ax.text(
        title_x, 1090,
        f"CVE Contributions of Top CNAs ({range_label}) — MoM & YoY",
        ha="center",
        va="bottom",
        color="#FFFFFF",
        fontsize=26,
        fontweight="bold"
    )
    ax.text(
        title_x, 1065,
        f"Left: previous month {prev_range_label} (MoM).  Center: current incomplete month.  "
        f"Right: {prev_year} same range (YoY).  Sized by volume, sorted by current-month volume.",
        ha="center",
        va="bottom",
        color="#A4B0BE",
        fontsize=15,
        style="italic"
    )

    ax.set_xlim(-0.55, len(stages) - 0.45)
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


def plot_ytd_growth(daily_counts_2025, daily_counts_2026, anchor_date_str, output_filename="cve_monthly_stats_comparison_ytd_growth.png"):
    """
    Plots YTD growth over the same date in 2025 for all days in 2026 up to anchor_date_str.
    """
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

    plt.style.use("dark_background")
    fig, ax = plt.subplots(1, 1, figsize=(14, 7), facecolor="#1E1E1E")
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

    # Set bottom of y-axis to 0 to prevent negative speeds
    ax.set_ylim(bottom=0)

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
        0.01,
        f"Generated on {datetime.now().strftime('%Y-%m-%d')} | Data Source: Vulners CVE Archive",
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
    saved_files_log.append(f"YTD growth comparison chart saved to {os.path.abspath(output_filename)}")


def plot_yearly_cumulative(daily_counts, anchor_date_str, output_filename="cve_monthly_stats_comparison_yearly_cumulative.png"):
    """
    Plots cumulative CVEs for each year from 2022 to 2025 (full year) and 2026 (YTD up to anchor_date_str).
    Includes the average daily speed in the legend and highlights the moment 2026 surpassed any previous years' totals.
    """
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
            surpassed_info.append({
                "prev_year": prev_y,
                "prev_total": prev_total,
                "ref_date": surpassed_dt,
                "date_str": surpass_date_2026.strftime("%B %d, %Y"),
                "short_date_str": surpass_date_2026.strftime("%b %d"),
                "cumulative_2026_val": cumulative_series["2026"][surpassed_idx]
            })

    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(14, 9), facecolor="#1E1E1E")
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
            label=f"{y} (Avg: {avg_speeds[y]:.1f}/day)"
        )

    # Plot 2026 curve
    ax.plot(
        dates_series["2026"],
        cumulative_series["2026"],
        color=colors["2026"],
        linewidth=4.5,
        label=f"{int(anchor_date_str[:4])} YTD (Avg: {avg_speeds['2026']:.1f}/day)"
    )

    # Draw horizontal lines for the surpassed years' totals
    for info in surpassed_info:
        prev_y = info["prev_year"]
        prev_total = info["prev_total"]
        ax.axhline(
            y=prev_total,
            color=colors[prev_y],
            linestyle="--",
            linewidth=1.5,
            alpha=0.6,
            zorder=1
        )
        # Label on the right margin
        ax.text(
            ref_dates[-1] + timedelta(days=2),
            prev_total,
            f"{prev_y} Total: {prev_total:,}",
            color=colors[prev_y],
            va="center",
            ha="left",
            fontsize=11,
            fontweight="bold"
        )

        # Plot crossover star marker on 2026 curve
        ax.plot(
            info["ref_date"],
            info["cumulative_2026_val"],
            marker="*",
            color="#FFBB33",
            markersize=14,
            markeredgecolor="#FFFFFF",
            zorder=5
        )

        # Annotate crossover points with curved arrows
        # Use a uniform offset to make the arrow lines parallel and prevent them from crossing
        # and place them closer to the points.
        x_off, y_off = -50, 35
        ha, va = "right", "bottom"

        ax.annotate(
            f"Surpassed {prev_y} Total on {info['short_date_str']}",
            xy=(info["ref_date"], info["cumulative_2026_val"]),
            xytext=(x_off, y_off),
            textcoords="offset points",
            ha=ha,
            va=va,
            fontsize=12,
            fontweight="bold",
            color="#FFFFFF",
            bbox=dict(boxstyle="round,pad=0.4", fc="#262626", ec=colors[prev_y], alpha=0.9, lw=1.5),
            arrowprops=dict(arrowstyle="->", connectionstyle="arc3,rad=0.2", color=colors[prev_y], lw=1.5)
        )

    ax.grid(True, color="#444444", linestyle="--", alpha=0.5)
    ax.set_ylabel("Cumulative CVE Count", fontsize=16, fontweight="bold", color="#FFFFFF")
    ax.set_title("Year-over-Year Cumulative CVE Publications Comparison", fontsize=18, fontweight="bold", color="#FFFFFF", pad=28)
    ax.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: f"{int(x):,}"))
    ax.set_ylim(bottom=0)

    # Set x limits with right margin for text labels
    ax.set_xlim(ref_dates[0], ref_dates[-1] + timedelta(days=22))

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
    ax.legend(loc="upper left", facecolor="#262626", edgecolor="#444444", fontsize=13)

    plt.figtext(
        0.5,
        0.01,
        f"Generated on {datetime.now().strftime('%Y-%m-%d')} | Data Source: Vulners CVE Archive",
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
    saved_files_log.append(f"Yearly cumulative comparison chart saved to {os.path.abspath(output_filename)}")


def plot_monthly_projections(stats, completed_month_strs, slope, intercept, partial_stats=None, current_month_str=None, current_month_yoy_growth=None, anchor_date=None, output_filename="cve_monthly_stats_comparison_projection.png"):
    """
    Generates a cumulative monthly publication comparison chart for 2025 vs 2026,
    including trend projections for remaining 2026 months and MoM growth annotations.
    """
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

    # Compute projection adjustment factor to land on exactly 100,000 total CVEs
    cur_month_idx = int(current_month_str) - 1 if current_month_str else -1
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
            g_m = max(-0.9, min(3.0, g_m))
            
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
        g_m = max(-0.9, min(3.0, g_m)) + d_adj
        
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
        g_m = max(-0.9, min(3.0, g_m))
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

    start_proj_idx = min(4, last_comp_idx)
    # The green curve uses actual values up to May (index 4) and then projects using REFERENCE_PREDICTIONS from June (index 5) onwards
    for i in range(start_proj_idx, 5):
        y_2026_proj_cum[i] = y_2026_full_cum[i]
        
    cum_proj = y_2026_proj_cum[4] if y_2026_proj_cum[4] is not None else y_2026_full_cum[4]
    for i in range(5, 12):
        month_str = months_list[i]
        pred_val = REFERENCE_PREDICTIONS.get(month_str, 0)
        cum_proj += pred_val
        y_2026_proj_cum[i] = cum_proj
        
        v25 = y_2025[i]
        yoy_2026_green[i] = ((pred_val - v25) / v25 * 100) if v25 > 0 else 0.0

    # Hardcode December value to land exactly on 100,000 baseline target
    y_2026_proj_cum[11] = 100000

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

            # If this is June (last completed month), also print the baseline projection label under the curve
            if i == last_comp_idx:
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

            if val_runrate >= val_100k:
                # Run-rate is higher (or equal) -> run-rate above, baseline below
                rr_offset_yoy, rr_va_yoy = 42, "bottom"
                rr_offset_val, rr_va_val = 12, "bottom"
                bsl_offset_yoy, bsl_va_yoy = -48, "top"
                bsl_offset_val, bsl_va_val = -18, "top"
            else:
                # Baseline is higher -> baseline above, run-rate below
                bsl_offset_yoy, bsl_va_yoy = 42, "bottom"
                bsl_offset_val, bsl_va_val = 12, "bottom"
                rr_offset_yoy, rr_va_yoy = -48, "top"
                rr_offset_val, rr_va_val = -18, "top"

            # Run-rate YoY% label
            ax.annotate(
                f"{yoy_runrate:+5.1f}%*",
                xy=(i, val_runrate),
                xytext=(0, rr_offset_yoy),
                textcoords="offset points",
                ha="center",
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
                xytext=(0, rr_offset_val),
                textcoords="offset points",
                ha="center",
                va=rr_va_val,
                fontsize=15,
                fontweight="bold" if i == 11 else "normal",
                color="#FFFFFF"
            )

            # Baseline YoY% label
            ax.annotate(
                f"{yoy_100k_val:+5.1f}%*",
                xy=(i, val_100k),
                xytext=(0, bsl_offset_yoy),
                textcoords="offset points",
                ha="center",
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
                xytext=(0, bsl_offset_val),
                textcoords="offset points",
                ha="center",
                va=bsl_va_val,
                fontsize=15,
                color="#FFFFFF"
            )

    ax.set_ylabel("Cumulative CVE Count", fontsize=22.5, fontweight="bold", color="#FFFFFF")  # 150% of 15
    ax.set_title(f"Cumulative Monthly CVE Publications: {prev_year} vs {current_year} Projections", fontsize=27, fontweight="bold", color="#FFFFFF", pad=20)
    ax.grid(True, color="#444444", linestyle="--", alpha=0.5)
    ax.legend(loc="upper left", facecolor="#262626", edgecolor="#444444", fontsize=18)  # 150% of 12
    ax.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: f"{int(x):,}"))
    
    # Increase the y-axis limit by 15% to leave headroom at the top for labels, preventing overlap with the title
    max_val = max(*y_2026_full_cum, *y_2026_runrate_cum)
    ax.set_ylim(bottom=0, top=max_val * 1.15)
    ax.set_xlim(-0.3, 11.3)  # Tight x-axis limits to use full width

    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    for spine in ["left", "bottom"]:
        ax.spines[spine].set_color("#777777")
    ax.tick_params(colors="#CCCCCC", labelsize=18)  # 150% of 12

    footer_text = (
        f"Generated on {datetime.now().strftime('%Y-%m-%d')} | "
        f"* Dashed/dash-dotted lines and '*' values = projections | "
        f"YoY = Year-over-Year monthly growth"
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

    plt.tight_layout(rect=[0, 0.04, 1, 1])
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
        f"Generated on {datetime.now().strftime('%Y-%m-%d')} | Data Source: Vulners CVE Archive",
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

    charts = [
        {"file": os.path.join(out_dir, name), "caption": CHART_CAPTIONS.get(name, "")}
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

    sorted_months = sorted(stats.keys())
    for month_str in sorted_months:
        if "2026" not in stats[month_str] and month_str > current_month_str:
            continue
        if month_str > current_month_str:
            continue
        # Skip the current month if we just rolled into a new month today
        if month_str == current_month_str and month_str != anchor_month_str:
            continue

        month_name = months_map.get(month_str, month_str)

        if month_str < current_month_str:
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

            # Generate the incomplete-month Sankey chart (PNG). Include every top
            # CNA of the previous month in the named set so MoM (rightmost stop)
            # contributors are shown as their own lanes across all three stops.
            prev_month_name = months_map.get(prev_month_str, prev_month_str)
            prev_range_label = f"{prev_month_name[:3]} 1-{current_day}"
            sankey_named_cnas = set(top_names) | prev_month_top_names
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

    # Generate custom monthly flow Sankey chart
    plot_custom_sankey_flow(
        stats,
        partial_stats,
        ytd_top_cnas,
        anchor_date,
    )

    # Generate YTD growth chart
    plot_ytd_growth(daily_counts_2025, daily_counts_2026, anchor_date)

    # Generate Yearly Cumulative YoY comparison chart (2022-2025 full year, 2026 YTD)
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
    current_month_yoy_growth = None
    current_month_has_data_for_chart = (
        current_month_str and stats
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
