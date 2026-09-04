'''Presentation-slide versions of the monthly dashboard's charts.

Every chart on the monthly page is drawn here a second time as a 16:9 slide
(the weekly NVD-status chart as two, one per panel):
the same numbers (each renderer reads the same ``_prep_*`` result the web chart
is drawn from), rethought for a projector — one fixed frame, a title and a
one-line takeaway across the top, direct labels in the right margin instead of
legend boxes, and far fewer numbers per picture.

The frame is PowerPoint's default widescreen slide, 13.333 x 7.5 in, saved at
its exact size (no tight cropping, so every slide has the same ratio). Because
the figure is the size of the slide, a font size here *is* the point size the
audience sees once the picture fills the slide.

Local runs only: ``monthly._SLIDES`` is off on the published path, and the
page lists only the six files in ``monthly.CHART_FILES``.
'''
import collections
import csv
import os
import textwrap
import traceback
from datetime import date, datetime, timedelta

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patheffects as path_effects

from . import monthly as m

# ── Frame ────────────────────────────────────────────────────────────────────
SLIDE_W, SLIDE_H = 13.333, 7.5   # inches; PowerPoint's default 16:9 slide
SLIDE_DPI = 200                  # 2667 x 1500 px

BG = "#1E1E1E"
INK = "#FFFFFF"                  # titles, values
INK2 = "#A4B0BE"                 # subtitles, secondary labels
INK3 = "#747D8C"                 # footer, ruler
GRID = "#3A3F47"
SPINE = "#666B73"

F_TITLE = 24
F_SUB = 12.5
F_TICK = 12
F_LABEL = 11.5      # the main line of a direct label
F_SMALL = 9.5       # the second line of a direct label, pills, small values
F_FOOT = 9.5

# Figure-fraction bands shared by every slide: title, subtitle, content, footer.
TITLE_Y = 0.945
SUB_Y = 0.878
CONTENT_TOP = 0.805
AXES_BOTTOM = 0.15     # charts with x tick labels
FOOT_Y = 0.03

SLIDE_FILES = {
    "yearly_cumulative": "cve_monthly_stats_comparison_yearly_cumulative_slide.png",
    "ytd_growth": "cve_monthly_stats_comparison_ytd_growth_slide.png",
    "sankey_flow": "cve_monthly_stats_comparison_sankey_monthly_slide.png",
    "incomplete_month": "cve_monthly_stats_comparison_incomplete_month_slide.png",
    "projections": "cve_monthly_stats_comparison_projection_slide.png",
    "candidate_track": "cve_monthly_stats_comparison_candidate_track_slide.png",
    "status_yearly": "cve_monthly_stats_comparison_status_yearly_slide.png",
    "status_weekly_absolute": "cve_monthly_stats_comparison_status_weekly_absolute_slide.png",
    "status_weekly_normalized": "cve_monthly_stats_comparison_status_weekly_normalized_slide.png",
    "fanin_chrome": "cve_monthly_stats_comparison_fanin_chrome_slide.png",
    "fanin_chrome_estate": "cve_monthly_stats_comparison_fanin_chrome_estate_slide.png",
    "fanout_downstream": "cve_monthly_stats_comparison_fanout_downstream_slide.png",
    "exploitation_vs_volume": "cve_monthly_stats_comparison_exploitation_vs_volume_slide.png",
    "exploitation_share": "cve_monthly_stats_comparison_exploitation_share_slide.png",
    "kernel_fixes": "cve_monthly_stats_comparison_kernel_fixes_vs_publishing_slide.png",
    "epss_cohort_age": "cve_monthly_stats_comparison_epss_recency_cohort_age_slide.png",
    "epss_recall": "cve_monthly_stats_comparison_epss_recall_slide.png",
}

# ── The Chrome fan-in slide's facts ──────────────────────────────────────────
# The two milestones bracketed on the slide — the ones Google's "Chrome:
# Stronger with every update" post (30 Jul 2026) singled out for fixing more
# security bugs than the prior 23 milestones combined. The slide shows only
# this data's own CVE count for them.
CHROME_BLOG_MILESTONES = (149, 150)
# An unlinked CVE joins a release of its Chrome version published within this
# many days of it (an advisory's CVEs can trickle into the following day).
CHROME_ATTACH_DAYS = 7


TEXT_LEFT = 0.045
TEXT_RIGHT = 0.955


def _fit_text(fig, txt, min_size, wrap_first=False):
    """Keep a title-band text inside the slide's margins.

    Shrinks the font down to ``min_size`` until the text fits. A subtitle
    (``wrap_first``) that still overflows after a small shrink is broken into
    two lines instead — two lines at a readable size beat one line at a tiny one.
    """
    renderer = fig.canvas.get_renderer()
    fig_w_px = fig.get_figwidth() * fig.dpi
    max_w = TEXT_RIGHT - TEXT_LEFT

    def width():
        return txt.get_window_extent(renderer).width / fig_w_px

    if wrap_first:
        size = txt.get_fontsize()
        while width() > max_w and size > min_size + 1.0:
            size -= 0.5
            txt.set_fontsize(size)
    if wrap_first and width() > max_w:
        s = txt.get_text()
        fit_chars = int(len(s) * max_w / width()) - 1
        txt.set_text(textwrap.fill(s, width=max(fit_chars, 30)))
    size = txt.get_fontsize()
    while width() > max_w and size > min_size:
        size -= 0.5
        txt.set_fontsize(size)


def _slide(title, subtitle=None):
    """A blank slide with the title band and footer already in place."""
    plt.style.use("dark_background")
    fig = plt.figure(figsize=(SLIDE_W, SLIDE_H), facecolor=BG)
    t = fig.text(
        TEXT_LEFT, TITLE_Y, title,
        ha="left", va="top", fontsize=F_TITLE, fontweight="bold", color=INK,
    )
    _fit_text(fig, t, min_size=18)
    if subtitle:
        s = fig.text(
            TEXT_LEFT, SUB_Y, subtitle,
            ha="left", va="top", fontsize=F_SUB, color=INK2, style="italic",
            linespacing=1.25,
        )
        _fit_text(fig, s, min_size=10.5, wrap_first=True)
    fig.text(
        0.955, FOOT_Y, f"{m._stamp()} | Data Source: Vulners CVE Archive",
        ha="right", va="bottom", fontsize=F_FOOT, color=INK3, style="italic",
    )
    return fig


def _save(fig, output_filename, what):
    m._add_logo(fig)
    # No bbox_inches="tight": the whole point is that every slide is the same
    # 16:9 frame, whatever is drawn in it.
    fig.savefig(output_filename, dpi=SLIDE_DPI, facecolor=BG, edgecolor="none")
    plt.close(fig)
    m.saved_files_log.append(f"Saved {what} slide to {os.path.abspath(output_filename)}")


def _style_axes(ax):
    ax.set_facecolor(BG)
    ax.grid(True, color=GRID, linestyle="--", linewidth=0.8, alpha=0.7)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(SPINE)
    ax.tick_params(colors="#CCCCCC", labelsize=F_TICK, length=0)


def _stroke(txt, lw=2.0):
    txt.set_path_effects([
        path_effects.Stroke(linewidth=lw, foreground=BG),
        path_effects.Normal(),
    ])


def _end_labels(ax, items, min_gap=0.088, dx=0.0):
    """Direct labels in the margin right of the axes, one per series.

    ``items`` are dicts with ``y`` (data units — where the label wants to sit
    and where its leader starts), ``color``, ``main`` and ``sub`` (the two text
    lines). Labels are nudged apart with ``_spread_label_ys`` so a crowded
    right edge stays legible, and a leader in the series color points from the
    axis edge back to the value the label belongs to.
    """
    if not items:
        return
    y0, y1 = ax.get_ylim()
    to_frac = lambda y: (y - y0) / (y1 - y0)   # noqa: E731
    items = sorted(items, key=lambda it: it["y"], reverse=True)
    targets = [to_frac(it["y"]) for it in items]
    ys = m._spread_label_ys(targets, min_gap, 0.02, 0.98)
    for it, y_line, y_lab in zip(items, targets, ys):
        ax.plot(
            [1.0 + dx, 1.018 + dx], [y_line, y_lab],
            transform=ax.transAxes, color=it["color"], alpha=0.8,
            linewidth=1.2, clip_on=False, solid_capstyle="round",
        )
        ax.plot(
            [1.0 + dx], [y_line], transform=ax.transAxes, marker="o", markersize=5,
            color=it["color"], clip_on=False,
        )
        ax.text(
            1.026 + dx, y_lab + 0.003, it["main"],
            transform=ax.transAxes, ha="left", va="bottom",
            fontsize=F_LABEL, fontweight="bold", color=INK,
        )
        if it.get("sub"):
            ax.text(
                1.026 + dx, y_lab - 0.003, it["sub"],
                transform=ax.transAxes, ha="left", va="top",
                fontsize=F_SMALL, color=INK2,
            )


def _curve(x1, y1, x2, y2, num_points=100):
    """The Sankey band edge: a cubic Bezier with horizontal tangents."""
    cx1 = x1 + (x2 - x1) * 0.4
    cx2 = x2 - (x2 - x1) * 0.4
    t = np.linspace(0, 1, num_points)
    x = (1 - t) ** 3 * x1 + 3 * (1 - t) ** 2 * t * cx1 + 3 * (1 - t) * t ** 2 * cx2 + t ** 3 * x2
    y = (1 - t) ** 3 * y1 + 3 * (1 - t) ** 2 * t * y1 + 3 * (1 - t) * t ** 2 * y2 + t ** 3 * y2
    return x, y


# ── 1. Cumulative CVEs by year ──────────────────────────────────────────────

def slide_yearly_cumulative(daily_counts, anchor_date_str, output_filename=SLIDE_FILES["yearly_cumulative"]):
    p = m._prep_yearly_cumulative(daily_counts, anchor_date_str)
    ref_dates = p["ref_dates"]
    series, dates = p["cumulative_series"], p["dates_series"]
    totals, avg = p["totals"], p["avg_speeds"]
    years = p["years"]
    cur, prev = years[-1], years[-2]
    cur_year = int(anchor_date_str[:4])
    prev_year = cur_year - 1
    passed = {info["prev_year"]: info for info in p["surpassed_info"]}

    fig = _slide(
        f"Cumulative CVE publications: {cur_year} against the four years before it",
        f"{cur_year} to date: {totals[cur]:,} CVEs, {avg[cur]:.0f} a day  ·  "
        f"{prev_year} full year: {totals[prev]:,}, {avg[prev]:.0f} a day  ·  "
        f"★ marks the day {cur_year} passed an earlier year's full-year total",
    )
    ax = fig.add_axes([0.085, AXES_BOTTOM, 0.715, CONTENT_TOP - AXES_BOTTOM])
    _style_axes(ax)

    for y in years[:-1]:
        ax.plot(dates[y], series[y], color=m.YEAR_COLORS[y], linewidth=2.2, alpha=0.9)
    ax.plot(dates[cur], series[cur], color=m.YEAR_COLORS[cur], linewidth=3.6, zorder=4)

    y_top = max(totals.values()) * 1.06 if totals else 1
    ax.set_ylim(0, y_top)
    ax.set_xlim(ref_dates[0], ref_dates[-1] + timedelta(days=6))

    for y in p["guide_years"]:
        ax.hlines(
            totals[y], ref_dates[0], p["guide_xmax"],
            color=m.YEAR_COLORS[y], linestyle="--", linewidth=1.2, alpha=0.5, zorder=1,
        )
    for info in p["surpassed_info"]:
        ax.plot(
            info["cross_x"], info["cross_y"], marker="*", markersize=14,
            color="#FFBB33", markeredgecolor=INK, markeredgewidth=0.8, zorder=6,
        )
        t = ax.annotate(
            info["short_date_str"], xy=(info["cross_x"], info["cross_y"]),
            xytext=(-8, 6), textcoords="offset points", ha="right", va="bottom",
            fontsize=F_SMALL, fontweight="bold", color=INK, zorder=6,
        )
        _stroke(t, 2.5)

    # The current year's line ends mid-chart while the year is young; a dotted
    # leader carries its total across to the label column like the others.
    if dates[cur]:
        ax.hlines(
            totals[cur], dates[cur][-1], ax.get_xlim()[1],
            color=m.YEAR_COLORS[cur], linestyle=":", linewidth=1.2, alpha=0.6, zorder=1,
        )

    labels = []
    for y in years:
        display_year = cur_year - (int(cur) - int(y))
        if y == cur:
            main = f"{display_year} to date  {totals[y]:,}"
            sub = f"{avg[y]:.1f} CVEs/day"
        else:
            main = f"{display_year}  {totals[y]:,}"
            sub = f"{avg[y]:.1f}/day"
            if y in passed:
                sub += f"  ·  passed {passed[y]['short_date_str']}"
        labels.append({"y": totals[y], "color": m.YEAR_COLORS[y], "main": main, "sub": sub})
    _end_labels(ax, labels)

    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax.xaxis.set_major_locator(mdates.MonthLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
    ax.set_ylabel("Cumulative CVEs", fontsize=F_TICK, color=INK2)
    _save(fig, output_filename, "yearly cumulative")


# ── 2. Publishing speed ─────────────────────────────────────────────────────

def slide_ytd_growth(daily_counts_2025, daily_counts_2026, anchor_date_str, output_filename=SLIDE_FILES["ytd_growth"]):
    p = m._prep_ytd_growth(daily_counts_2025, daily_counts_2026, anchor_date_str)
    cur, prev = p["current_year"], p["prev_year"]
    dates, ma25, ma26 = p["date_series"], p["ma_2025"], p["ma_2026"]
    f25, f26 = p["final_speed_25"], p["final_speed_26"]

    fig = _slide(
        f"CVE publishing speed: 30-day moving average, {cur} against {prev}",
        f"CVEs published per day, {cur} over the same days of {prev}  ·  "
        f"dashed lines are each year's average to date: {f26:.1f} against {f25:.1f} a day",
    )
    ax = fig.add_axes([0.085, AXES_BOTTOM, 0.715, CONTENT_TOP - AXES_BOTTOM])
    _style_axes(ax)

    ax.plot(dates, ma25, color=m.C_BLUE, linewidth=2.2, alpha=0.9)
    ax.plot(dates, ma26, color=m.C_RED, linewidth=3.0, zorder=4)
    ax.fill_between(dates, ma25, color=m.C_BLUE, alpha=0.08)
    ax.fill_between(dates, ma26, color=m.C_RED, alpha=0.08)
    ax.axhline(f26, color=m.C_RED, linestyle="--", linewidth=1.8, alpha=0.85)
    ax.axhline(f25, color=m.C_BLUE, linestyle=":", linewidth=1.5, alpha=0.7)

    peak = max(ma25 + ma26, default=1)
    ax.set_ylim(0, peak * 1.08)
    if dates:
        ax.set_xlim(dates[0], dates[-1] + timedelta(days=1))

    labels = [
        {"y": f26, "color": m.C_RED, "main": f"{f26:.1f}/day", "sub": f"{cur} average to date"},
        {"y": f25, "color": m.C_BLUE, "main": f"{f25:.1f}/day", "sub": f"{prev} average to date"},
    ]
    if ma26:
        labels.append({"y": ma26[-1], "color": m.C_RED, "main": f"{ma26[-1]:.0f}/day",
                       "sub": f"{cur}, last 30 days"})
    if ma25:
        labels.append({"y": ma25[-1], "color": m.C_BLUE, "main": f"{ma25[-1]:.0f}/day",
                       "sub": f"{prev}, same 30 days"})
    _end_labels(ax, labels)

    ax.xaxis.set_major_locator(mdates.MonthLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
    ax.set_ylabel("CVEs per day", fontsize=F_TICK, color=INK2)
    _save(fig, output_filename, "publishing speed")


# ── Shared Sankey furniture ─────────────────────────────────────────────────
# Both Sankey slides hang their columns from one baseline at one scale, with
# the vertical axis in CVEs: y = -depth. Lane separation is an inward inset of
# each band, in inches, so it costs no layout.
_BAND_INSET_IN = 0.02
_MIN_BAND_IN = 0.01
_HEADER_IN = 0.58        # above the baseline: month name and total
_HEADER_TEXT_IN = 0.47   # where the month name's cap height ends, within that
_FLOOR_PAD_IN = 0.14     # below the deepest column


def _subtitle_bottom(fig):
    """Figure fraction of the subtitle's lower edge (the title's when there is
    none), measured after ``_fit_text`` has shrunk or wrapped it."""
    txt = fig.texts[1] if len(fig.texts) > 1 and fig.texts[1].get_position()[1] == SUB_Y else fig.texts[0]
    y0 = txt.get_window_extent(fig.canvas.get_renderer()).y0
    return y0 / (fig.get_figheight() * fig.dpi)


def _sankey_axes(fig, max_total, n_columns, gutter_in, values_in, top=CONTENT_TOP, bottom=0.085):
    """An axes spanning the slide's width, scaled so the deepest column fills
    the band between ``top`` and ``bottom`` (figure fractions). Returns
    ``(ax, geom)`` with the conversions the drawing needs: ``cpi`` (CVEs per
    inch), ``x_in`` (data units per inch), ``span``."""
    ax = fig.add_axes([0, bottom, 1, top - bottom])
    ax.set_facecolor(BG)
    ax_h = (top - bottom) * SLIDE_H
    col_h = ax_h - _HEADER_IN - _FLOOR_PAD_IN
    cpi = max(max_total, 1) / col_h
    span = n_columns - 1
    x_range = span / (1.0 - (gutter_in + values_in) / SLIDE_W)
    x_in = x_range / SLIDE_W
    ax.set_xlim(-gutter_in * x_in, span + values_in * x_in)
    ax.set_ylim(-(max_total + _FLOOR_PAD_IN * cpi), _HEADER_IN * cpi)
    ax.axis("off")
    return ax, {"cpi": cpi, "x_in": x_in, "span": span}


def _draw_span(y0, y1, cpi):
    h = y1 - y0
    if h <= 0:
        return y0, y1
    d = min(_BAND_INSET_IN * cpi, max(0.0, (h - _MIN_BAND_IN * cpi) / 2.0))
    return y0 + d, y1 - d


def _stack_positions(volumes_per_stage, all_items):
    """Every column hung from y = 0, stacked downward in lane order."""
    positions = []
    for volumes in volumes_per_stage:
        pos = {}
        cursor = 0.0
        for item in all_items:
            h = volumes[item]
            pos[item] = (cursor - h, cursor)
            cursor -= h
        positions.append(pos)
    return positions


def _draw_bands(ax, positions, all_items, colors, cpi, alpha):
    for s in range(len(positions) - 1):
        pos_s, pos_s1 = positions[s], positions[s + 1]
        for item in all_items:
            a0, a1 = _draw_span(*pos_s[item], cpi)
            b0, b1 = _draw_span(*pos_s1[item], cpi)
            x_top, y_top = _curve(s, a1, s + 1, b1)
            x_bot, y_bot = _curve(s, a0, s + 1, b0)
            ax.fill(
                np.concatenate([x_top, x_bot[::-1]]),
                np.concatenate([y_top, y_bot[::-1]]),
                color=colors.get(item, m.SANKEY_OTHERS_COLOR), alpha=alpha, edgecolor="none",
            )
        # The underside of the last lane is the column total: the growth curve.
        last = all_items[-1]
        cx, cy = _curve(s, pos_s[last][0], s + 1, pos_s1[last][0])
        ax.plot(cx, cy, color=INK, alpha=0.22, linewidth=1.0, zorder=2)


def _draw_ruler(ax, max_total, geom, x_from, x_to, x_ticks):
    """Depth below the baseline, in CVEs — what lets a lane in one column be
    read against a whole column somewhere else."""
    ax.plot([x_from, x_to], [0, 0], color=INK, alpha=0.25, linewidth=1.2, zorder=0.5)
    step = next(
        (s for s in (100, 250, 500, 1000, 2000, 2500, 5000, 10000, 20000) if max_total / s <= 5),
        20000,
    )
    for depth in range(0, int(max_total) + 1, step):
        if depth:
            ax.plot([x_from, x_to], [-depth] * 2, color=INK, alpha=0.09, linewidth=0.8, zorder=0.5)
        tick = f"{depth / 1000:g}k" if step >= 1000 and depth else f"{depth:,}"
        ax.text(x_ticks, -depth, tick, ha="left", va="center", color=INK3, fontsize=F_SMALL)
    ax.text(
        x_ticks, 0.06 * geom["cpi"], "CVEs\ndeep", ha="left", va="bottom",
        color=INK3, fontsize=8.5, style="italic", linespacing=1.1,
    )


def _draw_columns(ax, positions, all_items, volumes_per_stage, colors, geom,
                  label_all=(), label_min_in=0.2, others_counts=None):
    """Node blocks and their values. Columns listed in ``label_all`` print every
    lane's value, nudged apart with a leader; elsewhere a value appears only
    where its own lane has the room, which keeps small lanes honest."""
    cpi, x_in = geom["cpi"], geom["x_in"]
    half_w = 0.055 * x_in
    for s, pos in enumerate(positions):
        volumes = volumes_per_stage[s]
        spread = None
        if s in label_all:
            centers = [sum(pos[item]) / 2.0 for item in all_items]
            floor = min(centers[-1], pos[all_items[-1]][0]) - 0.12 * cpi
            spread = m._spread_label_ys(centers, 0.15 * cpi, floor, 0.0)
        for i, item in enumerate(all_items):
            y0, y1 = pos[item]
            val = volumes[item]
            if val <= 0:
                continue
            d0, d1 = _draw_span(y0, y1, cpi)
            ax.add_patch(plt.Rectangle(
                (s - half_w, d0), 2 * half_w, d1 - d0,
                facecolor=colors.get(item, m.SANKEY_OTHERS_COLOR), edgecolor="none", zorder=3,
            ))
            center = (y0 + y1) / 2.0
            if spread is None and (y1 - y0) < label_min_in * cpi:
                continue
            text = f"{val:,}"
            if item == "Others" and others_counts is not None:
                text = f"{val:,} [{others_counts[s]}]"
            label_y = spread[i] if spread is not None else center
            label_x = s + (0.16 if spread is not None else 0.09) * x_in
            if spread is not None and abs(label_y - center) > 0.03 * cpi:
                ax.plot(
                    [label_x - 0.03 * x_in, s + half_w + 0.01 * x_in], [label_y, center],
                    color=INK, alpha=0.35, linewidth=0.8, zorder=3.5,
                )
            t = ax.text(
                label_x, label_y, text, ha="left", va="center", color=INK,
                fontsize=F_SMALL if spread is not None else 9, fontweight="bold", zorder=4,
            )
            _stroke(t, 1.8)


def _draw_headers(ax, labels, totals, geom):
    cpi = geom["cpi"]
    for s, (label, total) in enumerate(zip(labels, totals)):
        ax.text(s, 0.30 * cpi, label, ha="center", va="bottom", color=INK, fontsize=12.5, fontweight="bold")
        ax.text(s, 0.07 * cpi, f"({total:,})", ha="center", va="bottom", color=INK2, fontsize=10.5)


def _draw_names(ax, positions, all_items, geom, column=0):
    """CNA names beside one column, nudged apart, each with a leader back to
    its lane."""
    cpi, x_in = geom["cpi"], geom["x_in"]
    pos = positions[column]
    centers = [sum(pos[item]) / 2.0 for item in all_items]
    floor = min(centers[-1], pos[all_items[-1]][0]) - 0.3 * cpi
    ys = m._spread_label_ys(centers, 0.165 * cpi, floor, 0.0)
    for item, center, y in zip(all_items, centers, ys):
        if abs(y - center) > 0.02 * cpi:
            ax.plot(
                [column - 0.30 * x_in, column - 0.16 * x_in, column - 0.07 * x_in],
                [y, y, center],
                color=INK, alpha=0.3, linewidth=0.8, solid_joinstyle="round", zorder=3.5,
            )
        ax.text(
            column - 0.33 * x_in, y, item, ha="right", va="center",
            color=INK, fontsize=10.5, fontweight="bold",
        )


# ── 3. Monthly flow by CNA ──────────────────────────────────────────────────

def slide_sankey_flow(stats, partial_stats, top_names, anchor_date, anchor_month_complete=False,
                      output_filename=SLIDE_FILES["sankey_flow"]):
    p = m._prep_sankey_flow(stats, partial_stats, top_names, anchor_date, anchor_month_complete)
    stages, labels = p["stages"], p["stage_labels"]
    all_items, top = p["all_items"], p["sorted_top_names"]
    raw, totals, max_total, colors = p["raw_data"], p["totals"], p["max_total"], p["colors"]
    cur, prev = p["current_year"], p["prev_year"]
    ref_idx, ref_total, ref_label = p["ref_idx"], p["ref_total"], p["ref_label"]
    c = p["callout"]

    # The web chart's callout paragraph becomes the slide's one-line takeaway.
    if p["show_ref"] and c and c["n_cnas"] < len(top) and c["cum"] >= m._SANKEY_ALMOST * ref_total:
        subtitle = (
            f"{labels[-1]}: the top {c['n_cnas']} CNAs alone {c['verb']} all of {ref_label} — "
            f"{c['cum']:,} CVEs from {c['n_cnas']} publishers against {ref_total:,} from "
            f"{c['ref_publishers']}  ·  every column hangs from one baseline at one scale"
        )
    else:
        subtitle = (
            "Every column hangs from the same baseline at one scale, so equal heights mean "
            f"equal CVE counts  ·  lanes ordered by total {cur} volume"
        )
    fig = _slide(
        f"CVEs by month and CNA: the top {len(top)} publishers, "
        f"Dec {prev} – {p['months_abbrev'][p['anchor_month_str']]} {cur}",
        subtitle,
    )

    # Ten columns want every inch of height: the headers start a quarter inch
    # under the subtitle (wrapped or not) and the deepest column stops just
    # short of the footer.
    ax, geom = _sankey_axes(
        fig, max_total, len(stages), gutter_in=1.5, values_in=1.35,
        top=_subtitle_bottom(fig) - (0.25 - (_HEADER_IN - _HEADER_TEXT_IN)) / SLIDE_H,
        bottom=FOOT_Y + (F_FOOT / 72 + 0.06) / SLIDE_H - _FLOOR_PAD_IN / SLIDE_H,
    )
    cpi, x_in, span = geom["cpi"], geom["x_in"], geom["span"]
    positions = _stack_positions(raw, all_items)

    _draw_ruler(ax, max_total, geom, -0.08 * x_in, span + 0.62 * x_in, span + 0.70 * x_in)
    _draw_bands(ax, positions, all_items, colors, cpi, alpha=0.38)

    if p["show_ref"]:
        ax.plot(
            [-0.08 * x_in, span + 0.55 * x_in], [-ref_total] * 2,
            color=m.C_YELLOW, alpha=0.6, linewidth=1.5, linestyle=(0, (7, 5)), zorder=2.2,
        )
        t = ax.text(
            ref_idx + 0.09 * x_in, -ref_total - 0.03 * cpi, f"all of {ref_label} ({ref_total:,})",
            ha="left", va="top", color=m.C_YELLOW, fontsize=10.5, fontweight="bold", zorder=4,
        )
        _stroke(t, 2.5)

    others_counts = [
        sum(1 for k, v in st["data"].items() if k not in top and v > 0) for st in stages
    ]
    # 0.14in is about as thin a lane as a 9pt value can sit in — at this year's
    # scale roughly 350 CVEs, so the mid-size lanes of the inner months get
    # their numbers too.
    _draw_columns(
        ax, positions, all_items, raw, colors, geom,
        label_all=(len(stages) - 1,), label_min_in=0.14, others_counts=others_counts,
    )
    _draw_headers(ax, labels, totals, geom)
    _draw_names(ax, positions, all_items, geom, column=0)
    _save(fig, output_filename, "monthly flow Sankey")


# ── 4. One month, three ways ────────────────────────────────────────────────

def slide_incomplete_month(data_2025_partial, data_2026_partial, prev_data_partial, top_names,
                           range_label, prev_range_label, prev_year_str, anchor_date,
                           center_is_complete=False, rank_colors=None,
                           output_filename=SLIDE_FILES["incomplete_month"]):
    p = m._prep_incomplete_sankey(
        data_2025_partial, data_2026_partial, prev_data_partial, top_names,
        range_label, prev_range_label, prev_year_str, anchor_date,
        center_is_complete=center_is_complete, rank_colors=rank_colors,
    )
    stages, labels = p["stages"], p["stage_labels"]
    all_items, top, colors = p["all_items"], p["sorted_top_names"], p["colors"]
    exact, totals = p["exact_data"], p["display_totals"]
    cur, prev = p["current_year"], p["prev_year"]
    max_total = max(totals) if totals else 1

    mom = (totals[1] - totals[0]) / totals[0] * 100 if totals[0] else 0.0
    yoy = (totals[1] - totals[2]) / totals[2] * 100 if totals[2] else 0.0
    what = "the month just closed" if center_is_complete else "the month so far"
    fig = _slide(
        f"{range_label} {cur}: {what}, month over month and year over year",
        f"{labels[1]}: {totals[1]:,} CVEs — {mom:+.0f}% on {prev_range_label} ({totals[0]:,}), "
        f"{yoy:+.0f}% on {range_label} {prev} ({totals[2]:,})  ·  "
        f"columns hang from one baseline at one scale, lanes sorted by the middle column",
    )

    ax, geom = _sankey_axes(fig, max_total, len(stages), gutter_in=1.55, values_in=1.35)
    cpi, x_in, span = geom["cpi"], geom["x_in"], geom["span"]
    positions = _stack_positions(exact, all_items)

    _draw_ruler(ax, max_total, geom, -0.08 * x_in, span + 0.62 * x_in, span + 0.70 * x_in)
    _draw_bands(ax, positions, all_items, colors, cpi, alpha=0.35)
    others_counts = [
        sum(1 for k, v in st["data"].items() if k not in top and v > 0) for st in stages
    ]
    # With only three stops there is room to print every lane's value in every
    # column, which is what makes the per-CNA comparison readable.
    _draw_columns(
        ax, positions, all_items, exact, colors, geom,
        label_all=tuple(range(len(stages))), others_counts=others_counts,
    )
    _draw_headers(ax, labels, totals, geom)
    _draw_names(ax, positions, all_items, geom, column=0)
    _save(fig, output_filename, "month comparison Sankey")


# ── 5. Year-end projections ─────────────────────────────────────────────────

def slide_projections(stats, completed_month_strs, slope, intercept, partial_stats=None,
                      current_month_str=None, current_month_yoy_growth=None, anchor_date=None,
                      output_filename=SLIDE_FILES["projections"]):
    p = m._prep_projections(
        stats, completed_month_strs, slope, intercept, partial_stats=partial_stats,
        current_month_str=current_month_str, current_month_yoy_growth=current_month_yoy_growth,
        anchor_date=anchor_date,
    )
    cur, prev = p["current_year"], p["prev_year"]
    names = p["months_names"]
    n_comp, last = p["n_comp"], p["last_comp_idx"]
    cur_idx, start_proj = p["cur_month_idx"], p["start_proj_idx"]
    y25 = p["y_2025_cum"]
    y_act = p["y_2026_actual_cum"]
    y_rr, y_rr_proj = p["y_2026_runrate_cum"], p["y_2026_runrate_proj_cum"]
    y_bsl = p["y_2026_proj_cum"]
    yoy_act, yoy_rr, yoy_bsl = p["yoy_2026"], p["yoy_2026_runrate"], p["yoy_2026_green"]
    all_actual = n_comp >= 12

    fig = _slide(
        f"{cur} cumulative CVEs against {prev}, projected to December",
        f"Solid = actual  ·  dash-dot = {cur} run-rate (fitted year-over-year trend)  ·  "
        f"dashed = fixed 100k baseline  ·  * = projected  ·  boxes = growth on the same month of {prev}",
    )
    ax = fig.add_axes([0.085, AXES_BOTTOM, 0.735, CONTENT_TOP - AXES_BOTTOM])
    _style_axes(ax)

    ax.plot(names, y25, color=m.C_BLUE, marker="o", markersize=4.5, linewidth=2.2, alpha=0.8,
            zorder=2, label=f"{prev} cumulative")
    ax.plot(names[start_proj:], y_bsl[start_proj:], color=m.C_GREEN, marker="o", markersize=5,
            markerfacecolor="none", linestyle="--", linewidth=2.8, zorder=3,
            label=f"{cur} projected, 100k baseline")
    ax.plot(names[last:], y_rr_proj[last:], color=m.C_RED, marker="o", markersize=5,
            markerfacecolor="none", linestyle="-.", linewidth=2.8, zorder=4,
            label=f"{cur} projected, run-rate")
    ax.plot(names[:n_comp], y_act[:n_comp], color=m.C_RED, marker="o", markersize=5.5,
            linewidth=3.2, zorder=5, label=f"{cur} cumulative, actual")

    def pill(x, y, text, color, dx, dy, ha, va, style="solid"):
        ax.annotate(
            text, xy=(x, y), xytext=(dx, dy), textcoords="offset points", ha=ha, va=va,
            fontsize=F_SMALL, fontweight="bold", color=color,
            bbox=dict(boxstyle="round,pad=0.25", fc="#262626", ec=color, alpha=0.9, lw=1.2, linestyle=style),
            zorder=6,
        )

    def value(x, y, text, dx, dy, ha, va, color=INK, size=F_SMALL + 0.5, weight="normal"):
        ax.annotate(
            text, xy=(x, y), xytext=(dx, dy), textcoords="offset points", ha=ha, va=va,
            fontsize=size, color=color, fontweight=weight, zorder=6,
        )

    # Growth boxes go on every month the web chart labels: solid for actuals,
    # dotted for the run-rate forecast, dashed for the 100k baseline. The two
    # projected series ride the same rising segment, so the upper one's labels
    # sit above-left and the lower one's below-right, in the empty wedges.
    def rr_pill_text(i):
        # The running month's rate is a measured partial, not a forecast: no '*'.
        return f"{yoy_rr[i]:+.1f}%" if i == cur_idx else f"{yoy_rr[i]:+.1f}%*"

    for i in range(12):
        if i <= last:
            v = y_act[i]
            above = v >= y25[i]
            if i < 11:   # December's totals are read off the margin labels
                value(i, v, f"{v:,}", 0, 9 if above else -9, "center", "bottom" if above else "top")
            pill(i, v, f"{yoy_act[i]:+.1f}%", m.C_RED, 0, 27 if above else -27,
                 "center", "bottom" if above else "top")
            # The baseline's own call for a month the calendar has overtaken —
            # kept under the curve so the miss stays visible.
            if i >= m._BASELINE_PROJ_IDX and y_bsl[i] is not None and i < 11:
                value(i, y_bsl[i], f"{y_bsl[i]:,}*", 0, -9, "center", "top", color=INK2)
                pill(i, y_bsl[i], f"{yoy_bsl[i]:+.1f}%*", m.C_GREEN, 0, -27, "center", "top", "dashed")
        else:
            # Upper series' labels above-left, lower series' below-right. December's
            # totals are read off the margin labels, so only its boxes stay, hugging
            # the points: further out they land on the lines arriving from November.
            rr = (y_rr[i], rr_pill_text(i), m.C_RED, "dotted", INK)
            bsl = (y_bsl[i], f"{yoy_bsl[i]:+.1f}%*", m.C_GREEN, "dashed", INK2)
            hi, lo = (rr, bsl) if rr[0] >= bsl[0] else (bsl, rr)
            if i < 11:
                value(i, hi[0], f"{hi[0]:,}*", -9, 9, "right", "bottom", color=hi[4])
                value(i, lo[0], f"{lo[0]:,}*", 9, -9, "left", "top", color=lo[4])
            up, down = (27, -27) if i < 11 else (12, -14)
            pill(i, hi[0], hi[1], hi[2], -9, up, "right", "bottom", hi[3])
            pill(i, lo[0], lo[1], lo[2], 9, down, "left", "top", lo[3])

    peak = max([*p["y_2026_full_cum"], *y_rr] + [v for v in y_bsl if v is not None] + y25)
    ax.set_ylim(0, peak * 1.12)
    ax.set_xlim(-0.3, 11.4)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax.set_ylabel("Cumulative CVEs", fontsize=F_TICK, color=INK2)
    ax.legend(loc="upper left", facecolor="#262626", edgecolor="#444444", fontsize=10.5)

    star = "" if all_actual else "*"
    labels = [
        {"y": y_rr[11], "color": m.C_RED, "main": f"{y_rr[11]:,}{star}",
         "sub": f"{cur} full year, actual" if all_actual else f"{cur} run-rate projection"},
        {"y": y_bsl[11], "color": m.C_GREEN, "main": f"{y_bsl[11]:,}*", "sub": "100k baseline"},
        {"y": y25[11], "color": m.C_BLUE, "main": f"{y25[11]:,}", "sub": f"{prev} full year"},
    ]
    _end_labels(ax, labels)
    _save(fig, output_filename, "projection")


# ── 6. The reserved backlog ─────────────────────────────────────────────────

def slide_candidate_track(candidate_stats, output_filename=SLIDE_FILES["candidate_track"]):
    p = m._prep_candidate_track(candidate_stats)
    if p is None:
        return
    months, totals, rows, mat, vmax = p["months"], p["totals"], p["rows"], p["mat"], p["vmax"]
    year = p["year"]

    fig = _slide(
        f"Hidden volume: who feeds the reserved CVE backlog in {year}",
        f"{p['grand_total']:,} CVE IDs reserved but not yet published in {year}, none of them counted "
        "in the other charts  ·  cell = reserved CVEs a source touched that month  ·  brighter = more",
    )
    ax = fig.add_axes([0.115, 0.10, 0.84, 0.655])
    ax.set_facecolor(BG)
    ax.imshow(mat, aspect="auto", cmap="inferno", vmin=0, vmax=vmax)

    ax.set_xticks(range(len(months)))
    ax.set_xticklabels(
        [f"{datetime.strptime(mo, '%Y-%m').strftime('%b')}\n{totals[mo]:,} CVEs" for mo in months],
        fontsize=11, fontweight="bold", color=INK,
    )
    ax.xaxis.set_ticks_position("top")
    ax.tick_params(axis="x", labeltop=True, labelbottom=False, length=0, pad=6)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(rows, fontsize=11, fontweight="bold", color=INK)
    ax.tick_params(axis="y", length=0, pad=8)

    for i in range(len(rows)):
        for j in range(len(months)):
            v = int(mat[i, j])
            if v > 0:
                ax.text(
                    j, i, f"{v}", ha="center", va="center", fontsize=10.5, fontweight="bold",
                    color="#111111" if mat[i, j] > vmax * 0.5 else "#EAEAEA",
                )
    for s in ("top", "right", "left", "bottom"):
        ax.spines[s].set_visible(False)
    ax.set_xticks(np.arange(-0.5, len(months), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(rows), 1), minor=True)
    ax.grid(which="minor", color=BG, linewidth=2.5)
    ax.tick_params(which="minor", length=0)
    _save(fig, output_filename, "candidate track")


# ── 7. NVD status by year ───────────────────────────────────────────────────

def _queue_share(values, statuses, i):
    """Share of bar/column ``i`` still waiting for NVD analysis, in percent."""
    total = sum(values[s][i] for s in statuses)
    queued = sum(values[s][i] for s in statuses if s in m.STATUS_QUEUE)
    return (queued / total * 100.0) if total else 0.0


def slide_status_yearly(status_yearly, anchor_date, output_filename=SLIDE_FILES["status_yearly"]):
    p = m._prep_status_yearly(status_yearly, anchor_date)
    if p is None:
        return
    years, statuses, colors = p["years"], p["statuses"], p["colors"]
    values, totals = p["values"], p["totals"]
    n = len(years)

    subtitle = (
        "Blue = analysed by NVD  ·  gray = Deferred, waved through unanalysed  ·  "
        "warm colors = still in the NVD queue"
    )
    if n >= 2:
        q_now, q_prev = _queue_share(values, statuses, n - 1), _queue_share(values, statuses, n - 2)
        d_now = values["Deferred"][n - 1] / totals[n - 1] * 100 if totals[n - 1] else 0
        subtitle = (
            f"{p['end_label']}: {totals[n - 1]:,} CVEs, {q_now:.0f}% still in the NVD queue "
            f"({q_prev:.0f}% for {years[n - 2]}) and {d_now:.0f}% deferred unanalysed  ·  "
            "blue = analysed, gray = deferred, warm = queued"
        )
    fig = _slide(
        f"CVEs published per year by NVD status, {p['start_year']} – {p['end_label']}",
        subtitle,
    )
    ax = fig.add_axes([0.085, AXES_BOTTOM, 0.715, CONTENT_TOP - AXES_BOTTOM])
    _style_axes(ax)
    ax.grid(False, axis="x")

    x = np.arange(n)
    bottoms = np.zeros(n)
    y_max = max(totals) if totals else 1
    dark_text = {"Modified", "Undergoing Analysis", "Awaiting Analysis"}
    for status, color in zip(statuses, colors):
        vals = np.array(values[status], dtype=float)
        ax.bar(x, vals, 0.7, bottom=bottoms, label=status, color=color, edgecolor=BG, linewidth=1.2, alpha=0.95)
        # A count inside every segment tall enough to hold one.
        for i in range(n):
            if vals[i] >= 0.045 * y_max:
                ax.text(
                    x[i], bottoms[i] + vals[i] / 2.0, f"{int(vals[i]):,}", ha="center", va="center",
                    fontsize=F_SMALL, fontweight="bold",
                    color="#1E1E1E" if status in dark_text else INK,
                )
        bottoms += vals
    for i, total in enumerate(bottoms):
        ax.annotate(
            f"{int(total):,}", xy=(x[i], total), xytext=(0, 6), textcoords="offset points",
            ha="center", va="bottom", fontsize=F_LABEL, fontweight="bold", color=INK,
        )

    ax.set_xticks(x)
    ax.set_xticklabels(
        [f"{y} YTD" if (i == n - 1 and "YTD" in p["end_label"]) else str(y) for i, y in enumerate(years)],
        fontsize=F_TICK, fontweight="bold", color="#E0E0E0",
    )
    ax.set_ylim(0, y_max * 1.08)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax.set_ylabel("CVEs published", fontsize=F_TICK, color=INK2)
    # Legend in the right margin, top-down in stack order (top of the bar first).
    handles, labels = ax.get_legend_handles_labels()
    ax.legend(
        reversed(handles), reversed(labels), loc="upper left", bbox_to_anchor=(1.02, 1.0),
        facecolor="#262626", edgecolor="#444444", fontsize=F_LABEL, labelspacing=0.9, borderpad=0.8,
    )
    _save(fig, output_filename, "yearly status bar")


# ── 8 & 9. NVD status by week: absolute, then share ─────────────────────────

# Dated events drawn on the share view as quiet vertical rules. Each names the
# status whose weekly series switches on at the event, and the slide checks the
# data for that switch before drawing: the rule is placed on the event date only
# when the series' first sustained non-zero week lies within a week of it,
# otherwise the discrepancy is printed and the rule is skipped.
NVD_STATUS_EVENTS = [
    # NIST, "NVD Updates NVD Operations to Address Record CVE Growth", 15 Apr 2026:
    # CVEs published before 1 Mar 2026 moved to Not Scheduled; enrichment from
    # then on limited to KEV, federal software and EO 14028 critical software.
    {"date": "2026-03-01", "label": "1 Mar 2026 · NVD prioritisation cutoff", "status": "Awaiting Analysis"},
    # The intake queue reappears: "Received" goes from zero to hundreds a week.
    {"date": "2026-07-20", "label": "Jul 2026 · queue returns", "status": "Received"},
]


def _status_switch_on(p, status_weekly, status, sustain=3):
    """First week from which ``status`` is non-zero for ``sustain`` weeks running."""
    keys = [w.isoformat() for w in p["weeks"]]
    vals = [status_weekly.get(k, {}).get(status, 0) for k in keys]
    for i in range(len(vals) - sustain + 1):
        if all(v > 0 for v in vals[i:i + sustain]):
            return p["weeks"][i], vals[i:i + sustain]
    return None, []

def _slide_status_weekly(p, output_filename, normalized, status_weekly=None):
    dates, statuses, colors = p["dates"], p["statuses"], p["colors"]
    series = p["y_normalized"] if normalized else p["y_absolute"]
    last_total = p["week_totals"][-1]
    q_last = sum(
        p["y_absolute"][statuses.index(s)][-1] for s in m.STATUS_QUEUE
    ) / last_total * 100 if last_total else 0.0
    d_last = p["y_absolute"][statuses.index("Deferred")][-1] / last_total * 100 if last_total else 0.0
    week_of = p["weeks"][-1].strftime("%b %d")
    end_of = (p["weeks"][-1] + timedelta(days=6)).strftime("%b %d")

    if normalized:
        title = "Weekly CVE publications by NVD status: the mix"
        subtitle = (
            f"Every week squeezed to the same height, {p['start_str']} to {p['end_str']}  ·  "
            f"week of {week_of}–{end_of}: {q_last:.0f}% in the NVD queue, {d_last:.0f}% deferred"
        )
    else:
        title = "Weekly CVE publications by NVD status"
        subtitle = (
            f"Full weeks, Monday to Sunday, {p['start_str']} to {p['end_str']}  ·  "
            f"week of {week_of}–{end_of}: {last_total:,} CVEs, {q_last:.0f}% still in the NVD queue"
        )
    fig = _slide(title, subtitle)
    ax = fig.add_axes([0.085, AXES_BOTTOM, 0.715, CONTENT_TOP - AXES_BOTTOM])
    _style_axes(ax)

    ax.stackplot(dates, series, labels=statuses, colors=colors, alpha=0.9, edgecolor=BG, linewidth=0.4)
    ax.set_xlim(dates[0], dates[-1])
    if normalized:
        ax.set_ylim(0, 100)
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v)}%"))
        ax.set_ylabel("Share of the week's CVEs", fontsize=F_TICK, color=INK2)
    else:
        ax.set_ylim(0, max(p["week_totals"]) * 1.06)
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v):,}"))
        ax.set_ylabel("CVEs published per week", fontsize=F_TICK, color=INK2)
    ax.xaxis.set_major_locator(mdates.MonthLocator(bymonth=(1, 4, 7, 10)))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %Y"))
    ax.tick_params(axis="x", labelsize=F_TICK - 1)

    if status_weekly is not None:
        y_top = ax.get_ylim()[1]
        for ev in NVD_STATUS_EVENTS:
            week, head = _status_switch_on(p, status_weekly, ev["status"])
            ev_date = date.fromisoformat(ev["date"])
            print(f"[status_weekly] {ev['status']!r} first sustained non-zero week: {week}, values {head}; "
                  f"event {ev['date']}")
            if week is None or abs((week - ev_date).days) > 7:
                print(f"[status_weekly] event {ev['date']} not confirmed by the data; rule skipped.")
                continue
            x = datetime(ev_date.year, ev_date.month, ev_date.day)
            ax.axvline(x, color=INK2, linestyle=(0, (4, 4)), linewidth=1.1, alpha=0.8, zorder=5)
            # Written along the rule, top down, so two events a few months
            # apart never run into each other or into the band labels.
            t = ax.annotate(ev["label"], xy=(x, 0.97 * y_top), xytext=(-4, 0), textcoords="offset points",
                            rotation=90, rotation_mode="anchor", ha="right", va="bottom",
                            fontsize=F_SMALL, color=INK2, style="italic", zorder=6)
            _stroke(t, 2.5)

    # Each band named at its right-hand end, with last week's value.
    labels = []
    cursor = 0.0
    for s, color, ser in zip(statuses, colors, series):
        v = ser[-1]
        center = cursor + v / 2.0
        cursor += v
        if normalized:
            sub = f"{v:.0f}% of the week" if v >= 0.5 else "under 1%"
        else:
            sub = f"{int(round(v)):,} last week"
        labels.append({"y": center, "color": color, "main": s, "sub": sub})
    _end_labels(ax, labels)
    _save(fig, output_filename, "weekly status (share)" if normalized else "weekly status (absolute)")


def slide_status_weekly_absolute(status_weekly, anchor_date, output_filename=SLIDE_FILES["status_weekly_absolute"]):
    p = m._prep_status_weekly(status_weekly, anchor_date)
    if p is not None:
        _slide_status_weekly(p, output_filename, normalized=False, status_weekly=status_weekly)


def slide_status_weekly_normalized(status_weekly, anchor_date, output_filename=SLIDE_FILES["status_weekly_normalized"]):
    p = m._prep_status_weekly(status_weekly, anchor_date)
    if p is not None:
        _slide_status_weekly(p, output_filename, normalized=True, status_weekly=status_weekly)


# ── 10. Chrome fan-in: every release, one restart ───────────────────────────

def _chrome_releases(chrome_cves, anchor_date):
    """Group the year's Chrome CVEs into releases.

    A release is pinned by the Chrome security advisory (``GCSA-…``) its CVEs
    reference, and dated by the day those CVEs were published. Advisories that
    name the same Chrome version are one release (a desktop and a mobile post
    for the same build). A CVE without an advisory link joins the release of
    its own Chrome version (from its Nessus plugin id) published within
    ``CHROME_ATTACH_DAYS`` of it — most of Chrome's volume arrives this way, in
    bulk on release day. Whatever matches neither is counted as unattributed.

    Returns ``(releases, unattributed)``; each release is a dict with ``key``,
    ``version`` (or ``None``), ``major``, ``date``, ``linked`` and ``attached``
    counts, sorted by date.
    """
    rows = [r for r in chrome_cves if r["day"] <= anchor_date[:10]]
    by_adv = {}
    for r in rows:
        for gid in r["advisories"]:
            by_adv.setdefault(gid, []).append(r)

    releases = {}
    for gid, rs in by_adv.items():
        vers = collections.Counter(v for r in rs for v in r["versions"])
        version = sorted(vers, key=lambda v: (-vers[v], v))[0] if vers else None
        key = version or gid
        rel = releases.setdefault(key, {
            "key": key, "version": version, "advisories": set(), "date": None,
            "linked_ids": set(), "attached_ids": set(),
        })
        rel["advisories"].add(gid)
        first = min(r["day"] for r in rs)
        rel["date"] = first if rel["date"] is None else min(rel["date"], first)
        rel["linked_ids"].update(r["id"] for r in rs)

    by_version = {}
    for rel in releases.values():
        if rel["version"]:
            by_version.setdefault(rel["version"], []).append(rel)
    unattributed = 0
    for r in rows:
        if r["advisories"]:
            continue
        day = date.fromisoformat(r["day"])
        best = None
        for v in r["versions"]:
            for rel in by_version.get(v, ()):
                gap = abs((date.fromisoformat(rel["date"]) - day).days)
                if gap <= CHROME_ATTACH_DAYS and (best is None or gap < best[0]):
                    best = (gap, rel)
        if best is None:
            unattributed += 1
        else:
            best[1]["attached_ids"].add(r["id"])

    out = []
    for rel in releases.values():
        out.append({
            "key": rel["key"],
            "version": rel["version"],
            "major": int(rel["version"].split(".")[0]) if rel["version"] else None,
            "date": date.fromisoformat(rel["date"]),
            "advisories": sorted(rel["advisories"]),
            "linked": len(rel["linked_ids"]),
            "attached": len(rel["attached_ids"]),
        })
    out.sort(key=lambda rel: (rel["date"], rel["version"] or ""))
    return out, unattributed


def slide_fanin_chrome(chrome_cves, anchor_date, output_filename=SLIDE_FILES["fanin_chrome"]):
    """Every Chrome release of the year with the CVEs it carried, against the
    one thing a user ever has to do about any of them: restart the browser."""
    releases, unattributed = _chrome_releases(chrome_cves, anchor_date)
    if not releases:
        return
    year = anchor_date[:4]
    n = len(releases)
    totals = [rel["linked"] + rel["attached"] for rel in releases]
    milestone_first = {}
    for rel in releases:
        if rel["major"] is not None and rel["major"] not in milestone_first:
            milestone_first[rel["major"]] = rel

    # The numbers behind the picture, persisted and printed so a figure quoted
    # from the slide can be checked against them.
    csv_path = os.path.splitext(output_filename)[0].replace("_slide", "") + ".csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["release_date", "version", "kind", "cves", "advisories"])
        writer.writeheader()
        for rel, tot in zip(releases, totals):
            writer.writerow({
                "release_date": rel["date"].isoformat(), "version": rel["version"] or "",
                "kind": "milestone" if milestone_first.get(rel["major"]) is rel else "point update",
                "cves": tot, "advisories": ";".join(rel["advisories"]),
            })
    m.saved_files_log.append(f"Saved Chrome release CSV to {os.path.abspath(csv_path)}")
    q1 = [(rel, tot) for rel, tot in zip(releases, totals) if rel["date"].month <= 3]
    q1_cves = sum(tot for _, tot in q1)
    print(f"\n[fanin_chrome] {year}: Q1 (Jan 1 – Mar 31): {len(q1)} releases, {q1_cves} CVEs; "
          + (f"largest Q1 release {max(q1, key=lambda rt: rt[1])[0]['version']} with {max(tot for _, tot in q1)} CVEs; " if q1 else "")
          + f"year to date: {n} releases, {sum(totals):,} CVEs (unattributed {unattributed}); "
          + (f"CVEs per release: Q1 {q1_cves / len(q1):.1f} vs YTD {sum(totals) / n:.1f}" if q1 else ""))
    print("[fanin_chrome] milestone first releases: " + ", ".join(
        f"{mj}: {milestone_first[mj]['linked'] + milestone_first[mj]['attached']}" for mj in sorted(milestone_first)))
    grand = sum(totals)
    big_i = max(range(n), key=totals.__getitem__)
    big = releases[big_i]
    # The first release of each milestone is the milestone itself; the rest are point updates.
    milestone_idx = {i for i, rel in enumerate(releases) if milestone_first.get(rel["major"]) is rel}

    big_ver = f"Chrome {big['version']}" if big["version"] else "an unnumbered release"
    fig = _slide(
        f"Chrome CVEs per release, {year}: every update, one user action",
        f"{n} releases, Jan 1 – {releases[-1]['date'].strftime('%b %-d')}, {grand:,} CVEs  ·  "
        f"biggest: {big_ver} on {big['date'].strftime('%b %-d')}, {totals[big_i]:,} CVEs  ·  "
        f"user action for every one of them: exactly one restart",
    )
    # The axes run down to just above the footer: the rotated date ticks and the
    # month names underneath are all that sits below them.
    ax_bottom = 0.165
    ax = fig.add_axes([0.075, ax_bottom, 0.885, CONTENT_TOP - ax_bottom])
    _style_axes(ax)
    ax.grid(False, axis="x")
    ax_h_in = (CONTENT_TOP - ax_bottom) * SLIDE_H

    xs = np.arange(n)
    colors = [m.C_RED if i in milestone_idx else m.C_BLUE for i in range(n)]
    ax.bar(xs, totals, 0.72, color=colors, alpha=0.95, edgecolor=BG, linewidth=0.6, zorder=3)

    y_max = max(totals) * 1.30
    ax.set_ylim(0, y_max)
    ax.set_xlim(-0.7, n - 0.3)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax.set_ylabel("CVEs published with the release", fontsize=F_TICK, color=INK2)

    # Every release pinned to its day; month names underneath, month breaks as faint rules.
    ax.set_xticks(xs)
    ax.set_xticklabels([rel["date"].strftime("%b %-d") for rel in releases], rotation=90, fontsize=7.5, color="#CCCCCC")
    ax.tick_params(axis="x", pad=3)
    month_y = -0.58 / ax_h_in     # 0.58in below the axis: under the rotated day labels
    month_start = 0
    for i in range(1, n + 1):
        if i == n or releases[i]["date"].month != releases[month_start]["date"].month:
            ax.text((month_start + i - 1) / 2.0, month_y, releases[month_start]["date"].strftime("%B"),
                    transform=ax.get_xaxis_transform(), ha="center", va="top",
                    fontsize=F_SMALL, fontweight="bold", color=INK2)
            if i < n:
                ax.axvline(i - 0.5, color=GRID, linewidth=0.8, alpha=0.8, zorder=1)
            month_start = i

    # Counts above every bar; the milestone's number above its first release,
    # lifted a step when the previous milestone tag sits within two bars.
    prev_tag_i = None
    for i, (rel, tot) in enumerate(zip(releases, totals)):
        ax.annotate(f"{tot:,}", xy=(i, tot), xytext=(0, 3), textcoords="offset points", ha="center", va="bottom",
                    fontsize=7.5, fontweight="bold", color=INK, zorder=5)
        if i in milestone_idx:
            lift = 14 if (prev_tag_i is None or i - prev_tag_i > 2) else 27
            ax.annotate(f"Chrome {rel['major']}", xy=(i, tot), xytext=(0, lift), textcoords="offset points",
                        ha="center", va="bottom", fontsize=F_SMALL, fontweight="bold", color=m.C_RED, zorder=5)
            prev_tag_i = i
        elif rel["version"] is None:
            ax.annotate("version\npending", xy=(i, tot), xytext=(0, 14), textcoords="offset points",
                        ha="center", va="bottom", fontsize=7, color=INK2, zorder=5, linespacing=1.1)

    # The old normal, so the first quarter reads as a baseline rather than as empty.
    if q1 and len(q1) < n:
        il, ir = 0, len(q1) - 1
        top = max(tot for _, tot in q1) + 0.17 * y_max      # clear of the milestone tags
        ax.plot([il - 0.45, il - 0.45, ir + 0.45, ir + 0.45], [top - 0.02 * y_max, top, top, top - 0.02 * y_max],
                color=INK3, linewidth=1.1, zorder=5, solid_joinstyle="miter")
        ax.text((il + ir) / 2.0, top + 0.012 * y_max, f"Jan–Mar: {len(q1)} releases, {q1_cves} CVEs",
                ha="center", va="bottom", fontsize=F_SMALL, color=INK2, style="italic", zorder=5)

    # The persistent counter-weight: one restart, whatever the release brings.
    ax.axhline(1, color=m.C_YELLOW, linestyle=(0, (6, 4)), linewidth=1.6, alpha=0.9, zorder=4)
    ax.text(
        0.012, 0.955, "User action required: 1 restart",
        transform=ax.transAxes, ha="left", va="top", fontsize=F_TITLE - 4, fontweight="bold", color=m.C_YELLOW,
        bbox=dict(boxstyle="round,pad=0.5", fc="#262626", ec=m.C_YELLOW, lw=1.8), zorder=6,
    )
    ax.text(0.02, 0.845, f"one restart per release, {n} releases this year — the dashed line never moves",
            transform=ax.transAxes, ha="left", va="top", fontsize=F_SMALL, color=m.C_YELLOW, style="italic", zorder=6)
    ax.annotate(
        "", xy=(0.006, 1.0 / y_max), xytext=(0.006, 0.80), textcoords="axes fraction", xycoords="axes fraction",
        arrowprops=dict(arrowstyle="-|>", color=m.C_YELLOW, lw=1.4, alpha=0.9, shrinkA=0, shrinkB=2), zorder=6,
    )

    # Which bars are milestones — in the empty air over the small spring releases.
    from matplotlib.patches import Patch
    handles = [
        Patch(facecolor=m.C_RED, alpha=0.95, label="first release of a milestone"),
        Patch(facecolor=m.C_BLUE, alpha=0.95, label="point update"),
    ]
    ax.legend(handles=handles, loc="upper left", bbox_to_anchor=(0.06, 0.55), facecolor="#262626",
              edgecolor="#444444", fontsize=F_SMALL, framealpha=0.95)

    # The milestones the blog counts: a bracket over their releases, with the claim.
    ms_idx = [i for i, rel in enumerate(releases) if rel["major"] in CHROME_BLOG_MILESTONES]
    if ms_idx:
        il, ir = min(ms_idx), max(ms_idx)
        top = max(totals[il:ir + 1]) + 0.10 * y_max
        xl, xr = il - 0.45, ir + 0.45
        ax.plot([xl, xl, xr, xr], [top - 0.025 * y_max, top, top, top - 0.025 * y_max],
                color=m.C_RED, linewidth=1.4, zorder=5, solid_joinstyle="miter")
        in_data = sum(totals[i] for i in ms_idx)
        ms_names = " + ".join(f"Chrome {mj}" for mj in CHROME_BLOG_MILESTONES)
        # Bare figures under the restart box; the red bracket over the Chrome
        # 149/150 releases is what they refer to.
        ax.text(0.06, 0.745, f"{ms_names}: {in_data:,} CVEs across {len(ms_idx)} releases",
                transform=ax.transAxes, ha="left", va="top", fontsize=F_LABEL, fontweight="bold", color=INK, zorder=6)

    _save(fig, output_filename, "Chrome fan-in")


# ── 10b. Chrome fan-in at estate scale ──────────────────────────────────────
# The same releases as the fan-in slide, with the axis in the unit a scanner
# console shows: one finding per asset per CVE, before any aggregation, across
# a desktop estate of ESTATE_SEATS. Drawn from the CSV the fan-in slide writes,
# so the two can never disagree. It shows the size of the number and nothing
# else — the one-restart resolution belongs to the slide that follows it.
ESTATE_SEATS = 2500


def slide_fanin_chrome_estate(chrome_cves, anchor_date, output_filename=SLIDE_FILES["fanin_chrome_estate"]):
    csv_path = os.path.splitext(SLIDE_FILES["fanin_chrome"])[0].replace("_slide", "") + ".csv"
    if not os.path.exists(csv_path):
        print(f"{csv_path} missing; estate slide skipped.")
        return
    with open(csv_path, newline="") as f:
        rows = [{"date": date.fromisoformat(r["release_date"]), "version": r["version"],
                 "milestone": r["kind"] == "milestone", "cves": int(r["cves"])} for r in csv.DictReader(f)]
    if not rows:
        return
    year = anchor_date[:4]
    n = len(rows)
    findings = [r["cves"] * ESTATE_SEATS for r in rows]
    total_cves = sum(r["cves"] for r in rows)
    total_findings = total_cves * ESTATE_SEATS
    big_i = max(range(n), key=lambda i: rows[i]["cves"])
    big = rows[big_i]
    q1 = [i for i, r in enumerate(rows) if r["date"].month <= 3]
    q1_cves = sum(rows[i]["cves"] for i in q1)

    print(f"\n[fanin_chrome_estate] estate of {ESTATE_SEATS:,} seats, one finding per asset per CVE: "
          f"{n} releases, {total_cves:,} CVEs -> {total_findings:,} findings; largest release Chrome {big['version']} "
          f"on {big['date'].strftime('%b %-d')}: {big['cves']:,} CVEs -> {big['cves'] * ESTATE_SEATS:,} findings"
          + (f"; Jan–Mar: {len(q1)} releases, {q1_cves:,} CVEs -> {q1_cves * ESTATE_SEATS:,} findings" if q1 else ""))

    fig = _slide(
        "One year of Chrome updates, counted the way a console counts",
        f"A {ESTATE_SEATS:,}-seat desktop estate, one finding per asset per CVE, before any aggregation  ·  "
        f"{n} releases in {year} to date: {total_cves:,} CVEs → {total_findings:,} findings  ·  "
        f"Chrome {big['version']} on {big['date'].strftime('%b %-d')}: {big['cves']:,} CVEs → {big['cves'] * ESTATE_SEATS:,} findings",
    )
    # Same frame as the fan-in slide; a little more room on the left for a
    # seven-digit axis, and a right-hand axis carrying the CVE count.
    ax_bottom = 0.165
    ax = fig.add_axes([0.10, ax_bottom, 0.80, CONTENT_TOP - ax_bottom])
    _style_axes(ax)
    ax.grid(False, axis="x")
    ax_h_in = (CONTENT_TOP - ax_bottom) * SLIDE_H

    xs = np.arange(n)
    colors = [m.C_RED if r["milestone"] else m.C_BLUE for r in rows]
    ax.bar(xs, findings, 0.72, color=colors, alpha=0.95, edgecolor=BG, linewidth=0.6, zorder=3)
    y_max = max(findings) * 1.30
    ax.set_ylim(0, y_max)
    ax.set_xlim(-0.7, n - 0.3)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax.set_ylabel(f"findings across {ESTATE_SEATS:,} desktops", fontsize=F_TICK, color=INK2)

    # The CVE count on the right, the same bars read in the vendor's unit.
    ax2 = ax.twinx()
    ax2.set_ylim(0, y_max / ESTATE_SEATS)
    ax2.set_facecolor("none")
    for sp in ("top", "left", "bottom"):
        ax2.spines[sp].set_visible(False)
    ax2.spines["right"].set_color(SPINE)
    ax2.tick_params(axis="y", colors="#CCCCCC", labelsize=F_TICK, length=0)
    ax2.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax2.set_ylabel("CVEs in the release", fontsize=F_TICK, color=INK2, labelpad=10)

    # Release dates and month names, as on the fan-in slide.
    ax.set_xticks(xs)
    ax.set_xticklabels([r["date"].strftime("%b %-d") for r in rows], rotation=90, fontsize=7.5, color="#CCCCCC")
    ax.tick_params(axis="x", pad=3)
    month_y = -0.58 / ax_h_in
    month_start = 0
    for i in range(1, n + 1):
        if i == n or rows[i]["date"].month != rows[month_start]["date"].month:
            ax.text((month_start + i - 1) / 2.0, month_y, rows[month_start]["date"].strftime("%B"),
                    transform=ax.get_xaxis_transform(), ha="center", va="top",
                    fontsize=F_SMALL, fontweight="bold", color=INK2)
            if i < n:
                ax.axvline(i - 0.5, color=GRID, linewidth=0.8, alpha=0.8, zorder=1)
            month_start = i
    for i, r in enumerate(rows):
        t = ax.annotate(r["version"].split(".")[0] if r["version"] else "", xy=(i, 0), xytext=(0, 3),
                        textcoords="offset points", ha="center", va="bottom", fontsize=7.5, color=INK,
                        fontweight="bold", zorder=5, rotation=90)
        _stroke(t, 1.8)

    # The biggest release, in both units; the year's total in the right margin.
    ax.annotate(
        f"{big['cves']:,} CVEs  ·  {big['cves'] * ESTATE_SEATS:,} findings",
        xy=(big_i, findings[big_i]), xytext=(-12, 22), textcoords="offset points", ha="right", va="bottom",
        fontsize=F_LABEL, fontweight="bold", color=INK, zorder=6,
        arrowprops=dict(arrowstyle="-", color=INK3, lw=1.0, alpha=0.8, shrinkA=2, shrinkB=3),
    )
    # The old normal, in the same unit.
    if q1 and len(q1) < n:
        il, ir = q1[0], q1[-1]
        top = max(findings[i] for i in q1) + 0.17 * y_max
        ax.plot([il - 0.45, il - 0.45, ir + 0.45, ir + 0.45], [top - 0.02 * y_max, top, top, top - 0.02 * y_max],
                color=INK3, linewidth=1.1, zorder=5, solid_joinstyle="miter")
        ax.text((il + ir) / 2.0, top + 0.012 * y_max,
                f"Jan–Mar: {len(q1)} releases, {q1_cves:,} CVEs · {q1_cves * ESTATE_SEATS:,} findings",
                ha="center", va="bottom", fontsize=F_SMALL, color=INK2, style="italic", zorder=5)
    # The year so far, as the quiet sum in the top-left air.
    ax.text(0.012, 0.955, f"{year} to date: {total_cves:,} CVEs across {n} releases\n"
                          f"= {total_findings:,} findings, one per desktop per CVE",
            transform=ax.transAxes, ha="left", va="top", fontsize=F_LABEL, color=INK2, linespacing=1.4, zorder=6)
    _save(fig, output_filename, "Chrome fan-in at estate scale")


# ── 11. Fan-out: one CVE, N downstream package updates ─────────────────────

_FANOUT_MAX_BARS = 15   # products drawn individually; the rest pool into one bar
# Readable names for the affected-software strings the archive carries.
_FANOUT_SOFTWARE_LABELS = {"linux linux_kernel": "Linux kernel", "openssl": "OpenSSL", "haxx curl": "curl"}


def _fanout_rows(record):
    """The bars: from ``audit/cve`` (package updates per product) when it can be
    reached, else from the archive references (records per issuer)."""
    audit_rows, totals = m.fanout_packages(m.fetch_audit_cve(record["id"]))
    if audit_rows:
        rows = [{"label": r["product"], "value": r["updates"],
                 "note": f"{r['releases']} release{'s' if r['releases'] != 1 else ''} · "
                         + ", ".join(sorted(r["packages"][:8], key=len)[:3])}
                for r in audit_rows]
        return rows, totals, "audit"
    groups = m.fanout_breakdown(record["references"])
    rows = sorted(({"label": g, "value": len(ids), "note": ""} for g, ids in groups.items()),
                  key=lambda r: (-r["value"], r["label"]))
    totals = {"updates": sum(r["value"] for r in rows), "products": len(rows), "releases": None, "advisories": None}
    return rows, totals, "references"


def slide_fanout_downstream(record, output_filename=SLIDE_FILES["fanout_downstream"]):
    """One CVE, and how far its fix travels: every downstream package rebuilt for
    it, grouped by the product that ships it. The matched pair of the Chrome
    fan-in slide — same frame, opposite direction of travel.

    The slide describes the ecosystem, never the viewer: the ladder in the right
    margin (one fix → products → releases → rebuilt packages) is an ecosystem
    fact, and the slide says in print that the count is the ecosystem's rebuilds,
    not any one organisation's queue. Nothing on it is an instruction.

    No time axis, on purpose: ``audit/cve``'s ``affectedPackages`` carry
    ``id``/``name``/``range``/``registry``/``distro`` and no date, and the archive
    references carry only ids, so the propagation delay per product is not in
    this data. (The cache holds 4,261 entries for FANOUT_CVE with no date-bearing
    field, checked 2026-09-03.) Do not estimate it; add it only from real
    per-advisory dates."""
    if not record:
        return
    rows, totals, source = _fanout_rows(record)
    if not rows:
        return
    total = totals["updates"]
    n_products = len(rows)
    if len(rows) > _FANOUT_MAX_BARS:
        head, tail = rows[:_FANOUT_MAX_BARS - 1], rows[_FANOUT_MAX_BARS - 1:]
        rows = head + [{"label": f"{len(tail)} more products", "value": sum(r["value"] for r in tail),
                        "note": ", ".join(r["label"] for r in tail[:4]) + ("…" if len(tail) > 4 else "")}]
    rows = rows[::-1]                                  # biggest at the top
    pooled_idx = 0 if len(rows) < n_products else None

    cve = record["id"]
    software = record["software"][0] if record["software"] else (record["reporter"] or "")
    software = _FANOUT_SOFTWARE_LABELS.get(software, software.replace("_", " "))
    kev_txt = "  ·  CISA KEV" if record["kev"] else ""
    published = datetime.strptime(record["published"], "%Y-%m-%d").strftime("%b %-d, %Y") if record["published"] else ""
    unit = "rebuilt packages" if source == "audit" else "downstream records"
    if source == "audit":
        scope = f"{n_products} products, {totals['releases']} releases, {total:,} {unit}  ·  Vulners audit/cve"
    else:
        scope = f"{n_products} issuers, {total:,} {unit}  ·  archive references (audit/cve unavailable)"
    print(f"Fan-out ladder for {cve}: one upstream fix → {n_products} "
          f"{'products' if source == 'audit' else 'issuers'}"
          + (f" → {totals['releases']} product releases" if source == "audit" else "")
          + f" → {total:,} {unit}")

    fig = _slide(
        f"One {software} fix, and how far it travels before everyone has it",
        f"{cve}  ·  {software}  ·  published {published}{kev_txt}  ·  {scope}",
    )
    ax = fig.add_axes([0.225, 0.115, 0.51, CONTENT_TOP - 0.115])
    _style_axes(ax)
    ax.grid(False, axis="y")
    ax.grid(True, axis="x", color=GRID, linestyle="--", linewidth=0.8, alpha=0.7)

    values = [r["value"] for r in rows]
    ys = np.arange(len(rows))
    colors = [m.C_GRAY if i == pooled_idx else m.C_RED for i in ys]
    ax.barh(ys, values, 0.72, color=colors, alpha=0.95, edgecolor=BG, linewidth=0.6, zorder=3)
    ax.set_yticks(ys)
    ax.set_yticklabels([r["label"] for r in rows], fontsize=F_LABEL - 0.5, fontweight="bold", color="#E0E0E0")
    ax.tick_params(axis="y", pad=8)
    x_max = max(values) * 1.02
    ax.set_xlim(0, x_max)
    ax.set_ylim(-0.6, len(rows) - 0.4)
    ax.set_xlabel(
        "rebuilt packages: distinct package × product release" if source == "audit"
        else "distinct downstream records referencing the CVE",
        fontsize=F_TICK, color=INK2,
    )
    # Count at the bar's end; what it consists of just after — or inside the bar
    # when it already reaches the margin. Both in white over a dark stroke, so
    # the note reads the same on the red bar and on the black background.
    for y, r in zip(ys, rows):
        ax.annotate(f"{r['value']:,}", xy=(r["value"], y), xytext=(5, 0), textcoords="offset points",
                    ha="left", va="center", fontsize=F_SMALL, fontweight="bold", color=INK, zorder=5)
        if not r["note"]:
            continue
        if r["value"] > 0.55 * x_max:
            note = ax.annotate(r["note"], xy=(r["value"], y), xytext=(-8, 0), textcoords="offset points",
                               ha="right", va="center", fontsize=8.5, color=INK, fontweight="bold", zorder=5)
        else:
            note = ax.annotate(r["note"], xy=(r["value"], y), xytext=(5 + 7.5 * len(f"{r['value']:,}") + 8, 0),
                               textcoords="offset points", ha="left", va="center", fontsize=8.5, color=INK, zorder=5)
        _stroke(note, lw=2.5)

    # The right margin is the ladder: how far the one fix travels. Each rung is a
    # count in the title ink with what it counts underneath, on one vertical
    # rule from the fix down to the rebuilt packages.
    if source == "audit":
        rungs = [("1", "upstream fix"), (f"{n_products}", "products"),
                 (f"{totals['releases']}", "product releases"), (f"{total:,}", unit)]
    else:
        rungs = [("1", "upstream fix"), (f"{n_products}", "issuers"), (f"{total:,}", unit)]
    x_rule, x_txt = 0.772, 0.787
    y_top, step = 0.775, 0.105
    y_last = y_top - step * (len(rungs) - 1)
    fig.add_artist(plt.Line2D([x_rule, x_rule], [y_last - 0.012, y_top + 0.012], transform=fig.transFigure,
                              color=INK3, linewidth=1.4, solid_capstyle="round", zorder=1))
    for i, (count, what) in enumerate(rungs):
        y = y_top - step * i
        last = i == len(rungs) - 1
        fig.add_artist(plt.Line2D([x_rule], [y], transform=fig.transFigure, marker="o",
                                  markersize=9 if last else 6, color=m.C_RED if last else INK3, zorder=2))
        fig.text(x_txt, y + 0.004, count, ha="left", va="bottom", fontsize=20 if last else 17,
                 fontweight="bold", color=INK)
        fig.text(x_txt, y - 0.006, what, ha="left", va="top", fontsize=F_LABEL, color=INK2)
    # What the number is not, in print, so the rest is credible; then the reading.
    y_note = y_last - 0.085
    fig.text(x_txt, y_note, textwrap.fill(
        f"The {total:,} {unit} are the ecosystem's rebuilds, not any one organisation's queue.", 36),
        ha="left", va="top", fontsize=F_SMALL, color=INK, style="italic", linespacing=1.35)
    who = f"{n_products} vendors" if source == "audit" else f"{n_products} issuers"
    fig.text(x_txt, y_note - 0.085, textwrap.fill(
        f"{who} rebuilding on {n_products} uncoordinated schedules: the CVE ID says nothing about "
        "when the fix arrives downstream.", 36),
        ha="left", va="top", fontsize=F_SMALL, color=INK2, linespacing=1.35)
    _save(fig, output_filename, "fan-out")


# ── 12. Exploitation signals vs publication volume ──────────────────────────

def _months_between(first, last):
    """Month-start dates from ``first`` ("YYYY-MM") to ``last`` inclusive."""
    cur = datetime.strptime(first, "%Y-%m").date()
    end = datetime.strptime(last, "%Y-%m").date()
    out = []
    while cur <= end:
        out.append(cur)
        cur = (cur + timedelta(days=32)).replace(day=1)
    return out


def _exploitation_series(stats, anchor_date, anchor_month_complete):
    """Complete months from ``EXPLOIT_START_MONTH``, their publication counts,
    and CISA KEV additions; ``None`` when the catalog is unavailable."""
    anchor = date.fromisoformat(anchor_date[:10])
    last = date(anchor.year, anchor.month, 1)
    if not anchor_month_complete:
        last = (last - timedelta(days=1)).replace(day=1)
    months = _months_between(m.EXPLOIT_START_MONTH, last.strftime("%Y-%m"))
    if len(months) < 3:
        return None
    keys = [mo.strftime("%Y-%m") for mo in months]
    pubs = [sum(stats.get(k[5:7], {}).get(k[:4], {}).values()) for k in keys]
    kev_all, kev_released = m.kev_additions_by_month()
    if not kev_all:
        print("CISA KEV catalog unavailable; exploitation slides skipped.")
        return None
    return {
        "months": months, "keys": keys, "pubs": pubs, "kev": [kev_all.get(k, 0) for k in keys],
        "kev_released": kev_released, "last": last,
        "x": [datetime(mo.year, mo.month, 15) for mo in months],
        "first_lbl": months[0].strftime("%b %Y"), "last_lbl": months[-1].strftime("%b %Y"),
    }


def _exploitation_xaxis(ax, d):
    ax.set_xlim(datetime(d["months"][0].year, d["months"][0].month, 1),
                datetime(d["last"].year, d["last"].month, 1) + timedelta(days=31))
    ax.xaxis.set_major_locator(mdates.MonthLocator(bymonth=(1, 4, 7, 10)))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %Y"))
    ax.tick_params(axis="x", labelsize=F_TICK - 1)


def slide_exploitation_vs_volume(stats, anchor_date, anchor_month_complete=False,
                                 output_filename=SLIDE_FILES["exploitation_vs_volume"]):
    """CVE publications per month on the left axis; CISA KEV additions on a
    right-hand raw axis with their whole range shaded as a corridor. The right
    axis is scaled so both series meet at the first month — the two lines start
    together, and then one climbs while the band just sits there."""
    d = _exploitation_series(stats, anchor_date, anchor_month_complete)
    if d is None:
        return
    x, pubs, kev = d["x"], d["pubs"], d["kev"]
    k_lo, k_hi = min(kev), max(kev)
    ratio_p = pubs[-1] / pubs[0] if pubs[0] else float("nan")
    ratio_k = kev[-1] / kev[0] if kev[0] else float("nan")

    fig = _slide(
        f"CVE publications ×{ratio_p:.1f}, CISA KEV additions ×{ratio_k:.1f} — and never outside {k_lo}–{k_hi} a month",
        f"{d['first_lbl']} → {d['last_lbl']}  ·  publications {pubs[0]:,} → {pubs[-1]:,} a month (left axis)  ·  "
        f"KEV additions {kev[0]} → {kev[-1]} a month, average {sum(kev) / len(kev):.0f} (right axis, scaled to meet "
        f"publications in {d['first_lbl']})",
    )
    ax = fig.add_axes([0.085, AXES_BOTTOM, 0.665, CONTENT_TOP - AXES_BOTTOM])
    _style_axes(ax)
    ax2 = ax.twinx()
    ax2.set_facecolor("none")
    for sp in ("top", "left", "bottom"):
        ax2.spines[sp].set_visible(False)
    ax2.spines["right"].set_color(m.C_YELLOW)
    ax2.tick_params(axis="y", colors=m.C_YELLOW, labelsize=F_TICK, length=0)

    p_top = max(pubs) * 1.12
    ax.set_ylim(0, p_top)
    # Right axis: the same height means the same multiple of the first month.
    ax2.set_ylim(0, p_top * kev[0] / pubs[0] if pubs[0] and kev[0] else max(kev) * 1.12)

    # The corridor first, so the lines sit on it.
    ax2.axhspan(k_lo, k_hi, color=m.C_YELLOW, alpha=0.12, zorder=1)
    for y in (k_lo, k_hi):
        ax2.axhline(y, color=m.C_YELLOW, linestyle=(0, (6, 4)), linewidth=1.0, alpha=0.6, zorder=1.5)
    t = ax2.text(x[-1], k_lo + 0.04 * (k_hi - k_lo), f"every month since {d['first_lbl']}: {k_lo}–{k_hi} KEV additions",
                 ha="right", va="bottom", fontsize=F_SMALL, color=m.C_YELLOW, style="italic", zorder=5)
    _stroke(t, 2.5)

    ax.plot(x, pubs, color=m.C_RED, linewidth=3.2, marker="o", markersize=3.5, zorder=4)
    ax2.plot(x, kev, color=m.C_YELLOW, linewidth=2.2, marker="o", markersize=3.5, zorder=4)

    _exploitation_xaxis(ax, d)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax.set_ylabel("CVE publications per month", fontsize=F_TICK, color=INK2)
    ax2.set_ylabel("CISA KEV additions per month", fontsize=F_TICK, color=m.C_YELLOW, labelpad=10)

    # Labels beyond the right axis, each on its own scale.
    _end_labels(ax, [{"y": pubs[-1], "color": m.C_RED, "main": "CVE publications",
                      "sub": f"{pubs[0]:,} → {pubs[-1]:,} a month"}], dx=0.085)
    _end_labels(ax2, [{"y": kev[-1], "color": m.C_YELLOW, "main": "CISA KEV additions",
                       "sub": f"{kev[0]} → {kev[-1]} a month, avg {sum(kev) / len(kev):.0f}"}], dx=0.085)
    _save(fig, output_filename, "exploitation vs volume")


def slide_exploitation_share(stats, anchor_date, anchor_month_complete=False,
                             output_filename=SLIDE_FILES["exploitation_share"]):
    """The one-number version: CISA KEV additions as a share of the month's CVE
    publications. No indexing, no second axis."""
    d = _exploitation_series(stats, anchor_date, anchor_month_complete)
    if d is None:
        return
    x, pubs, kev = d["x"], d["pubs"], d["kev"]
    share = [k / p * 100.0 if p else float("nan") for k, p in zip(kev, pubs)]
    avg = sum(v for v in share if v == v) / max(1, sum(1 for v in share if v == v))

    fig = _slide(
        f"CISA KEV additions as a share of monthly CVE publications: {share[0]:.2f}% → {share[-1]:.2f}%",
        f"{d['first_lbl']} → {d['last_lbl']}  ·  {kev[0]} of {pubs[0]:,} → {kev[-1]} of {pubs[-1]:,}  ·  "
        f"average {avg:.2f}% a month, {min(share):.2f}%–{max(share):.2f}%",
    )
    ax = fig.add_axes([0.085, AXES_BOTTOM, 0.715, CONTENT_TOP - AXES_BOTTOM])
    _style_axes(ax)
    ax.plot(x, share, color=m.C_YELLOW, linewidth=2.8, marker="o", markersize=4, zorder=4)
    ax.fill_between(x, share, color=m.C_YELLOW, alpha=0.10)
    ax.axhline(avg, color=INK3, linestyle=(0, (6, 4)), linewidth=1.1, alpha=0.8, zorder=2)
    ax.set_ylim(0, max(share) * 1.15)
    _exploitation_xaxis(ax, d)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.1f}%"))
    ax.set_ylabel("KEV additions ÷ CVE publications, per month", fontsize=F_TICK, color=INK2)
    _end_labels(ax, [
        {"y": share[-1], "color": m.C_YELLOW, "main": f"{share[-1]:.2f}%", "sub": f"{d['last_lbl']}: {kev[-1]} of {pubs[-1]:,}"},
        {"y": avg, "color": INK3, "main": f"{avg:.2f}%", "sub": "average month"},
    ])
    ax.annotate(f"{share[0]:.2f}%  ({kev[0]} of {pubs[0]:,})", xy=(x[0], share[0]), xytext=(8, 8),
                textcoords="offset points", ha="left", va="bottom", fontsize=F_SMALL, fontweight="bold", color=INK)
    _save(fig, output_filename, "exploitation share")


# ── 13. Kernel bug-fix discovery vs CVE publishing ──────────────────────────

def slide_kernel_fixes(daily_counts_kernel, anchor_date, output_filename=SLIDE_FILES["kernel_fixes"]):
    """Two bar panels on one release timeline: Fixes:-tagged kernel commits per
    release (hand-transcribed from LWN, see ``monthly.LWN_FIXES_SERIES``) above
    the CVEs the kernel's own CNA published during that release's development
    cycle (the day after the previous release through release day)."""
    window_start = m.KERNEL_FIXES_WINDOW_START
    dates, counts = m.daily_publication_series(daily_counts_kernel, window_start, anchor_date)
    if len(dates) < 60:
        return
    per_day = {d.date(): c for d, c in zip(dates, counts)}
    data_start = dates[0].date()
    cna_start = date.fromisoformat(m.KERNEL_CNA_START)

    releases = list(zip(m.LWN_FIXES_RELEASES, m.LWN_FIXES_SERIES[m.KERNEL_FIXES_SERIES]))
    rel = []
    for i in range(1, len(releases)):
        v, fixes = releases[i]
        prev_v = releases[i - 1][0]
        start = date.fromisoformat(m.LWN_FIXES_RELEASE_DATES[prev_v]) + timedelta(days=1)
        end = date.fromisoformat(m.LWN_FIXES_RELEASE_DATES[v])
        if start < data_start or end > date.fromisoformat(anchor_date[:10]):
            continue     # only cycles the archive's daily counts cover in full
        days = (end - start).days + 1
        cves = sum(per_day.get(start + timedelta(days=k), 0) for k in range(days))
        rel.append({"v": v, "fixes": fixes, "start": start, "end": end, "days": days, "cves": cves})
    if len(rel) < 3:
        return
    last = rel[-1]
    plateau = [r["fixes"] for r in rel[:-3]]
    plateau_avg = sum(plateau) / len(plateau)
    # The CVE plateau only over cycles the kernel CNA was active for.
    cna_rel = [r for r in rel[:-3] if r["start"] >= cna_start]
    if not cna_rel:
        return
    cve_base = [r["cves"] for r in cna_rel]
    cve_base_avg = sum(cve_base) / len(cve_base)
    breakout = rel[-3:]                     # the releases that left the plateau

    # A Fixes: tag names the commit that introduced the bug: each one is a bug
    # that had already shipped. That is the sentence the panel leads with.
    plateau_round = int(round(plateau_avg, -2))          # a plateau is a round number: "near 2,000", not "near 2,039"
    fig = _slide(
        f"Kernel {last['v']}: {last['fixes']:,} fixes to bugs already shipped — after {len(plateau)} releases near {plateau_round:,}",
        f"A Fixes: tag names the commit that introduced the bug, so every one is a bug that was already in the tree and running  ·  "
        f"plateau {plateau_avg:,.0f} a release over {len(plateau)} releases ({rel[0]['v']}–{rel[-4]['v']}), then "
        + " / ".join(f"{r['fixes']:,}" for r in breakout)
        + "  ·  bottom: CVEs the kernel CNA published in each release's cycle",
    )
    x0 = datetime.fromisoformat(window_start)
    x1 = datetime.combine(last["end"], datetime.min.time()) + timedelta(days=45)
    ax_top = fig.add_axes([0.085, 0.50, 0.685, CONTENT_TOP - 0.50])
    ax_bot = fig.add_axes([0.085, AXES_BOTTOM, 0.685, 0.50 - 0.045 - AXES_BOTTOM])
    for ax in (ax_top, ax_bot):
        _style_axes(ax)
        ax.grid(False, axis="x")
        ax.set_xlim(x0, x1)
        ax.xaxis.set_major_locator(mdates.MonthLocator(bymonth=(1, 7)))
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %Y"))
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax_top.tick_params(axis="x", labelbottom=False, length=0)
    ax_bot.tick_params(axis="x", labelsize=F_TICK - 1)

    xs = [datetime.combine(r["end"], datetime.min.time()) for r in rel]
    colors = [m.C_RED if r is last else m.C_BLUE for r in rel]

    def panel(ax, key, avg, ylabel, label_main, label_sub, plateau_note):
        ys = [r[key] for r in rel]
        ax.bar(xs, ys, width=26, color=colors, alpha=0.95, edgecolor=BG, linewidth=0.6, zorder=3)
        ax.axhline(avg, color=INK3, linestyle=(0, (6, 4)), linewidth=1.1, alpha=0.8, zorder=2)
        y_max = max(ys) * 1.28
        ax.set_ylim(0, y_max)
        ax.text(x0 + timedelta(days=12), y_max * 0.93, plateau_note, ha="left", va="top",
                fontsize=F_SMALL, color=INK3, style="italic")
        for i, (r, xx) in enumerate(zip(rel, xs)):
            if i >= len(rel) - 3:
                ax.annotate(f"{r[key]:,}", xy=(xx, r[key]), xytext=(0, 3), textcoords="offset points",
                            ha="center", va="bottom", fontsize=F_SMALL, fontweight="bold", color=INK, zorder=5)
            t = ax.annotate(r["v"], xy=(xx, 0), xytext=(0, 3), textcoords="offset points", ha="center", va="bottom",
                            fontsize=7.5, color=INK, fontweight="bold", zorder=5, rotation=90)
            _stroke(t, 1.8)
        ax.set_ylabel(ylabel, fontsize=F_TICK - 1, color=INK2)
        _end_labels(ax, [{"y": last[key], "color": m.C_RED, "main": label_main, "sub": label_sub}], min_gap=0.2)

    # Both 7.2 figures, each with its basis: the bar is the chart's polyline, the
    # article's prose counts more broadly. Quoting one over the other is fine once
    # the slide shows both.
    prose = m.LWN_FIXES_ARTICLE_72_COMMITS if last["v"] == "7.2" else None
    panel(
        ax_top, "fixes", plateau_avg, "Fixes: tags per release",
        f"{last['v']}: {last['fixes']:,} fixes",
        (f"chart value · LWN text: {prose:,}" if prose else f"released {last['end'].strftime('%b %-d, %Y')}"),
        f"- - -  plateau {plateau_avg:,.0f} a release ({min(plateau):,}–{max(plateau):,}), {len(plateau)} releases",
    )
    panel(
        ax_bot, "cves", cve_base_avg, "kernel CNA CVEs per release cycle",
        f"{last['v']} cycle: {last['cves']:,} CVEs", f"{last['start'].strftime('%b %-d')} – {last['end'].strftime('%b %-d')}, {last['days']} days",
        f"- - -  plateau {cve_base_avg:,.0f} a cycle ({min(cve_base):,}–{max(cve_base):,}), {cna_rel[0]['v']}–{cna_rel[-1]['v']}",
    )
    # The bottom panel's honest reading: the CVE side has moved in one release so
    # far; fixes lead, CVE assignment follows. Said as a prediction, not a multiple.
    lead_names = " and ".join(r["v"] for r in breakout[:-1])
    ax_bot.text(
        0.012, 0.74,
        f"Fixes lead, CVE assignment follows: {lead_names} stayed at the plateau, {last['v']} broke out.\n"
        f"If the lag holds, the next two cycles publish far more kernel CVEs. Check in December.",
        transform=ax_bot.transAxes, ha="left", va="top", fontsize=F_SMALL, color=INK2, style="italic", linespacing=1.4,
    )
    # Cycles before the kernel CNA existed have nothing to count.
    first_cna_x = datetime.combine(cna_rel[0]["start"], datetime.min.time())
    ax_bot.axvspan(x0, first_cna_x, color=INK3, alpha=0.08, zorder=1)
    ax_bot.text(0.012, 0.47, f"kernel CNA began assigning CVEs in {cna_start.strftime('%B %Y')}",
                transform=ax_bot.transAxes, ha="left", va="top", fontsize=F_SMALL, color=INK3, style="italic")

    # The top panel's numbers are LWN's, credited the way the footer credits
    # Vulners for the bottom. The plot's form is this dashboard's own; only the
    # per-release counts are cited, as facts.
    fig.text(
        0.77, 0.50 - 0.012,
        "Data Source: Fixes: tag counts per release from LWN.net, Jonathan Corbet, "
        "\u201cDevelopment statistics for the 7.2 kernel\u201d, 2026-08-17",
        ha="right", va="top", fontsize=F_FOOT, color=INK3, style="italic",
    )
    _save(fig, output_filename, "kernel fixes vs publishing")


# ── 14 & 15. EPSS: the recency penalty, and recall of exploited CVEs ────────

_epss_ctx_cache = {}


def _epss_context(epss_rows, anchor_date):
    """Resolve the EPSS feeds once for both slides: the anchor feed and its
    annual snapshots, the cohort-aging stats, and the per-year recall rows."""
    key = (anchor_date, len(epss_rows))
    if key in _epss_ctx_cache:
        return _epss_ctx_cache[key]
    data_dir = m._epss_data_dir()
    try:
        anchor_path = m.download_latest_epss_scores(data_dir)
    except Exception as e:  # noqa: BLE001
        print(f"EPSS slides skipped: {e}")
        _epss_ctx_cache[key] = None
        return None
    feed_date = m.epss_date_from_filename(anchor_path)
    snapshots = m.resolve_aging_snapshots(data_dir, feed_date, anchor_path)
    aging = m.calculate_cohort_aging_stats(m.cohort_aging_from_rows(epss_rows, snapshots), snapshots) \
        if len(snapshots) >= 2 else None
    anchor_year = int(anchor_date[:4])
    years = [str(y) for y in range(anchor_year - m.EPSS_RECALL_YEARS_BACK, anchor_year + 1)]
    epss_map = m.load_epss_scores_csv(anchor_path)
    kev_ids = m.load_cisa_kev_cves()          # the same catalog the exploitation slides use
    recall, cutoff_md = m.epss_recall_by_year(epss_rows, epss_map, anchor_date, years, exploited_ids=kev_ids or None)
    del epss_map
    ctx = {"feed_date": feed_date, "snapshots": snapshots, "aging": aging, "recall": recall, "cutoff_md": cutoff_md}
    _epss_ctx_cache[key] = ctx
    return ctx


def slide_epss_cohort_age(epss_rows, anchor_date, output_filename=SLIDE_FILES["epss_cohort_age"]):
    """The middle panel of cve_epss_comparison.py's recency dashboard as a
    slide: each annual EPSS snapshot's cohorts by age at scoring time."""
    ctx = _epss_context(epss_rows, anchor_date)
    if not ctx or not ctx["aging"]:
        return
    aging, snapshots = ctx["aging"], ctx["snapshots"]
    cells, drops = aging["cells"], aging["drops"]
    cutoff_pct = m.EPSS_HIGH_CUTOFF * 100

    lines = []
    for snap in snapshots:
        pts = sorted((c["age"], c["pct_ge_cutoff"]) for c in cells[snap["date"]].values() if c)
        if pts:
            lines.append({"snap": snap, "pts": pts, "drop": drops.get(snap["date"])})
    if not lines:
        return
    falls = [ln["drop"]["drop_pct"] for ln in lines if ln["drop"]]

    print("\n[epss_cohort_age] % of scored CVEs with EPSS >= 10%, by cohort age at scoring time")
    for ln in lines:
        snap = ln["snap"]
        print(f"  snapshot {snap['date']} ({snap['model_version'] or 'model n/a'}): "
              + ", ".join(f"age {a}: {p:.1f}%" for a, p in ln["pts"])
              + (f"  -> fall {ln['drop']['drop_pct']:.0f}%" if ln["drop"] else ""))

    fig = _slide(
        "EPSS scores every cohort lowest when it is new: all four snapshots, no exceptions",
        f"A property of the scoring, not of the bugs: re-indexed by age at scoring time, each annual snapshot falls "
        f"{min(falls):.0f}–{max(falls):.0f}% from its oldest cohort to its newest  ·  "
        f"% of scored CVEs with EPSS ≥ {cutoff_pct:.0f}%  ·  snapshots {', '.join(s['date'] for s in snapshots)}",
    )
    ax = fig.add_axes([0.085, AXES_BOTTOM, 0.70, CONTENT_TOP - AXES_BOTTOM])
    _style_axes(ax)
    labels = []
    for ln in lines:
        year = ln["snap"]["date"][:4]
        color = m.YEAR_COLORS.get(year, m.C_GRAY)
        xs, ys = zip(*ln["pts"])
        ax.plot(xs, ys, color=color, linewidth=2.8, marker="o", markersize=7, alpha=0.95, zorder=4)
        main = f"EPSS {year}"
        sub = (f"−{ln['drop']['drop_pct']:.0f}% oldest → newest" if ln["drop"] else "") \
            + (f" · {ln['snap']['model_version']}" if ln["snap"]["model_version"] else "")
        labels.append({"y": ys[0], "color": color, "main": main, "sub": sub})
    ages = sorted({a for ln in lines for a, _ in ln["pts"]})
    y_max = max(p for ln in lines for _, p in ln["pts"]) * 1.15
    ax.set_ylim(0, y_max)
    ax.set_xlim(max(ages) + 0.15, -0.15)          # oldest left, newest right
    ax.set_xticks(ages)
    ax.set_xticklabels([f"{a} yr{'s' if a != 1 else ''} old" if a else "same year" for a in ages], fontsize=F_TICK)
    ax.set_xlabel("cohort age when the snapshot scored it", fontsize=F_TICK, color=INK2)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.set_ylabel(f"CVEs with EPSS ≥ {cutoff_pct:.0f}%", fontsize=F_TICK, color=INK2)
    _end_labels(ax, labels, min_gap=0.105)
    _save(fig, output_filename, "EPSS cohort age")


def slide_epss_recall(epss_rows, anchor_date, output_filename=SLIDE_FILES["epss_recall"]):
    """The top panel of cve_epss_comparison.py's overlap chart, reduced to the
    figure that matters: the share of each year's exploited CVEs that EPSS
    flagged, with the exploited counts as context."""
    ctx = _epss_context(epss_rows, anchor_date)
    if not ctx or not ctx["recall"]:
        return
    rows = [r for r in ctx["recall"] if r["n_wild"] > 0]
    if len(rows) < 2:
        return
    cutoff_pct = m.EPSS_HIGH_CUTOFF * 100
    first, last = rows[0], rows[-1]
    cutoff = datetime.strptime(f"2000-{ctx['cutoff_md']}", "%Y-%m-%d").strftime("%b %-d")

    print(f"\n[epss_recall] same period Jan 1 – {cutoff}, EPSS feed {ctx['feed_date']}, threshold > {cutoff_pct:.0f}%, exploited = CISA KEV")
    for r in rows:
        print(f"  {r['year']}: in KEV {r['n_wild']:,}, EPSS-flagged {r['n_epss']:,}, both {r['both']:,}, "
              f"recall {r['recall']:.1f}%  (published {r['pop']:,})")

    # The claim the data supports: a band, not a trend, and the share of
    # known-exploited CVEs that still sit under the threshold.
    n_kev = sum(r["n_wild"] for r in rows)
    n_both = sum(r["both"] for r in rows)
    miss_pct = (1 - n_both / n_kev) * 100 if n_kev else 0.0
    lo, hi = min(r["recall"] for r in rows), max(r["recall"] for r in rows)
    fig = _slide(
        f"EPSS flags {lo:.0f}–{hi:.0f}% of CISA KEV CVEs; {miss_pct:.0f}% of known-exploited bugs score under {cutoff_pct:.0f}%",
        f"Caught = EPSS > {cutoff_pct:.0f}% in today's feed ({ctx['feed_date']})  ·  of each year's CVEs that are in the "
        f"CISA KEV catalog, published Jan 1 – {cutoff}  ·  {n_both} of {n_kev} across the four years, no clear trend",
    )
    ax = fig.add_axes([0.085, AXES_BOTTOM, 0.865, CONTENT_TOP - AXES_BOTTOM])
    _style_axes(ax)
    ax.grid(False, axis="x")
    xs = np.arange(len(rows))
    vals = [r["recall"] for r in rows]
    colors = [m.YEAR_COLORS.get(r["year"], m.C_GRAY) for r in rows]
    ax.bar(xs, vals, 0.58, color=colors, alpha=0.95, edgecolor=BG, linewidth=0.6, zorder=3)
    for x, r in zip(xs, rows):
        ax.annotate(f"{r['recall']:.0f}%", xy=(x, r["recall"]), xytext=(0, 30), textcoords="offset points",
                    ha="center", va="bottom", fontsize=F_TITLE - 2, fontweight="bold", color=INK, zorder=5)
        ax.annotate(f"{r['both']:,} of {r['n_wild']:,} in KEV", xy=(x, r["recall"]), xytext=(0, 8),
                    textcoords="offset points", ha="center", va="bottom", fontsize=F_LABEL + 1, fontweight="bold",
                    color=INK, zorder=5)
    ax.set_ylim(0, 100)
    ax.set_xlim(-0.6, len(rows) - 0.4)
    ax.set_xticks(xs)
    ax.set_xticklabels([r["year"] for r in rows], fontsize=F_TICK + 2, fontweight="bold")
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.set_ylabel("CISA KEV CVEs that EPSS flagged", fontsize=F_TICK, color=INK2)
    ax.axhline(50, color=INK3, linestyle=(0, (6, 4)), linewidth=1.0, alpha=0.6, zorder=2)
    ax.text(len(rows) - 0.42, 51, "half of them", ha="right", va="bottom", fontsize=F_SMALL, color=INK3, style="italic")
    _save(fig, output_filename, "EPSS recall")


# ── Driver ──────────────────────────────────────────────────────────────────

_RENDERERS = [
    ("yearly_cumulative", slide_yearly_cumulative),
    ("ytd_growth", slide_ytd_growth),
    ("sankey_flow", slide_sankey_flow),
    ("incomplete_month", slide_incomplete_month),
    ("projections", slide_projections),
    ("status_yearly", slide_status_yearly),
    # The web chart stacks both weekly views in one tall picture; a slide gets one each.
    ("status_weekly", slide_status_weekly_absolute),
    ("status_weekly", slide_status_weekly_normalized),
    ("candidate_track", slide_candidate_track),
    ("fanin_chrome", slide_fanin_chrome),
    ("fanin_chrome", slide_fanin_chrome_estate),      # reads the CSV the line above writes
    ("fanout_downstream", slide_fanout_downstream),
    ("exploitation_vs_volume", slide_exploitation_vs_volume),
    ("exploitation_vs_volume", slide_exploitation_share),
    ("kernel_fixes", slide_kernel_fixes),
    ("epss", slide_epss_cohort_age),
    ("epss", slide_epss_recall),
]


def render_all(inputs):
    """Draw every slide whose inputs ``monthly._run_monthly`` collected.

    A slide is an extra, so one failing must not take the report or the web
    charts down with it: the error is printed and the rest still render.
    """
    for key, fn in _RENDERERS:
        kwargs = inputs.get(key)
        if kwargs is None:
            continue
        try:
            fn(**kwargs)
        except Exception:  # noqa: BLE001
            print(f"Slide '{key}' failed; skipping:\n{traceback.format_exc()}")
