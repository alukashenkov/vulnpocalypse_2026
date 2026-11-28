"""Worker helpers for parallel Matplotlib chart and slide rendering.

Each worker process imports ``monthly`` (and ``monthly_slides`` when needed)
once in its initializer, configures the exact same module flags and working
directory as the parent run, executes independent chart/slide tasks, and
returns captured stdout + ``saved_files_log`` entries so the parent replays
output in deterministic order.
"""
import io
import os
import traceback
from contextlib import redirect_stdout

_MODS = {}


def init_render_worker(state):
    """Initialize module state once per worker process."""
    out_dir = state["out_dir"]
    if out_dir:
        os.chdir(out_dir)

    from src.dashboards import monthly

    monthly._LOCAL = state["local"]
    monthly._WRITE_CSV = state["write_csv"]
    monthly._SLIDES = state["slides"]
    monthly._SANKEY_MONTH_ORDER = state["sankey_month_order"]
    monthly._DATA_THROUGH = state["data_through"]
    monthly.CUT_OFF_DATE = state["cut_off_date"]
    _MODS["monthly"] = monthly

    if state.get("load_slides"):
        from src.dashboards import monthly_slides

        _MODS["monthly_slides"] = monthly_slides


def run_render_batch(calls):
    """Execute a sequence of ``(mod_name, fn_name, args, kwargs, isolate)`` calls.

    ``isolate=True`` (used for slides) catches exceptions and records the exact
    slide failure message without aborting remaining calls in the batch.
    ``isolate=False`` (used for web charts) returns the exception traceback so
    the parent re-raises it.
    """
    monthly = _MODS["monthly"]
    buf = io.StringIO()
    log_start = len(monthly.saved_files_log)
    fatal_tb = None

    with redirect_stdout(buf):
        for mod_name, fn_name, args, kwargs, isolate, label in calls:
            mod = _MODS.get(mod_name)
            if mod is None:
                from src.dashboards import monthly_slides

                mod = monthly_slides
                _MODS[mod_name] = mod
            fn = getattr(mod, fn_name)
            if isolate:
                try:
                    fn(*args, **kwargs)
                except Exception:  # noqa: BLE001
                    print(f"Slide '{label}' failed; skipping:\n{traceback.format_exc()}")
            else:
                try:
                    fn(*args, **kwargs)
                except Exception:  # noqa: BLE001
                    fatal_tb = traceback.format_exc()
                    break

    new_logs = monthly.saved_files_log[log_start:]
    return buf.getvalue(), new_logs, fatal_tb
