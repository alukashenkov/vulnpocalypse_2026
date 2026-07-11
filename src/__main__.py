"""Entry point: `python -m src`.

Downloads the Vulners archive once, runs every registered dashboard against it,
builds the static site into ``SITE_DIR``, then leaves the archive for the caller
(the workflow) to discard. Nothing is committed.
"""
import os
import shutil
import traceback

from .common import (
    build_site,
    download_archive_once,
    get_site_dir,
    load_local_env,
)
from .registry import DASHBOARDS


def main():
    load_local_env()

    site_dir = get_site_dir()
    if os.path.isdir(site_dir):
        shutil.rmtree(site_dir)
    os.makedirs(site_dir, exist_ok=True)

    archive_path = download_archive_once()

    results = []
    for dashboard in DASHBOARDS:
        name = getattr(dashboard, "slug", dashboard.__class__.__name__)
        try:
            print(f"\n=== Generating dashboard: {name} ===")
            result = dashboard.generate(archive_path, site_dir)
            if result is not None:
                results.append(result)
        except Exception:  # noqa: BLE001 - isolate one dashboard's failure
            print(f"Dashboard '{name}' failed; skipping:\n{traceback.format_exc()}")

    if not results:
        raise SystemExit("No dashboards produced output; aborting.")

    build_site(results, site_dir)
    print(f"\nSite ready in {site_dir}")


if __name__ == "__main__":
    main()
