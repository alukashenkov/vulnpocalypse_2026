"""Dashboard contract shared by every dashboard module.

A dashboard is any object with a ``name`` and a ``generate(archive_path, out_dir)``
method that writes its chart PNGs into ``out_dir`` and returns a :class:`DashboardResult`.
The orchestrator (``src.__main__``) runs every registered dashboard against a single
downloaded archive and builds the site from the returned results.
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class DashboardResult:
    """What a dashboard hands back to the site builder.

    Attributes:
        slug: short id used for anchors / filenames (e.g. ``"monthly"``).
        title: human heading shown on the page.
        blurb: short prose describing what the dashboard shows and how to read it
            (rendered as the "wording" on the index page).
        charts: chart image paths, in display order. Each is a filename that lives
            inside ``out_dir`` (referenced by basename from the HTML).
        report_text: the dashboard's aligned-table report as a plain string, shown
            verbatim in a ``<pre>`` block on the tables page. For the monthly
            dashboard this is the same content the old console report produced.
    """

    slug: str
    title: str
    blurb: str
    charts: List[str] = field(default_factory=list)
    report_text: str = ""


class Dashboard:
    """Base class documenting the interface. Subclasses set ``slug``/``title`` and
    implement :meth:`generate`."""

    slug: str = ""
    title: str = ""

    def generate(self, archive_path: str, out_dir: str) -> DashboardResult:
        raise NotImplementedError
