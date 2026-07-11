"""The list of dashboards the site is built from.

Add a dashboard by importing its class and appending an instance here — the
orchestrator and site builder pick it up automatically.
"""
from .dashboards.monthly import MonthlyDashboard

DASHBOARDS = [
    MonthlyDashboard(),
    # EpssDashboard(),   # planned next
]
