# Assets

Place the **Vulners square logo** here as:

    vulners_logo.png

Requirements:
- Square (equal width/height) with a **transparent background** (PNG, RGBA).
- Reasonable resolution (e.g. 256–512 px square); it is scaled down at render time.

It is overlaid on every chart in the **bottom-left** corner at 7% of the figure
width. If it reads too big or small, tune `_LOGO_WIDTH_FRAC` in
`src/dashboards/monthly.py`. If the file is absent, charts simply render without
it (a one-time note is printed).
