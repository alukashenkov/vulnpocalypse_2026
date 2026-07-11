# Vulnpocalypse 2026 Statistics Dashboard

A free, self-updating dashboard of CVE / vulnerability statistics, built from the
[Vulners](https://vulners.com) CVE archive and published to GitHub Pages.

**🔗 Live site:** _enable GitHub Pages (see below), then your dashboard is at_
`https://<your-username>.github.io/<repo>/`

The site rebuilds itself **every day at 07:00 UTC** via GitHub Actions: it downloads
the current CVE collection once, regenerates every dashboard's charts and tables, and
deploys the result to Pages. Nothing is stored in the repository — the multi-GB raw
archive is downloaded, used, and discarded on each run, and only the live site is
updated (there are no daily commits).

## Dashboards

- **Monthly CVE statistics by CNA** — year-over-year publication counts per CVE
  Numbering Authority, YTD growth, the yearly cumulative curve, per-CNA cumulative
  contribution, a full-year projection from the observed monthly trend, and Sankey
  flows of how output moves month to month.

Full data tables for each dashboard are on the site's **Data Tables** page.

## Run it yourself

You only need a free **Vulners API key** ([get one from your Vulners
account](https://vulners.com)). Then:

1. **Fork** this repository (it must be **public** for free Actions minutes and Pages).
2. **Settings → Pages → Build and deployment → Source: _GitHub Actions_.**
3. **Settings → Secrets and variables → Actions → New repository secret:** add
   `VULNERS_API_KEY` with your key.
4. Open the **Actions** tab, enable workflows, and run **“Build & deploy CVE
   dashboard”** once (it also runs automatically every day at 07:00 UTC).

That's it — your fork builds and publishes its own copy. No servers, no domain, no
paid hosting. Your API key stays a secret and is never written to the site.

## How it works

- All code lives in the [`src/`](src/) package. `python -m src` downloads the CVE
  archive once, runs every dashboard in [`src/registry.py`](src/registry.py) against
  it, and builds `index.html` + `tables.html` + charts into a temporary directory.
- The workflow [`.github/workflows/daily.yml`](.github/workflows/daily.yml) uploads
  that directory as a Pages artifact and deploys it — no commit, no `contents: write`.
- Configuration comes entirely from environment variables (`VULNERS_API_KEY`,
  `DATA_DIR`, `SITE_DIR`); there is no config file to edit.

### Adding a dashboard

Add one module under [`src/dashboards/`](src/dashboards/) that implements
`generate(archive_path, out_dir) -> DashboardResult`, then append an instance to
`DASHBOARDS` in [`src/registry.py`](src/registry.py). It automatically gets its own
section on the charts page and the data-tables page — no other changes needed.

## Local development

```bash
pip install -r requirements.txt
export VULNERS_API_KEY=...        # or put it in a local .env (python-dotenv optional)
SITE_DIR=./site python -m src     # writes the site into ./site; open ./site/index.html
```

The archive is cached in `DATA_DIR` (defaults to the current directory) and reused if
it was already downloaded today.

## License

[MIT](LICENSE).
