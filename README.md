# Vulnerability Dashboard

A local, CSV-driven vulnerability management dashboard built with Python, Flask, HTML, CSS, and JavaScript.

The application has no database and does not connect to external systems. Place the latest standard vulnerability CSV in `data/`, then use the dashboard or Import Report button to generate the processed dataset and cached statistics used by the UI.

## Quick Setup for a New Clone

Use these steps after cloning the repository. The `data/` and `output/` folders are ignored by Git, so each developer must create them locally.

### Prerequisites

- Python 3.10 or later
- `pip`
- A standard vulnerability report CSV with the required columns listed in this README

### Setup and Run

#### Copy-Paste Setup Prompt

If you want an AI assistant or teammate to set up the project, use this prompt:

```text
Set up this Python Flask vulnerability dashboard so it is ready to run locally. Create a virtual environment, install Flask and all other dependencies from requirements.txt .

```

#### Manual Setup Commands

From the cloned project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The `python -m pip install -r requirements.txt` command installs Flask, pandas, and the test dependency `dukpy`.

Copy the vulnerability report CSV into `data/`, preferably as:

```text
data/vulnerability_report.csv
```

Then start the dashboard:

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:5000/
```

If PowerShell blocks virtual environment activation, run this once in the same terminal and activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Project Flow

```text
Latest standard CSV in data/
    |
    v
services/vulnerability_service.py detects the newest CSV
    |
    v
services/csv_loader.py validates exact standard columns
    |
    v
models/vulnerability.py stores each finding
    |
    v
utils calculate dates, vulnerability age, severity, status, and SLA values
    |
    v
output/processed_vulnerabilities.csv is written
    |
    v
output/dashboard_stats.json caches dashboard statistics
    |
    v
app.py passes cached JSON to templates/dashboard.html
    |
    v
Browser JavaScript renders KPIs, charts, filters, tables, and export files
```

### Request flow

1. Start Flask with `py app.py`.
2. Flask calls `get_dashboard_data()` for the dashboard page and API route.
3. The service scans `data/` for the most recently modified `*.csv` file.
4. If the file has not changed, Flask serves cached statistics from `output/dashboard_stats.json`.
5. If a new file is detected, or the user clicks Import Report, the CSV loader validates the exact standard columns.
6. The CSV loader reads each row, removes exact duplicates, and handles missing values.
7. Each row becomes a `Vulnerability` object.
8. Vulnerability age (`LastDetected` minus `FirstDetected`), SLA due dates, overdue status, and breach status are calculated from the record data and current date.
9. The processed dataset is saved to `output/processed_vulnerabilities.csv`.
10. The service calculates aggregate statistics once and saves them to `output/dashboard_stats.json`.
11. The template embeds the cached JSON in the page.
12. Browser JavaScript renders the dashboard. Dropdowns and search filter the loaded processed records in memory.
13. The Export report button creates a CSV containing only the currently selected filters and search results.

## Folder Structure

```text
Vuln management/
|
|-- app.py
|-- requirements.txt
|-- README.md
|-- test.py
|
|-- data/
|   `-- vulnerability_report.csv.csv
|
|-- output/
|   |-- dashboard_stats.json
|   |-- import_manifest.json
|   `-- processed_vulnerabilities.csv
|
|-- models/
|   |-- __init__.py
|   `-- vulnerability.py
|
|-- services/
|   |-- __init__.py
|   |-- csv_loader.py
|   `-- vulnerability_service.py
|
|-- utils/
|   |-- __init__.py
|   |-- date_utils.py
|   |-- dependant_team.py
|   `-- calculation_utils.py
|
|-- templates/
|   `-- dashboard.html
|
`-- static/
    |-- dependant_team_mapping.json
    |-- css/
    |   `-- dashboard.css
    `-- js/
        |-- charts.js
        |-- dashboard.js
        |-- filters.js
        |-- avs-core.js
        |-- avs.js
        |-- assistant-engine.js
        `-- assistant.js
```

## File Responsibilities

### `app.py`

The Flask application entry point.

- Defines the Flask application.
- Calls the service layer to load cached dashboard data.
- Serves the HTML page at `/`.
- Serves processed JSON at `/api/dashboard`.
- Provides `/api/import` for manually triggering the latest-file import.
- Shows a friendly error state when the CSV is missing or malformed.

### `requirements.txt`

Lists the Python dependencies:

- `Flask` for the local web server and routes.
- `pandas` for CSV/data processing.
- `dukpy` for unit testing the browser-side JavaScript (test-only).

### `test.py`

A small standalone Python example created before the dashboard. It is not used by the dashboard and can be ignored or replaced with automated tests later.

### `models/vulnerability.py`

Defines the `Vulnerability` data model.

It stores normalized fields such as server, environment, AppSpace, severity, status, CVE, vendor, dependant team, PCI state, dates, SLA results, and aging information. Its `to_dict()` method prepares a record for JSON and frontend use.

The file also defines the supported standard severity values:

- Critical
- High
- Medium
- Low

And status values:

- Open
- In Progress
- Resolved
- Closed

### `services/csv_loader.py`

Reads the CSV and creates `Vulnerability` objects.

Responsibilities:

- Opens the CSV with UTF-8 BOM support.
- Validates that a header row exists.
- Validates required standard columns using their exact names.
- Converts missing and `N/A` values into safe defaults.
- Parses dates, numbers, and boolean values.
- Removes exact duplicate rows.
- Normalizes severity and status values.
- Calculates vulnerability age (`LastDetected` minus `FirstDetected`, in days), aging bucket, SLA due date, overdue state, and breach state.
- Resolves `DependantTeam` from the `Detection` value using the keyword rules in `static/dependant_team_mapping.json`.
- Returns records plus metadata such as skipped duplicates, invalid dates, and original columns.

The required standard input columns are `ServerName`, `OperatingSystem`, `Environment`, `AppSpaceId`, `AppSpaceName`, `AppSpaceTeam`, `QID`, `VulnerabilityName`, `Severity`, `AssetRiskScore`, `PCIRequired`, `Category`, `CVE`, `VendorReference`, `FirstDetected`, `LastDetected`, `Resolved`, `SIABreach`, and `Status`.

The latest CSV remains in `data/`. Older CSV files in `data/` are moved to `archive/` after a successful import.

### `services/vulnerability_service.py`

Contains dashboard aggregation logic.

It also detects the latest input CSV, writes `output/processed_vulnerabilities.csv`, writes cached dashboard statistics to `output/dashboard_stats.json`, stores import state in `output/import_manifest.json`, and archives superseded input files.

It calculates:

- KPI totals
- Severity distribution
- Severity versus status
- Severity versus SLA
- Aging distribution
- Aging by severity and status
- Environment metrics
- DependantTeam counts
- AppSpace risk matrix data
- Top vulnerable servers
- Top CVEs
- Top QIDs
- Critical vulnerability records
- PCI metrics
- Filter option lists

This keeps business calculations out of the Flask routes and HTML template.

### `utils/date_utils.py`

Provides safe parsing helpers:

- `parse_date()` accepts several common date formats and ISO dates.
- `parse_number()` converts numeric text while handling commas and missing values.
- `parse_bool()` converts common yes/no, true/false, required, and breached values.

Invalid values return safe empty results instead of crashing the application.

### `utils/dependant_team.py`

Resolves the `DependantTeam` value for each finding.

- Loads the keyword rules from `static/dependant_team_mapping.json`.
- Matches the raw `Detection` value against every keyword, case-insensitively.
- Uses the longest matching keyword when several rules match, so the most specific rule wins.
- Returns `Other` when the detection is empty or matches no rule.

### `static/dependant_team_mapping.json`

Holds every `Detection` keyword to `DependantTeam` rule as a flat JSON object, for example `"/apps/ctm": "Control-M"` and `"splunk": "AppHealth"`. Edit this file to change the mapping; no code change is needed.

### `utils/calculation_utils.py`

Contains reusable business rules.

SLA durations:

| Severity | SLA |
| --- | ---: |
| Critical | 7 days |
| High | 30 days |
| Medium | 60 days |
| Low | 90 days |

It also:

- Normalizes severity values such as `Sev1` and `P1`.
- Normalizes status values such as `Fixed` and `Remediated`.
- Assigns aging buckets from the vulnerability age.
- Calculates SLA due date, breach state, overdue state, days remaining, and days overdue.
- Uses the resolution date for resolved and closed findings when available.

### `templates/dashboard.html`

The main server-rendered dashboard page.

It defines the page structure for:

- Header and report status
- Filter toolbar
- KPI cards
- Severity, SLA, and aging charts
- Environment and server analysis
- AppSpace matrix
- Critical vulnerability table
- CVE, QID, and PCI sections
- Searchable and paginated vulnerability register

It receives JSON generated by Python and loads the frontend JavaScript modules.

### `static/css/dashboard.css`

Defines the dashboard visual system.

It contains:

- Enterprise security dashboard colors
- KPI card styles
- Responsive grid layouts
- Severity and status badges
- Tables and heatmap cells
- Responsive mobile behavior
- Modern filter labels and dropdown controls
- Hover and keyboard focus states for accessibility

### `static/js/charts.js`

Contains lightweight local canvas chart helpers.

It renders:

- Donut chart for severity distribution
- Grouped bar charts for status and SLA
- Horizontal bar charts for aging and vulnerable servers

No external chart service or backend connection is used.

### `static/js/filters.js`

Builds the filter controls from the option lists returned by Python.

It:

- Creates labeled dropdowns.
- Adds environment, severity, status, dependant team, AppSpace, team, operating system, and category options.
- Escapes option text before inserting it into the page.
- Returns the selected filter values to the main dashboard script.

### `static/js/dashboard.js`

Controls browser-side dashboard behavior.

It:

- Filters records based on dropdown selections and search text.
- Recalculates the visible KPIs and chart inputs.
- Renders the AppSpace matrix, critical table, ranking lists, and vulnerability register.
- Handles pagination.
- Handles Reset filters.
- Creates the filtered CSV download when Export report is clicked.
- Starts the AI assistant widget and supplies it with the records currently in scope.

### `static/js/avs-core.js`

Holds the browser-side AVS (Application Vulnerability Score) calculation, mirroring `avs_calculator.py`.

It:

- Defines the zone and asset rating constants and the Low / Medium / High thresholds.
- Computes per-AppSpace scores from a record set, deduplicating by CVE (or vendor reference when no CVE exists).
- Contains no DOM access, so both `avs.js` and the assistant reuse the same numbers.

### `static/js/assistant-engine.js`

Contains the rule-based AI assistant logic. No external AI service is used.

It:

- Defines the predefined questions (report summary, Critical vulnerabilities, top 10 vulnerable AppSpaces, applications with High AVS, SLA breach summary, top remediation actions, and the AVS score explanation).
- Matches free-text questions to a handler using keyword scoring, and falls back to the suggested-question list when nothing matches.
- Builds structured answers (summary, stat chips, ranked items, notes) from the records passed in, so answers always reflect the active filters and search text.
- Adds a scope line to every answer describing which filters produced it.

### `static/js/assistant.js`

Renders the floating assistant widget and wires up the DOM.

It:

- Opens and closes the popup chat panel from the floating button, the close button, or the Escape key.
- Renders the suggested-question chips and the chat message log.
- Sends questions from the input box or the Send button to the assistant engine.
- Keeps chat history in memory for the session only and escapes all rendered text.

## CSV Location

Place the report in the preferred location:

```text
data/vulnerability_report.csv
```

The application also searches these fallback paths:

```text
vulnerability_report.csv
data/vulnerability_report.csv.csv
vulnerability_report.csv.csv
```

The current project report is named:

```text
data/vulnerability_report.csv.csv
```

## Run the Dashboard

From the project directory:

```powershell
cd "C:\Project\Vuln management"
py -m pip install -r requirements.txt
py app.py
```

Open the dashboard at:

```text
http://127.0.0.1:5000/
```

The processed data endpoint is:

```text
http://127.0.0.1:5000/api/dashboard
```

Stop the server with `Ctrl+C`.

## Using the Dashboard

1. Use the dropdowns in the dark filter toolbar to select environment, severity, status, dependant team, AppSpace, team, operating system, or category.
2. Use the search box to find a server, QID, CVE, or vulnerability name.
3. All KPI cards, charts, matrix rows, critical findings, ranking lists, and table rows update to the current scope.
4. Use Reset filters to return to the full report.
5. Use Export report to download the current filtered and searched records as a CSV file.
6. Use the table pagination controls to move through the findings without rendering all rows at once.
7. Use the assistant button in the bottom-right corner to ask questions about the findings currently in scope. Pick a suggested question or type your own. Chat history lasts for the browser session only.

## Error Handling

If the report is missing or invalid:

- The page still loads.
- The dashboard displays a clear report-not-loaded message.
- The API returns an error response with an explanation.
- No fake statistics are generated.

## Verification

Useful checks from the project directory:

```powershell
py -m compileall app.py models services utils
py -c "from app import app; client=app.test_client(); response=client.get('/'); print(response.status_code)"
py -c "from app import get_dashboard_data; data,error=get_dashboard_data(); print(data['meta']['record_count'], error)"
```

## Tests

Run the unit tests from the project directory:

```powershell
py -m unittest discover -s tests
```

The suite covers the AVS calculator, the import workflow, the age calculation, the `Detection` to `DependantTeam` mapping, the DependantTeam dashboard filter, and the browser-side AI assistant. The JavaScript tests execute the real files in `static/js` with the `dukpy` engine and a small DOM stub, so no Node.js install is required.

The report currently loads dynamically from the CSV. With the provided report, the API should return the actual number of parsed records and the filter option lists derived from those records.
