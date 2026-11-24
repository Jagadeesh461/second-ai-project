import json
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, abort, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

import avs_calculator
import services.vulnerability_service as vulnerability_service
from services.vulnerability_service import import_avs_list, latest_input_file, load_cached_dashboard, process_latest_report, save_uploaded_report


BASE_DIR = Path(__file__).resolve().parent
ARCHIVE_DIR = BASE_DIR / "archive"
app = Flask(__name__)


def _timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def get_dashboard_data():
    try:
        return load_cached_dashboard(), None
    except (FileNotFoundError, ValueError, OSError) as error:
        return {"meta": {"record_count": 0}, "kpis": {}, "filters": {}, "charts": {}, "records": [], "critical_records": [], "most_risky_records": [], "app_matrix": [], "top_servers": [], "top_cves": [], "top_qids": [], "avs": {"applications": [], "totals": {"total": 0, "low": 0, "medium": 0, "high": 0}}}, str(error)


@app.get("/")
@app.get("/<any(overview, risky, movement, avs, tables):tab>")
def dashboard(tab=None):
    data, error = get_dashboard_data()
    return render_template("dashboard.html", dashboard_json=json.dumps(data), load_error=error)


@app.get("/api/dashboard")
def dashboard_api():
    data, error = get_dashboard_data()
    response = jsonify({"data": data, "error": error})
    if error:
        response.status_code = 503
    return response


@app.post("/api/import")
def import_report():
    try:
        result = process_latest_report(force=True)
    except (FileNotFoundError, ValueError, OSError) as error:
        response = jsonify({"ok": False, "error": str(error)})
        response.status_code = 400
        return response
    dashboard_data = result.pop("dashboard", {})
    return jsonify({"ok": True, **result, "record_count": dashboard_data.get("meta", {}).get("record_count", 0)})


@app.post("/api/import/upload")
def import_uploaded_report():
    upload = request.files.get("report")
    if not upload or not upload.filename:
        abort(400, description="No vulnerability report file selected")
    try:
        result = save_uploaded_report(upload.stream, secure_filename(upload.filename))
    except (ValueError, OSError) as error:
        response = jsonify({"ok": False, "error": str(error)})
        response.status_code = 400
        return response
    dashboard_data = result.pop("dashboard", {})
    return jsonify({"ok": True, **result, "record_count": dashboard_data.get("meta", {}).get("record_count", 0)})


@app.get("/api/avs/export")
def export_avs_list():
    mapping_path = avs_calculator.STATIC_MAPPING_PATH
    if not mapping_path.exists():
        abort(404, description="AVS List file not found")
    filename = f"avs_list_{_timestamp()}.csv"
    return send_file(mapping_path, mimetype="text/csv", as_attachment=True, download_name=filename)


@app.post("/api/avs/import/upload")
def import_uploaded_avs_list():
    upload = request.files.get("avs_list")
    if not upload or not upload.filename:
        abort(400, description="No AVS List file selected")
    try:
        result = import_avs_list(upload.stream, secure_filename(upload.filename))
    except (ValueError, OSError) as error:
        response = jsonify({"ok": False, "error": str(error)})
        response.status_code = 400
        return response
    dashboard_data = result.pop("dashboard", {})
    return jsonify({"ok": True, **result, "dashboard": dashboard_data})


@app.post("/api/import/portal")
def import_from_portal():
    return jsonify({"ok": True, "message": "Portal Integration Coming Soon."})


@app.post("/api/export/filtered")
def export_filtered_report():
    payload = request.get_json(silent=True) or {}
    csv_text = payload.get("csv", "")
    if not isinstance(csv_text, str) or not csv_text.strip():
        abort(400, description="No CSV content provided")
    requested_name = secure_filename(payload.get("filename") or "")
    filename = requested_name if requested_name.lower().endswith(".csv") else f"filtered_report_{_timestamp()}.csv"
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    (ARCHIVE_DIR / filename).write_text(csv_text, encoding="utf-8")
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/export/raw")
def export_raw_report():
    source = latest_input_file()
    if not source.exists():
        abort(404, description="Raw input report not found")
    filename = f"raw_input_report_{_timestamp()}.csv"
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    (ARCHIVE_DIR / filename).write_bytes(source.read_bytes())
    return send_file(source, mimetype="text/csv", as_attachment=True, download_name=filename)


@app.get("/api/export/output")
def export_processed_output():
    output_path = vulnerability_service.PROCESSED_REPORT_PATH
    if not output_path.exists():
        abort(404, description="Processed output file not found")
    return send_file(output_path, mimetype="text/csv", as_attachment=True, download_name=output_path.name)


@app.get("/api/archive")
def list_archive():
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(
        (
            {
                "name": item.name,
                "size_kb": round(item.stat().st_size / 1024, 1),
                "modified": datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
            for item in ARCHIVE_DIR.iterdir()
            if item.is_file()
        ),
        key=lambda entry: entry["modified"],
        reverse=True,
    )
    return jsonify({"files": files})


@app.get("/api/archive/download/<path:filename>")
def download_archive_file(filename):
    safe_name = secure_filename(filename)
    if not safe_name:
        abort(404)
    target = (ARCHIVE_DIR / safe_name).resolve()
    if target.parent != ARCHIVE_DIR.resolve() or not target.is_file():
        abort(404)
    return send_file(target, as_attachment=True, download_name=safe_name)


@app.delete("/api/archive/<path:filename>")
def delete_archive_file(filename):
    safe_name = secure_filename(filename)
    if not safe_name:
        abort(404)
    target = (ARCHIVE_DIR / safe_name).resolve()
    if target.parent != ARCHIVE_DIR.resolve() or not target.is_file():
        abort(404)
    target.unlink()
    return jsonify({"deleted": safe_name})


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)