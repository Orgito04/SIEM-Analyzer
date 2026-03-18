#!/usr/bin/env python3
"""
SIEM Web Dashboard — Flask app
Provides a real-time web UI for uploading logs and viewing results.
"""

import os
import sys
import json
import threading
from pathlib import Path
from datetime import datetime
from werkzeug.utils import secure_filename

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
from core.engine import SIEMEngine
from core.models import Severity

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB max upload
app.config["UPLOAD_FOLDER"] = "uploads"

Path("uploads").mkdir(exist_ok=True)
Path("reports").mkdir(exist_ok=True)

# Global state (in production, use Redis / DB)
_state = {
    "engine":    None,
    "manager":   None,
    "analyzing": False,
    "error":     None,
    "files":     [],
}


def _allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in {
        ".log", ".txt", ".json", ".xml", ".evtx", ".csv"
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "files" not in request.files:
        return jsonify({"error": "No files provided"}), 400

    files = request.files.getlist("files")
    saved = []

    for f in files:
        if f and f.filename and _allowed_file(f.filename):
            fname = secure_filename(f.filename)
            fpath = os.path.join(app.config["UPLOAD_FOLDER"], fname)
            f.save(fpath)
            saved.append(fpath)

    if not saved:
        return jsonify({"error": "No valid log files uploaded"}), 400

    _state["files"] = saved
    _state["engine"]  = None
    _state["manager"] = None
    _state["error"]   = None

    return jsonify({"ok": True, "files": [Path(p).name for p in saved]})


@app.route("/analyze", methods=["POST"])
def analyze():
    if not _state["files"]:
        return jsonify({"error": "No files loaded"}), 400
    if _state["analyzing"]:
        return jsonify({"error": "Analysis already running"}), 409

    parser_hint = request.json.get("parser") if request.is_json else None

    def _run():
        _state["analyzing"] = True
        _state["error"]     = None
        try:
            engine = SIEMEngine(output_dir="reports")
            for fpath in _state["files"]:
                try:
                    engine.load_file(fpath, parser=parser_hint)
                except Exception as e:
                    pass  # skip unreadable files silently
            manager = engine.analyze()
            _state["engine"]  = engine
            _state["manager"] = manager
        except Exception as e:
            _state["error"] = str(e)
        finally:
            _state["analyzing"] = False

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return jsonify({"ok": True, "message": "Analysis started"})


@app.route("/status")
def status():
    return jsonify({
        "analyzing": _state["analyzing"],
        "ready":     _state["manager"] is not None,
        "error":     _state["error"],
        "files":     [Path(p).name for p in _state["files"]],
    })


@app.route("/results")
def results():
    m = _state["manager"]
    if not m:
        return jsonify({"error": "No results yet"}), 404

    e = _state["engine"]
    summary = m.summary()
    summary["event_count"] = e.event_count if e else 0
    summary["sources"]     = [Path(p).name for p in (e.sources if e else [])]

    return jsonify({
        "summary":       summary,
        "alerts":        [a.to_dict() for a in m.alerts[:200]],
        "top_attackers": m.top_attackers(10),
        "timeline":      m.timeline(),
        "mitre":         m.mitre_coverage(),
    })


@app.route("/export/<fmt>")
def export_report(fmt: str):
    m = _state["manager"]
    if not m:
        return jsonify({"error": "No results"}), 404

    if fmt == "json":
        path = m.export_json()
        return send_file(path, as_attachment=True, download_name=path.name)
    elif fmt == "csv":
        path = m.export_csv()
        return send_file(path, as_attachment=True, download_name=path.name)
    else:
        return jsonify({"error": "Unknown format"}), 400


@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.now().isoformat()})


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--debug", action="store_true")
    a = p.parse_args()
    print(f"  SIEM Dashboard → http://{a.host}:{a.port}")
    app.run(host=a.host, port=a.port, debug=a.debug)
