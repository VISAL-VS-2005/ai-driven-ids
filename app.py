"""IDS Alert Dashboard - Flask backend.

- Converts alert_fast.txt -> data/alerts.json + data/summary.json (converter.py)
- Streams new alerts to the browser live over Server-Sent Events
- Replay mode re-streams historical alerts for live showcase
- Generates PDF attack reports via OpenRouter free models (report.py)

Run:  python3 app.py   (or .venv/bin/python app.py)
"""

import json
import os
import queue
import re
import threading
import time

from flask import (Flask, Response, jsonify, render_template, request,
                   send_from_directory)
from dotenv import load_dotenv

import converter
import report as report_gen

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))
ALERT_FILE = os.environ.get("ALERT_FILE") or os.path.join(BASE_DIR, "alert_fast.txt")
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORT_DIR = os.path.join(DATA_DIR, "reports")
STATIC_DIR = os.path.join(BASE_DIR, "static")

LOG_EXTS = (".txt", ".log", ".fast", ".alert")
LOG_DENY = {"requirements.txt"}
LOG_SUBDIRS = ("logs", "log", "snort")

# Extra directories scanned for log files (set in .env), e.g.:
#   LOG_DIRS=/var/log/snort
_raw_dirs = os.environ.get("LOG_DIRS", "")
LOG_DIRS = [os.path.abspath(os.path.expanduser(d.strip()))
            for d in re.split(r"[:,]", _raw_dirs) if d.strip()]


class LogSwitchError(Exception):
    """Raised when the active log cannot be loaded (permissions etc.)."""

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------

class State:
    def __init__(self):
        self.lock = threading.RLock()
        self.log_file = ALERT_FILE          # absolute path of active log
        self.log_name = os.path.basename(ALERT_FILE)
        self.events = []
        self.summary = {}
        self.parse_errors = 0
        self.offset = 0
        self.partial = ""
        self.mode = "live"          # 'live' | 'replay'
        self.replay_speed = 8.0     # events per second
        self.replay_gen = 0
        self.replay_progress = {"index": 0, "total": 0, "active": False}
        self.subscribers = set()
        self.last_summary_write = 0.0
        self.dirty_summary = False
        self.file_size = 0
        self.tail_error = None      # last tail/read error (None = healthy)

    # ---- pub/sub --------------------------------------------------------
    def subscribe(self):
        q = queue.Queue(maxsize=500)
        with self.lock:
            self.subscribers.add(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            self.subscribers.discard(q)

    def emit(self, event, data):
        with self.lock:
            subs = list(self.subscribers)
        for q in subs:
            try:
                q.put_nowait({"event": event, "data": data})
            except queue.Full:
                try:
                    q.get_nowait()
                    q.put_nowait({"event": event, "data": data})
                except (queue.Empty, queue.Full):
                    pass

    # ---- data -----------------------------------------------------------
    def add_events(self, new_events):
        if not new_events:
            return
        with self.lock:
            self.events.extend(new_events)
            self.dirty_summary = True

    def rebuild_summary(self, force=False):
        with self.lock:
            if not self.dirty_summary and not force:
                return None
            self.dirty_summary = False
            events = list(self.events)
            source = self.log_file
        summary = converter.build_summary(events, source)
        with self.lock:
            self.summary = summary
        self._write_json(summary)
        return summary

    def _write_json(self, summary):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(os.path.join(DATA_DIR, "summary.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(summary, fh, indent=2)
            with self.lock:
                events = list(self.events)
                log_name = self.log_name
            with open(os.path.join(DATA_DIR, "alerts.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({
                    "source_file": log_name,
                    "generated_at": summary.get("generated_at"),
                    "count": len(events),
                    "events": events,
                }, fh, indent=2)
        except OSError as exc:
            app.logger.warning("could not write JSON outputs: %s", exc)


state = State()


# --------------------------------------------------------------------------
# file tail + replay workers
# --------------------------------------------------------------------------

def _set_tail_error(msg):
    """Record/propagate tail errors so the UI can show them (no silent fails)."""
    with state.lock:
        if state.tail_error == msg:
            return
        state.tail_error = msg
    state.emit("status", {"tail_error": msg})
    if msg:
        print(f"[tail-error] {msg}")


def tail_worker():
    """Follow the active log file and push newly appended alerts via SSE."""
    while True:
        try:
            with state.lock:
                path = state.log_file
                name = state.log_name
            if not os.path.exists(path):
                _set_tail_error(f"{name}: file not found")
                time.sleep(1)
                continue
            size = os.path.getsize(path)
            with state.lock:
                if state.log_file != path:          # switched meanwhile
                    continue
                if size < state.offset:             # truncated / rotated
                    state.offset = 0
                    state.partial = ""
                offset = state.offset
                partial = state.partial

            if size == offset:
                _set_tail_error(None)               # healthy again
                time.sleep(0.4)
                # flush summary writes (debounced)
                if state.dirty_summary and time.time() - state.last_summary_write > 2:
                    state.last_summary_write = time.time()
                    summary = state.rebuild_summary()
                    if summary:
                        state.emit("summary", summary)
                continue

            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(offset)
                chunk = fh.read()
                new_offset = fh.tell()
            _set_tail_error(None)

            data = partial + chunk
            lines = data.split("\n")
            new_partial = lines.pop() if not data.endswith("\n") else ""

            new_events = []
            with state.lock:
                line_no = len(state.events) + 1
            for line in lines:
                if not line.strip():
                    continue
                ev, err = converter.parse_line(line, line_no)
                if ev:
                    new_events.append(ev)
                    line_no += 1
                elif err is not None:
                    with state.lock:
                        state.parse_errors += 1

            with state.lock:
                if state.log_file != path:          # switched while reading
                    continue
                state.offset = new_offset
                state.partial = new_partial

            if new_events:
                state.add_events(new_events)
                if state.mode == "live":
                    for ev in new_events:
                        state.emit("alert", ev)
                state.last_summary_write = time.time()
                summary = state.rebuild_summary()
                if summary:
                    state.emit("summary", summary)
        except PermissionError as exc:
            _set_tail_error(f"{name}: permission denied — grant read access "
                            f"(e.g. sudo setfacl -m u:{os.getenv('USER','youruser')}:r \"{path}\")")
            time.sleep(3)
        except OSError as exc:
            _set_tail_error(f"{name}: {exc.strerror or exc}")
            time.sleep(2)
        except Exception as exc:                     # noqa: BLE001
            _set_tail_error(f"{name}: {exc}")
            time.sleep(2)


def replay_worker(gen, speed):
    """Re-stream historical alerts for live showcase."""
    with state.lock:
        snapshot = list(state.events)
    total = len(snapshot)
    state.emit("mode", {"mode": "replay", "total": total, "speed": speed})
    state.replay_progress = {"index": 0, "total": total, "active": True}
    delay = 1.0 / max(speed, 0.2)
    i = 0
    for ev in snapshot:
        if state.replay_gen != gen or state.mode != "replay":
            break
        state.emit("alert", dict(ev, replay=True))
        i += 1
        state.replay_progress = {"index": i, "total": total, "active": True}
        time.sleep(delay)
    active = state.replay_gen == gen and state.mode == "replay"
    state.replay_progress = {"index": i, "total": total, "active": active}
    state.emit("replay_done", {"indexed": i, "total": total, "active": active})


# --------------------------------------------------------------------------
# startup
# --------------------------------------------------------------------------

def bootstrap():
    with state.lock:
        path = state.log_file
    try:
        events, errors = converter.parse_file(path) if os.path.exists(path) else ([], [])
        offset = os.path.getsize(path) if os.path.exists(path) else 0
        _set_tail_error(None)
    except OSError as exc:
        events, errors = [], []
        offset = 0
        _set_tail_error(f"{state.log_name}: {exc.strerror or exc}")
    with state.lock:
        state.events = events
        state.parse_errors = len(errors)
        state.offset = offset
        state.dirty_summary = True
    summary = state.rebuild_summary(force=True)
    print(f"[bootstrap] {state.log_name}: {len(events)} alerts loaded, summary written")
    threading.Thread(target=tail_worker, daemon=True, name="tail").start()


# --------------------------------------------------------------------------
# log file listing + switching
# --------------------------------------------------------------------------

def list_log_files():
    """Project logs (*.txt/*.log + known subdirs) + extra dirs from LOG_DIRS."""
    out = []

    def add(path, display):
        try:
            st = os.stat(path)
        except OSError:
            return
        out.append({"name": display, "path": path, "size": st.st_size,
                    "modified": st.st_mtime,
                    "readable": os.access(path, os.R_OK)})

    def scan_project(directory, prefix=""):
        if not os.path.isdir(directory):
            return
        for name in sorted(os.listdir(directory)):
            if name.startswith(".") or name in LOG_DENY:
                continue
            path = os.path.join(directory, name)
            if os.path.isdir(path):
                if not prefix and name in LOG_SUBDIRS:
                    scan_project(path, prefix=name + "/")
                continue
            if not name.lower().endswith(LOG_EXTS):
                continue
            add(path, prefix + name)

    def scan_external(directory):
        """Snort dirs: any regular file (alert has no extension)."""
        try:
            entries = sorted(os.listdir(directory))
        except OSError:
            return
        for name in entries:
            if name.startswith("."):
                continue
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                add(path, path)                      # display full path

    scan_project(BASE_DIR)
    for d in LOG_DIRS:
        scan_external(d)
    return out


def switch_log(path, name):
    """Swap the active log: re-parse fully, push new state over SSE.

    Parses BEFORE mutating state so a failed switch (permissions, missing
    file) leaves the previous log active and raises LogSwitchError.
    """
    try:
        events, errors = converter.parse_file(path)
        size = os.path.getsize(path)
    except OSError as exc:
        raise LogSwitchError(
            f"cannot read {name}: {exc.strerror or exc}. "
            f"Grant read access, e.g.: sudo setfacl -m u:{os.getenv('USER', 'youruser')}:r \"{path}\""
        ) from exc

    with state.lock:
        state.replay_gen += 1                      # cancel any running replay
        state.log_file = path
        state.log_name = name
        state.offset = size
        state.partial = ""
        state.events = events
        state.parse_errors = len(errors)
        state.replay_progress = {"index": 0, "total": 0, "active": False}
        state.dirty_summary = True
        state.tail_error = None

    summary = state.rebuild_summary(force=True)
    state.emit("logfile", {"file": name, "total": len(events),
                           "parse_errors": len(errors)})
    state.emit("mode", {"mode": state.mode, "total": len(events),
                        "replay_progress": state.replay_progress})
    state.emit("summary", summary)
    state.emit("status", {"tail_error": None})
    print(f"[switch] now parsing {name}: {len(events)} alerts")
    return {"file": name, "total": len(events), "parse_errors": len(errors)}


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/meta")
def api_meta():
    with state.lock:
        return jsonify({
            "source_file": state.log_name,
            "total": len(state.events),
            "mode": state.mode,
            "replay_speed": state.replay_speed,
            "replay_progress": state.replay_progress,
            "parse_errors": state.parse_errors,
            "file_size": os.path.getsize(state.log_file) if os.path.exists(state.log_file) else 0,
            "tail_error": state.tail_error,
            "log_dirs": LOG_DIRS,
            "has_api_key": bool(os.environ.get("OPENROUTER_API_KEY")),
        })


@app.route("/api/logs")
def api_logs():
    files = list_log_files()
    with state.lock:
        active = state.log_name
    for f in files:
        f["active"] = f["name"] == active
        f.pop("path", None)
    return jsonify({"files": files, "active": active})


@app.route("/api/log", methods=["POST"])
def api_switch_log():
    body = request.get_json(silent=True) or {}
    name = (body.get("file") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "file name required"}), 400
    match = next((f for f in list_log_files() if f["name"] == name), None)
    if not match:
        return jsonify({"ok": False, "error": f"log file not found: {name}"}), 404
    try:
        result = switch_log(match["path"], match["name"])
    except LogSwitchError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 403
    return jsonify({"ok": True, **result})


@app.route("/api/alerts")
def api_alerts():
    limit = min(int(request.args.get("limit", 200)), 5000)
    offset = max(int(request.args.get("offset", 0)), 0)
    search = (request.args.get("search") or "").strip().lower()
    category = request.args.get("category") or ""
    severity = request.args.get("severity") or ""
    sid = request.args.get("sid") or ""
    order = request.args.get("order", "desc")

    with state.lock:
        events = list(state.events)

    if search:
        events = [e for e in events
                  if search in e["raw"].lower()
                  or search in e["signature"].lower()
                  or search in e["src_ip"] or search in e["dst_ip"]]
    if category:
        events = [e for e in events if e["category"] == category]
    if severity:
        events = [e for e in events if e["severity"] == severity]
    if sid:
        events = [e for e in events if str(e["sid"]) == sid]

    total = len(events)
    if order == "asc":
        page = events[offset:offset + limit]
    else:
        page = list(reversed(events))[offset:offset + limit]
    return jsonify({"total": total, "count": len(page), "events": page})


@app.route("/api/summary")
def api_summary():
    with state.lock:
        source = state.log_file
    summary = state.summary or converter.build_summary([], source)
    return jsonify(summary)


@app.route("/api/models")
def api_models():
    return jsonify({"models": report_gen.FREE_MODELS,
                    "default": report_gen.DEFAULT_MODEL})


@app.route("/api/mode", methods=["POST"])
def api_mode():
    body = request.get_json(silent=True) or {}
    mode = body.get("mode")
    if mode not in ("live", "replay"):
        return jsonify({"ok": False, "error": "mode must be live|replay"}), 400
    speed = body.get("speed")
    with state.lock:
        if speed:
            try:
                state.replay_speed = min(max(float(speed), 0.5), 60)
            except (TypeError, ValueError):
                pass
        state.mode = mode
        if mode == "replay":
            state.replay_gen += 1
            gen = state.replay_gen
            speed_v = state.replay_speed
        else:
            state.replay_gen += 1          # cancel any running replay
            gen = None
            speed_v = None
    if mode == "replay":
        threading.Thread(target=replay_worker, args=(gen, speed_v),
                         daemon=True, name="replay").start()
    else:
        state.emit("mode", {"mode": "live"})
    return jsonify({"ok": True, "mode": mode,
                    "speed": state.replay_speed})


@app.route("/api/report", methods=["POST"])
def api_report():
    body = request.get_json(silent=True) or {}
    api_key = (body.get("api_key") or os.environ.get("OPENROUTER_API_KEY") or "").strip()
    model = (body.get("model") or "").strip() or None

    with state.lock:
        summary = state.summary
        source = state.log_file
    if not summary:
        summary = converter.build_summary(state.events, source)

    try:
        pdf_path, meta = report_gen.generate_report(
            summary, REPORT_DIR, api_key=api_key or None, model=model)
    except Exception as exc:                       # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 500

    filename = os.path.basename(pdf_path)
    meta.pop("pdf", None)
    return jsonify({"ok": True, "filename": filename,
                    "url": f"/api/reports/{filename}", "meta": meta,
                    "size_bytes": os.path.getsize(pdf_path)})


@app.route("/api/reports")
def api_reports():
    os.makedirs(REPORT_DIR, exist_ok=True)
    files = []
    for name in sorted(os.listdir(REPORT_DIR), reverse=True):
        if name.endswith(".pdf"):
            p = os.path.join(REPORT_DIR, name)
            files.append({"filename": name, "url": f"/api/reports/{name}",
                          "size_bytes": os.path.getsize(p),
                          "modified": os.path.getmtime(p)})
    return jsonify({"reports": files})


@app.route("/api/reports/<path:name>")
def api_report_file(name):
    return send_from_directory(REPORT_DIR, name, as_attachment=True)


@app.route("/api/download/<name>")
def api_download(name):
    if name not in ("alerts.json", "summary.json"):
        return jsonify({"ok": False, "error": "not found"}), 404
    return send_from_directory(DATA_DIR, name, as_attachment=True)


@app.route("/api/stream")
def api_stream():
    q = state.subscribe()

    def gen():
        try:
            yield ": connected\n\n"
            with state.lock:
                snapshot = {"mode": state.mode,
                            "total": len(state.events),
                            "replay_progress": state.replay_progress,
                            "tail_error": state.tail_error}
            yield f"event: mode\ndata: {json.dumps(snapshot)}\n\n"
            if snapshot.get("tail_error"):
                yield (f"event: status\ndata: "
                       f"{json.dumps({'tail_error': snapshot['tail_error']})}\n\n")
            while True:
                try:
                    item = q.get(timeout=15)
                    yield (f"event: {item['event']}\n"
                           f"data: {json.dumps(item['data'])}\n\n")
                except queue.Empty:
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            state.unsubscribe(q)
            return
    return Response(gen(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    })


def main():
    bootstrap()
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    print(f"[app] IDS dashboard on http://{host}:{port}")
    app.run(host=host, port=port, threaded=True, debug=False,
            use_reloader=False)


if __name__ == "__main__":
    main()
