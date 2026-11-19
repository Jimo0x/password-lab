"""Password Lab — serveur Flask."""
import json
import os
import subprocess
import threading

from flask import Flask, jsonify, request, send_from_directory

import lab as L

HERE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder="static", static_url_path="")
LAB = L.Lab()
_rates: dict = {}
_lock = threading.Lock()


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.post("/api/analyze")
def analyze():
    pw = (request.get_json() or {}).get("password", "")
    return jsonify(L.analyze_password(pw[:128]))


@app.post("/api/compare")
def compare():
    pw = (request.get_json() or {}).get("password", "")[:128] or "motdepasse"
    with _lock:
        if not _rates:
            for a in L.ALGOS:
                _rates[a] = L.time_hash(a, budget=0.4 if a in ("pbkdf2", "scrypt") else 0.15)
    a = L.analyze_password(pw)
    out = []
    for algo, label in L.ALGOS.items():
        h1, h2 = L.hash_pw(algo, pw), L.hash_pw(algo, pw)
        out.append({"algo": algo, "label": label, "hash": h1, "same_twice": h1 == h2, "cpu_rate": round(_rates[algo], 1),
                    "gpu_rate": L.GPU_RATES[algo], "crack_seconds": a["crack_seconds"][algo]})
    return jsonify({"analysis": a, "algos": out})


@app.get("/api/bench")
def bench():
    exe = os.path.join(HERE, "bench", "hashbench")
    if os.path.exists(exe):
        try:
            return jsonify(json.loads(subprocess.run([exe, "300"], capture_output=True, text=True, timeout=30).stdout))
        except Exception as e:  # pragma: no cover
            print("bench C :", e)
    res = [{"algo": a, "per_sec": round(L.time_hash(a, budget=0.3))} for a in ("md5", "sha1", "sha256")]
    res.append({"algo": "pbkdf2_sha256_600k", "per_sec": round(L.time_hash("pbkdf2", budget=0.6), 2)})
    return jsonify({"engine": "Python hashlib (compilez bench/ pour la version C)", "results": res})


@app.get("/api/lab")
def lab_state():
    return jsonify({"users": LAB.table(), "algos": L.ALGOS})


@app.post("/api/lab/users")
def lab_add():
    d = request.get_json() or {}
    try:
        LAB.add(d.get("name") or f"user{len(LAB.users) + 1}", d.get("password") or "", d.get("algo", "md5"))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return lab_state()


@app.post("/api/lab/demo")
def lab_demo():
    LAB.users.clear()
    people = [("alice", "soleil"), ("bob", "Marseille13"), ("chloe", "azerty123"), ("david", "Ch0c0lat!"), ("emma", "soleil"),
              ("farid", "pikachu-tournevis-violon-47")]
    algo = (request.get_json() or {}).get("algo", "md5")
    for n, p in people:
        LAB.add(n, p, algo)
    return lab_state()


@app.post("/api/lab/reset")
def lab_reset():
    LAB.users.clear()
    return lab_state()


@app.post("/api/lab/attack")
def lab_attack():
    budget = min(30.0, float((request.get_json() or {}).get("budget", 8)))
    return jsonify(L.attack(LAB, time_budget=budget))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5011))
    print(f"Password Lab → http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, threaded=True)
