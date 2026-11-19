import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import lab as L
from app import app

def test_strength_levels():
    assert L.analyze_password("azerty123")["level"] == 0
    assert L.analyze_password("M@rs3ille13")["level"] <= 1
    assert L.analyze_password("Xk9#mP2$vL8qR!wZ")["level"] == 4

def test_salt_and_verify():
    for a in L.ALGOS:
        h = L.hash_pw(a, "secret"); assert L.verify(a, "secret", h) and not L.verify(a, "Secret", h)
    assert L.hash_pw("md5", "x") == L.hash_pw("md5", "x") and L.hash_pw("sha256_salt", "x") != L.hash_pw("sha256_salt", "x")

def test_attack_md5_vs_salted():
    lab = L.Lab()
    for n, p in [("a", "soleil"), ("b", "Marseille13"), ("c", "pikachu-tournevis-violon-47")]: lab.add(n, p, "md5")
    r = L.attack(lab, 5); assert set(r["found"]) == {"a", "b"}

def test_api():
    c = app.test_client(); c.post("/api/lab/demo", json={"algo": "md5"})
    assert any(u["same_hash_as"] for u in c.get("/api/lab").json["users"])
    assert c.post("/api/lab/users", json={"name": "x", "password": "y", "algo": "rot13"}).status_code == 400
