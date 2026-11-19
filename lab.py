"""Password Lab — logique pédagogique : hachage, robustesse, attaque par dictionnaire sur des comptes de laboratoire.

L'attaque ne vise que les comptes fictifs créés dans le laboratoire : aucune
empreinte externe ne peut être soumise.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import itertools
import math
import os
import re
import secrets
import time
from dataclasses import dataclass, field

# Débits approximatifs d'une RTX 4090 (benchmarks publics hashcat), en hachages par seconde.
GPU_RATES = {"md5": 164e9, "sha1": 51e9, "sha256": 22e9, "sha512": 7.5e9,
             "md5_salt": 164e9, "sha256_salt": 22e9, "pbkdf2": 14.6e3, "scrypt": 7.1e3, "bcrypt": 184e3 / 2 ** 7}

COMMON = """123456 password 123456789 12345678 12345 qwerty azerty 1234567 111111 123123 abc123 password1 1234 iloveyou 000000 qwerty123
motdepasse soleil doudou loulou marseille chouchou nicolas camille julien thomas bonjour coucou football 1234567890 dragon monkey
letmein princesse superman jordan sunshine master welcome shadow ashley baseball michael trustno1 batman passw0rd hello freedom
whatever qazwsx charlie donald admin root toor test pokemon naruto chocolat amour vivelavie loveyou maman papa juliette
""".split()
WORDS = COMMON + """paris lyon lille nantes toulouse bordeaux france epitech ete hiver printemps automne chat chien lapin tigre lion
noel vacances plage soleil lune etoile musique guitare piano tennis rugby basket mario zelda minecraft fortnite""".split()
KEYBOARD = ["azertyuiop", "qsdfghjklm", "wxcvbn", "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
LEET = str.maketrans({"4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "0": "o", "5": "s", "$": "s", "7": "t"})

ALGOS = {
    "md5": "MD5 sans sel", "sha1": "SHA-1 sans sel", "sha256": "SHA-256 sans sel", "sha256_salt": "SHA-256 salé",
    "pbkdf2": "PBKDF2-SHA256 (600 000 itérations)", "scrypt": "scrypt (N=2¹⁴, r=8)",
}


def hash_pw(algo: str, pw: str, salt: bytes | None = None) -> str:
    b = pw.encode()
    if algo in ("md5", "sha1", "sha256", "sha512"):
        return hashlib.new(algo, b).hexdigest()
    salt = salt or secrets.token_bytes(16)
    s = base64.b64encode(salt).decode()
    if algo == "sha256_salt":
        return f"{s}${hashlib.sha256(salt + b).hexdigest()}"
    if algo == "pbkdf2":
        return f"{s}${hashlib.pbkdf2_hmac('sha256', b, salt, 600_000).hex()}"
    if algo == "scrypt":
        return f"{s}${hashlib.scrypt(b, salt=salt, n=2 ** 14, r=8, p=1).hex()}"
    raise ValueError(algo)


def verify(algo: str, pw: str, stored: str) -> bool:
    if "$" not in stored:
        return hmac.compare_digest(hash_pw(algo, pw), stored)
    s, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_pw(algo, pw, base64.b64decode(s)), stored)


def time_hash(algo: str, pw: str = "motdepasse", budget: float = 0.25) -> float:
    """Hachages par seconde mesurés sur cette machine (CPU, un cœur)."""
    n, t0 = 0, time.perf_counter()
    while time.perf_counter() - t0 < budget or n == 0:
        hash_pw(algo, pw + str(n), b"0123456789abcdef")
        n += 1
    return n / (time.perf_counter() - t0)


# ─────────────────────────── robustesse ───────────────────────────
def analyze_password(pw: str) -> dict:
    low = pw.lower()
    pool = sum([26 if re.search(r"[a-z]", pw) else 0, 26 if re.search(r"[A-Z]", pw) else 0,
                10 if re.search(r"\d", pw) else 0, 33 if re.search(r"[^a-zA-Z0-9]", pw) else 0])
    naive = len(pw) * math.log2(pool) if pool else 0
    patterns, guesses = [], 2 ** naive
    core, suffix = re.match(r"^(.*?)([\d!?.@#$%*_+-]*)$", low).groups()
    base = core.translate(LEET)
    if low in COMMON:
        patterns.append("fait partie des mots de passe les plus utilisés au monde")
        guesses = COMMON.index(low) + 1
    elif base in WORDS:
        patterns.append(f"basé sur le mot du dictionnaire « {base} »" + (" avec substitutions leet (4→a, 3→e…)" if core != base else ""))
        digits, symbols = len(re.sub(r"\D", "", suffix)), len(re.sub(r"[\d]", "", suffix))
        suf_space = 130 if re.fullmatch(r"(19|20)\d{2}", suffix[:4]) and digits == 4 else 10 ** digits
        guesses = (WORDS.index(base) + 1) * (2 if pw[:1].isupper() else 1) * (16 if core != base else 1) * suf_space * (33 ** symbols) * 4
        if suffix:
            patterns.append(f"suffixe prévisible « {suffix} » ajouté à la fin")
    words = [w for w in re.split(r"[\s_.\-]+", low) if w]
    if len(words) >= 3 and sum(w.isalpha() for w in words) >= 3:
        n = sum(w.isalpha() for w in words)
        patterns.append(f"phrase de passe de {n} mots (≈ 12,9 bits par mot tiré au hasard dans 7 776)")
        guesses = min(guesses, 7776 ** n * 10 ** len(re.sub(r"\D", "", pw)))
    if re.search(r"(19|20)\d{2}", pw) or re.search(r"\d{2}[/.-]\d{2}[/.-]\d{2,4}", pw):
        patterns.append("contient une année ou une date")
    for row in KEYBOARD:
        if any(row[i:i + 4] in low for i in range(len(row) - 3)):
            patterns.append("suite de touches du clavier")
            guesses = min(guesses, 2 ** (naive * 0.45))
            break
    if re.search(r"(.)\1{2,}", pw):
        patterns.append("caractères répétés")
        guesses = min(guesses, 2 ** (naive * 0.6))
    if re.fullmatch(r"\d+", pw):
        patterns.append("uniquement des chiffres")
    bits = max(0.0, math.log2(max(guesses, 1)))
    if len(pw) >= 4 and len(set(pw)) <= 2:
        bits = min(bits, 8)
    crack = {a: guesses / 2 / r for a, r in GPU_RATES.items()}
    level = 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4
    return {"length": len(pw), "pool": pool, "naive_bits": round(naive, 1), "bits": round(bits, 1), "level": level,
            "label": ["Catastrophique", "Faible", "Moyen", "Solide", "Excellent"][level], "patterns": patterns, "crack_seconds": crack}


# ─────────────────────────── laboratoire d'attaque ───────────────────────────
@dataclass
class LabUser:
    name: str
    algo: str
    stored: str
    password: str  # conservé uniquement pour la démonstration pédagogique (comptes fictifs)


@dataclass
class Lab:
    users: list[LabUser] = field(default_factory=list)

    def add(self, name: str, pw: str, algo: str) -> LabUser:
        if algo not in ALGOS:
            raise ValueError("algorithme inconnu")
        if len(self.users) >= 30:
            raise ValueError("30 comptes maximum dans le laboratoire")
        u = LabUser(name[:30], algo, hash_pw(algo, pw), pw)
        self.users.append(u)
        return u

    def table(self) -> list[dict]:
        same = {}
        for u in self.users:
            same.setdefault(u.stored, []).append(u.name)
        return [{"name": u.name, "algo": u.algo, "algo_label": ALGOS[u.algo], "stored": u.stored,
                 "same_hash_as": [n for n in same[u.stored] if n != u.name]} for u in self.users]


def candidates(max_n: int = 200_000):
    """Dictionnaire + règles de mutation classiques (majuscule, leet, suffixes numériques, symboles)."""
    seen = set()
    sub = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"})
    for w in WORDS:
        for v in (w, w.capitalize(), w.upper(), w.translate(sub), w.capitalize().translate(sub)):
            for suf in itertools.chain([""], [str(i) for i in range(100)], [str(y) for y in range(1950, 2031)], ["!", "?", "123", "123!", "*"]):
                c = v + suf
                if c not in seen:
                    seen.add(c)
                    yield c
                    if len(seen) >= max_n:
                        return


def attack(lab: Lab, time_budget: float = 20.0, progress=None) -> dict:
    """Attaque par dictionnaire sur les comptes du laboratoire, avec un budget de temps par algorithme."""
    found, stats = {}, {}
    by_algo: dict[str, list[LabUser]] = {}
    for u in lab.users:
        by_algo.setdefault(u.algo, []).append(u)
    for algo, users in by_algo.items():
        t0, tried = time.perf_counter(), 0
        remaining = {id(u): u for u in users}
        unsalted = "$" not in users[0].stored
        for cand in candidates():
            if not remaining or time.perf_counter() - t0 > time_budget:
                break
            tried += 1
            if unsalted:  # un seul calcul teste tous les comptes à la fois : c'est tout l'intérêt du sel
                h = hash_pw(algo, cand)
                hits = [u for u in users if u.stored == h and id(u) in remaining]
            else:
                hits = [u for u in list(remaining.values()) if verify(algo, cand, u.stored)]
                tried += len(remaining) - 1
            for u in hits:
                found[u.name] = {"password": cand, "after": round(time.perf_counter() - t0, 3), "tries": tried}
                remaining.pop(id(u), None)
            if progress and tried % 500 == 0:
                progress(algo, tried, len(found))
        el = time.perf_counter() - t0
        stats[algo] = {"tried": tried, "seconds": round(el, 3), "rate": round(tried / el if el else 0), "cracked": len(users) - len(remaining),
                       "total": len(users), "timeout": bool(remaining) and el > time_budget}
    return {"found": found, "stats": stats}
