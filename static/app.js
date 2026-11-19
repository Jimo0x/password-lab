const LVL_COL = ["#e5172f", "#ff6a3d", "#f5a524", "#8bd450", "#2ecc71"];
const NAMES = { md5: "MD5", sha1: "SHA-1", sha256: "SHA-256", sha512: "SHA-512", md5_salt: "MD5 salé", sha256_salt: "SHA-256 salé", pbkdf2: "PBKDF2 600k", scrypt: "scrypt", bcrypt: "bcrypt (12)" };
$$("#tabs .tab").forEach(t => t.onclick = () => { $$("#tabs .tab").forEach(x => x.classList.toggle("on", x === t)); $$(".pane").forEach(p => p.classList.toggle("on", p.id === t.dataset.p)); if (t.dataset.p === "lab") labLoad(); });

function human(s) {
  if (s < 1) return "instantané"; const u = [[31557600e2, "siècle"], [31557600, "an"], [2629800, "mois"], [86400, "jour"], [3600, "heure"], [60, "minute"], [1, "seconde"]];
  if (s > 31557600e9) return "plus que l'âge de l'Univers";
  for (const [k, n] of u) if (s >= k) { const v = s / k; return `${v >= 100 ? Math.round(v).toLocaleString("fr-FR") : v.toFixed(v < 10 ? 1 : 0)} ${n}${v >= 2 && !n.endsWith("s") ? "s" : ""}`; }
}

/* ── testeur ── */
let t; $("#pw").oninput = () => { clearTimeout(t); t = setTimeout(test, 120); };
async function test() {
  const pw = $("#pw").value; $("#cmpPw").textContent = pw || "motdepasse";
  if (!pw) { $$("#segs i").forEach(i => i.style.background = ""); $("#label").textContent = "—"; $("#patterns").innerHTML = $("#times").innerHTML = ""; return; }
  const a = await api("/api/analyze", { method: "POST", body: { password: pw } });
  $$("#segs i").forEach((i, k) => i.style.background = k <= a.level ? LVL_COL[a.level] : "");
  $("#label").textContent = a.label; $("#label").style.color = LVL_COL[a.level]; $("#bits").textContent = `${a.length} caractères · alphabet de ${a.pool}`;
  $("#naive").textContent = a.naive_bits; $("#real").textContent = a.bits;
  $("#patterns").innerHTML = a.patterns.map(p => `<div class="pat">⚠ ${esc(p)}</div>`).join("") || `<div class="pat" style="border-color:var(--ok)">✓ Aucun motif prévisible détecté</div>`;
  $("#times").innerHTML = ["md5", "sha256", "sha256_salt", "bcrypt", "scrypt"].map(k => { const s = a.crack_seconds[k];
    return `<div class="row between" style="padding:8px 0;border-bottom:1px solid var(--line)"><span>${NAMES[k]}</span><b class="${s < 86400 * 30 ? "cr" : "safe"}">${human(s)}</b></div>`; }).join("");
}

/* ── comparateur ── */
$("#cmpGo").onclick = async () => {
  $("#cmpGo").disabled = true; $("#cmpGo").textContent = "Mesure en cours…";
  const r = await api("/api/compare", { method: "POST", body: { password: $("#pw").value } });
  $("#cmpGo").disabled = false; $("#cmpGo").textContent = "Comparer";
  $("#cmp").innerHTML = `<tr><th>Algorithme</th><th>Empreinte stockée (2 calculs)</th><th>CPU ici</th><th>GPU (RTX 4090)</th><th>Temps pour casser</th></tr>` + r.algos.map(a => `<tr>
    <td><b>${esc(a.label)}</b>${a.same_twice ? `<div class="badge red" style="margin-top:4px">identique à chaque fois</div>` : `<div class="badge ok" style="margin-top:4px">sel unique</div>`}</td>
    <td class="hash">${esc(a.hash.slice(0, 90))}${a.hash.length > 90 ? "…" : ""}</td><td class="mono">${Math.round(a.cpu_rate).toLocaleString("fr-FR")}/s</td>
    <td class="mono">${a.gpu_rate.toExponential(1).replace("e+", "×10^")}/s</td><td class="${a.crack_seconds < 86400 * 30 ? "cr" : "safe"}">${human(a.crack_seconds)}</td></tr>`).join("");
  Charts.bar($("#cmpChart"), r.algos.map(a => NAMES[a.algo] || a.algo), r.algos.map(a => Math.max(0.1, Math.log10(Math.max(a.crack_seconds, 1)) + 1)),
    { colors: r.algos.map(a => a.crack_seconds < 86400 * 30 ? "#e5172f" : "#2ecc71") });
};

/* ── labo ── */
async function labLoad(state) {
  const s = state || await api("/api/lab");
  if (!$("#uAlgo").options.length) $("#uAlgo").innerHTML = Object.entries(s.algos).map(([k, v]) => `<option value="${k}">${v}</option>`).join("");
  $("#users").innerHTML = `<tr><th>Compte</th><th>Stockage</th><th>Empreinte en base</th><th>Résultat</th></tr>` + s.users.map(u => `<tr class="${u.same_hash_as.length ? "same" : ""}" data-u="${esc(u.name)}">
    <td><b>${esc(u.name)}</b></td><td style="font-size:12px">${esc(u.algo_label)}</td><td class="hash">${esc(u.stored.slice(0, 64))}${u.stored.length > 64 ? "…" : ""}${u.same_hash_as.length ? `<div class="red" style="font:600 11px var(--font)">même empreinte que ${u.same_hash_as.map(esc).join(", ")} → même mot de passe !</div>` : ""}</td><td class="res dim">—</td></tr>`).join("")
    || `<tr><td colspan="4"><div class="empty">Le labo est vide. Ajoutez des comptes ou chargez un scénario.</div></td></tr>`;
  $("#atkStats").innerHTML = "";
}
$("#uAdd").onclick = async () => { try { labLoad(await api("/api/lab/users", { method: "POST", body: { name: $("#uName").value, password: $("#uPw").value, algo: $("#uAlgo").value } })); $("#uName").value = $("#uPw").value = ""; } catch (e) { toast(e.message); } };
$$("[data-demo]").forEach(b => b.onclick = async () => { b.disabled = true; labLoad(await api("/api/lab/demo", { method: "POST", body: { algo: b.dataset.demo } })); b.disabled = false; });
$("#reset").onclick = async () => labLoad(await api("/api/lab/reset", { method: "POST" }));
$("#attack").onclick = async () => {
  $("#attack").disabled = true; $("#attack").innerHTML = `<span class="badge red live" style="border:0;background:none;color:#fff">attaque en cours…</span>`;
  $$("#users .res").forEach(r => r.innerHTML = `<span class="badge live">…</span>`);
  const r = await api("/api/lab/attack", { method: "POST", body: { budget: +$("#budget").value } });
  $("#attack").disabled = false; $("#attack").textContent = "☠ Lancer l'attaque par dictionnaire";
  $$("#users tr[data-u]").forEach(tr => { const f = r.found[tr.dataset.u]; $(".res", tr).innerHTML = f ? `<span class="cr">« ${esc(f.password)} »</span><div class="dim" style="font-size:11px">${f.after} s · ${f.tries.toLocaleString("fr-FR")} essais</div>` : `<span class="safe">résiste</span>`; });
  $("#atkStats").innerHTML = Object.entries(r.stats).map(([a, s]) => `<div class="grid g4"><div class="stat"><div class="l">${NAMES[a] || a}</div><div class="v">${s.cracked}/${s.total}</div></div>
    <div class="stat"><div class="l">Essais</div><div class="v">${s.tried.toLocaleString("fr-FR")}</div></div><div class="stat"><div class="l">Débit</div><div class="v">${s.rate.toLocaleString("fr-FR")}/s</div></div>
    <div class="stat"><div class="l">Durée</div><div class="v">${s.seconds} s${s.timeout ? ` <small class="muted">(budget épuisé)</small>` : ""}</div></div></div>`).join("");
};

/* ── benchmark ── */
$("#benchGo").onclick = async () => {
  $("#benchGo").disabled = true; const r = await api("/api/bench"); $("#benchGo").disabled = false;
  $("#engine").textContent = "Moteur : " + r.engine;
  Charts.bar($("#benchChart"), r.results.map(x => x.algo), r.results.map(x => Math.log10(Math.max(1, x.per_sec))));
  $("#benchT").innerHTML = `<tr><th>Algorithme</th><th>Hachages / seconde (1 cœur)</th><th>Ratio vs MD5</th></tr>` + r.results.map(x => `<tr><td>${x.algo}</td><td class="mono">${Math.round(x.per_sec).toLocaleString("fr-FR")}</td><td class="mono">${x.algo === "md5" ? "1" : "÷ " + Math.round(r.results[0].per_sec / x.per_sec).toLocaleString("fr-FR")}</td></tr>`).join("");
};
