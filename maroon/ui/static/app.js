"use strict";
const $ = (s) => document.querySelector(s);
const el = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e; };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const SEV = ["critical", "high", "medium", "low", "info"];

// --- BYOK persistence (local only) ---
try {
  $("#provider").value = localStorage.getItem("me_provider") || "";
  $("#apikey").value = localStorage.getItem("me_key") || "";
} catch (e) {}
$("#provider").addEventListener("change", () => { try { localStorage.setItem("me_provider", $("#provider").value); } catch (e) {} });
$("#apikey").addEventListener("input", () => { try { localStorage.setItem("me_key", $("#apikey").value); } catch (e) {} });

let RESULTS = {};  // target -> summary

$("#scanBtn").addEventListener("click", startScan);
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
  t.classList.add("active");
  ["findings", "inventory", "threat", "gov"].forEach((n) =>
    $("#tab-" + n).classList.toggle("hidden", n !== t.dataset.tab));
}));

function startScan() {
  const targets = $("#targets").value.split("\n").map((s) => s.trim()).filter(Boolean);
  if (!targets.length) { alert("Add at least one target."); return; }
  RESULTS = {};
  $("#board").classList.remove("hidden");
  $("#resultsWrap").classList.add("hidden");
  $("#queue").innerHTML = ""; $("#log").innerHTML = "";
  $("#scanBtn").disabled = true; $("#scanBtn").textContent = "Scanning…";

  const csrf = (document.querySelector('meta[name=me-csrf]') || {}).content || "";
  fetch("/api/scan", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Maroon-Token": csrf },
    body: JSON.stringify({ targets, crownJewels: $("#crown").value, subscanners: $("#subs").checked }),
  }).then((r) => r.json()).then((d) => {
    if (d.error) { logLine("error: " + d.error); done(); return; }
    stream(d.runId);
  }).catch((e) => { logLine("error: " + e); done(); });
}

function stream(runId) {
  const es = new EventSource("/api/stream/" + runId);
  es.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    handle(ev);
  };
  es.addEventListener("eof", () => { es.close(); done(); renderAll(); });
  es.onerror = () => { es.close(); done(); renderAll(); };
}

function handle(ev) {
  if (ev.kind === "plan") {
    ev.queue.forEach((q) => {
      const c = el("span", "chip p" + q.priority.slice(1).toLowerCase(),
        '<span class="pill">' + q.priority + '</span> ' + esc(q.target));
      c.id = "q-" + cssId(q.target); $("#queue").appendChild(c);
    });
    logLine('plan · ' + ev.queue.length + ' targets · crown jewels: "' + esc(ev.crown_jewels || "—") + '"');
    logLine('agency caps · max ' + ev.caps.max_targets + ' targets, ' + ev.caps.wall_clock_s + 's wall-clock');
  } else if (ev.kind === "scan_start") {
    logLine("▶ scanning " + esc(ev.target) + "  (" + ev.priority + ")");
  } else if (ev.kind === "scan_done") {
    RESULTS[ev.target] = ev.result;
    const chip = $("#q-" + cssId(ev.target));
    if (chip) chip.style.borderColor = ev.result.counts.critical || ev.result.counts.high ? "#ff5c7a66" : "#49c17c66";
    logLine("✓ " + esc(ev.target) + " — " + ev.findings + " findings · " + ev.verdict);
  } else if (ev.kind === "scan_error") {
    logLine("✗ " + esc(ev.target || "") + " — " + esc(ev.error));
  } else if (ev.kind === "complete") {
    logLine("done · " + ev.targets + " scanned · log " + (ev.log_verified ? "verified ✓" : "UNVERIFIED ✗"));
  }
}

function logLine(t) {
  const d = el("div", null, '<span class="dot">•</span> ' + t);
  $("#log").appendChild(d); $("#log").scrollTop = $("#log").scrollHeight;
}
function cssId(s) { return s.replace(/[^a-z0-9]/gi, "_"); }
function done() { $("#scanBtn").disabled = false; $("#scanBtn").textContent = "▸ Scan"; }

function allFindings() {
  const out = [];
  Object.values(RESULTS).forEach((r) => (r.findings_detail || []).forEach((f) => out.push(Object.assign({ _target: r.target }, f))));
  return out;
}

function renderAll() {
  if (!Object.keys(RESULTS).length) return;
  $("#resultsWrap").classList.remove("hidden");
  renderFindings(); renderInventory(); renderThreat(); renderGov();
}

function ids(fw) {
  let a = [];
  ["llm", "asi", "dsgai"].forEach((k) => (fw && fw[k] ? a = a.concat(fw[k]) : 0));
  return a.slice(0, 5).join(" ");
}

function renderFindings() {
  const fs = allFindings().sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity));
  const host = $("#tab-findings"); host.innerHTML = "";
  const counts = {}; fs.forEach((f) => counts[f.severity] = (counts[f.severity] || 0) + 1);
  const bar = el("div", "counts");
  SEV.forEach((s) => { if (counts[s]) bar.appendChild(el("span", "count sev-" + s, s.toUpperCase() + " " + counts[s])); });
  host.appendChild(bar);
  if (!fs.length) { host.appendChild(el("div", "empty", "No findings 🎉")); return; }
  const tbl = el("table"); tbl.innerHTML = "<thead><tr><th>Sev</th><th>Location</th><th>Finding</th><th>OWASP</th><th>Sources</th></tr></thead>";
  const tb = el("tbody");
  fs.forEach((f) => {
    const tr = el("tr");
    tr.innerHTML =
      '<td class="sev sev-' + f.severity + '">' + f.severity.toUpperCase() + "</td>" +
      "<td><code>" + esc(f._target) + ":" + esc(f.file) + ":" + esc(f.line || "?") + "</code></td>" +
      "<td>" + esc(f.message || f.title) + '<div class="ids">' + esc(f.rule_id) + " · score " + (f.severity_score || "") + "</div></td>" +
      '<td class="ids">' + esc(ids(f.frameworks)) + "</td>" +
      '<td class="ids">' + esc((f.sources || []).map((s) => s.scanner).filter((v, i, a) => a.indexOf(v) === i).join(",")) + "</td>";
    tb.appendChild(tr);
  });
  tbl.appendChild(tb); host.appendChild(tbl);
}

function renderInventory() {
  const host = $("#tab-inventory"); host.innerHTML = "";
  Object.values(RESULTS).forEach((r) => {
    host.appendChild(el("h3", null, esc(r.target) + " — " + (r.inventory.components.length) + " components"));
    if (!r.inventory.components.length) { host.appendChild(el("div", "empty", "no AI/agentic/MCP components")); return; }
    const tbl = el("table"); tbl.innerHTML = "<thead><tr><th>Component</th><th>Category</th><th>MAESTRO</th><th>Trust</th></tr></thead>";
    const tb = el("tbody");
    r.inventory.components.forEach((c) => {
      tb.appendChild(el("tr", null, "<td><code>" + esc(c.id) + "</code></td><td>" + esc(c.category) +
        "</td><td>L" + c.maestro_layer + "</td><td>" + esc(c.trust_tier) + "</td>"));
    });
    tbl.appendChild(tb); host.appendChild(tbl);
  });
}

function renderThreat() {
  const host = $("#tab-threat"); host.innerHTML = "";
  const LAYER = { 1: "Foundation Models", 2: "Data Operations", 3: "Agent Frameworks", 4: "Deployment & Infra", 5: "Eval & Observability", 6: "Security & Compliance", 7: "Agent Ecosystem" };
  Object.values(RESULTS).forEach((r) => {
    host.appendChild(el("h3", null, esc(r.target) + " — MAESTRO layers"));
    const byL = {};
    r.inventory.components.forEach((c) => { (byL[c.maestro_layer] = byL[c.maestro_layer] || []).push(c.id); });
    const row = el("div", "layers");
    Object.keys(byL).sort().forEach((L) => {
      const col = el("div", "layer", "<h3>L" + L + " · " + esc(LAYER[L] || "") + "</h3>");
      byL[L].forEach((cid) => col.appendChild(el("div", "comp", esc(cid))));
      row.appendChild(col);
    });
    if (!Object.keys(byL).length) row.appendChild(el("div", "empty", "no components"));
    host.appendChild(row);
  });
}

function renderGov() {
  const host = $("#tab-gov"); host.innerHTML = "";
  Object.values(RESULTS).forEach((r) => {
    const g = r.governance; const bad = /EXPOSURE|GAP|INSUFFICIENT|DO NOT/.test(g.verdict);
    const card = el("div", null,
      "<h3>" + esc(r.target) + "</h3>" +
      '<div class="verdict"><span class="big ' + (bad ? "bad" : "good") + '">' + esc(g.verdict) + "</span>" +
      '<span class="kv">Tier <b>' + esc(g.adoption_tier) + "</b> · " + esc(g.adoption_tier_name) + "</span>" +
      '<span class="kv">Maturity <b>' + esc(g.governance_level) + "</b> · " + esc(g.governance_level_name) + "</span></div>" +
      (g.recommendation ? '<p class="kv">→ ' + esc(g.recommendation) + "</p>" : "") +
      '<p class="kv" style="opacity:.7">' + esc(g.note || "") + "</p>");
    host.appendChild(card);
  });
}
