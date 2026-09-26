-- GET /_surge?format=html. One static page that polls the JSON status of
-- the same location every 2s. Targets and messages can carry a client's
-- Host header, so every value goes in with textContent, never innerHTML.

local _M = {}

_M.CSP = "default-src 'none'; script-src 'unsafe-inline'; "
    .. "style-src 'unsafe-inline'; connect-src 'self'"

_M.HTML = [[<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>surge status</title>
<style>
:root { color-scheme: light dark; --fg: #1d1d1f; --bg: #fff; --mute: #6e6e73;
  --line: #d2d2d7; --ok: #1a7f37; --warn: #9a6700; --bad: #cf222e; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e6e6e6; --bg: #161618; --mute: #9a9aa0; --line: #3a3a3f;
    --ok: #3fb950; --warn: #d29922; --bad: #f85149; } }
body { margin: 0; padding: 16px; font: 14px/1.45 system-ui, sans-serif;
  color: var(--fg); background: var(--bg); }
header { display: flex; flex-wrap: wrap; gap: 8px 24px; align-items: baseline; }
h1 { font-size: 16px; margin: 0; }
#mode { font-weight: 600; }
#mode.normal { color: var(--ok); } #mode.elevated { color: var(--warn); }
#mode.attack { color: var(--bad); }
.mute { color: var(--mute); }
.wrap { overflow-x: auto; margin-top: 16px; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 6px 10px 6px 0; border-bottom: 1px solid var(--line);
  vertical-align: top; }
th { font-weight: 600; color: var(--mute); font-size: 12px; }
td.t { font-family: ui-monospace, monospace; word-break: break-all; }
button { font: inherit; padding: 2px 10px; cursor: pointer; }
#err { color: var(--bad); }
</style>
</head>
<body>
<header>
  <h1>surge</h1>
  <span id="mode">…</span>
  <span id="rps" class="mute"></span>
  <span id="err"></span>
</header>
<div class="wrap">
<table>
  <thead><tr><th>Action</th><th>Target</th><th>Reason</th><th>Path</th>
    <th>Expires</th><th>Message</th><th></th></tr></thead>
  <tbody></tbody>
</table>
</div>
<p id="empty" class="mute" hidden>No decisions.</p>
<script>
const $ = (s) => document.querySelector(s);
const url = location.pathname;
async function load() {
  try {
    const r = await fetch(url, { cache: "no-store" });
    const d = await r.json();
    const mode = $("#mode");
    mode.className = d.mode || "";
    mode.textContent = (d.mode || "?") + (d.dry_run ? " (dry run)" : "")
      + (d.warming ? ", warming up" : "");
    $("#rps").textContent = Math.round(d.rps || 0) + " req/s, baseline "
      + Math.round(d.baseline_mean || 0);
    const list = d.decisions || [];
    const tb = $("tbody");
    tb.replaceChildren();
    for (const x of list) {
      const tr = tb.insertRow();
      const cells = [x.action, x.target, x.reason, x.uri || "",
        x.expires_in == null ? "" : x.expires_in + "s", x.message || ""];
      cells.forEach((v, i) => {
        const td = tr.insertCell();
        td.textContent = v == null ? "" : String(v);
        if (i === 1) td.className = "t";
      });
      const b = document.createElement("button");
      b.textContent = "Remove";
      b.onclick = async () => {
        b.disabled = true;
        await fetch(url + "?unblock=" + encodeURIComponent(x.incident), { method: "POST" });
        load();
      };
      tr.insertCell().append(b);
    }
    $("#empty").hidden = list.length > 0;
    $("#err").textContent = "";
  } catch (e) {
    $("#err").textContent = "status unavailable: " + e.message;
  }
}
load();
setInterval(load, 2000);
</script>
</body>
</html>
]]

return _M
