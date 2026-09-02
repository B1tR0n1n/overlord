"""OVERLORD mission control — localhost web UI served off the engine.

    overlord ui [--port 7777]

Zero dependencies, single file, binds 127.0.0.1 only. The review moment —
the receipt — rendered for human eyes: pending sessions, per-file diffs with
before/after hashes, provenance, one-click commit or rollback, policy editor.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import overlord as core

PALETTE = dict(bg="#0a0908", card="#151311", border="#2a2520",
               text="#c8bda0", dim="#8a7f6e", gold="#c9a227")

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>OVERLORD — mission control</title>
<style>
:root {{ --bg:{bg}; --card:{card}; --border:{border}; --text:{text}; --dim:{dim}; --gold:{gold}; }}
* {{ box-sizing:border-box; margin:0; }}
body {{ background:var(--bg); color:var(--text); font:14px/1.5 'JetBrains Mono',monospace; }}
header {{ display:flex; align-items:baseline; gap:14px; padding:14px 22px;
  border-bottom:1px solid var(--border); }}
header b {{ color:var(--gold); letter-spacing:.18em; font-size:16px; }}
header .sub {{ color:var(--dim); font-size:12px; }}
header .right {{ margin-left:auto; color:var(--dim); font-size:12px; }}
.layout {{ display:grid; grid-template-columns:340px 1fr; min-height:calc(100vh - 53px); }}
aside {{ border-right:1px solid var(--border); padding:14px; overflow-y:auto; }}
main {{ padding:20px 26px; overflow-y:auto; }}
.sess {{ border:1px solid var(--border); background:var(--card); border-radius:6px;
  padding:10px 12px; margin-bottom:10px; cursor:pointer; }}
.sess:hover, .sess.sel {{ border-color:var(--gold); }}
.sess .sid {{ font-size:12px; }}
.sess .tgt {{ color:var(--dim); font-size:11px; overflow:hidden; text-overflow:ellipsis;
  white-space:nowrap; }}
.chip {{ display:inline-block; font-size:10px; padding:1px 7px; border-radius:8px;
  border:1px solid var(--border); color:var(--dim); margin-right:5px; }}
.chip.pending {{ color:var(--gold); border-color:var(--gold); }}
.chip.grant {{ color:var(--text); }}
h2 {{ color:var(--gold); font-size:13px; letter-spacing:.14em; text-transform:uppercase;
  margin:22px 0 10px; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
td {{ padding:5px 10px 5px 0; border-bottom:1px solid var(--border); vertical-align:top; }}
.k-added {{ color:var(--gold); }}
.k-deleted {{ color:var(--dim); text-decoration:line-through; }}
.k-modified {{ color:var(--text); }}
.k-replaced-dir {{ color:var(--gold); }}
.hash {{ color:var(--dim); font-size:11px; }}
.cmdline {{ background:var(--card); border:1px solid var(--border); border-radius:6px;
  padding:10px 14px; margin-top:6px; word-break:break-all; }}
button {{ background:none; font:inherit; cursor:pointer; padding:9px 26px;
  border-radius:6px; letter-spacing:.1em; }}
.commit {{ background:var(--gold); color:var(--bg); border:1px solid var(--gold);
  font-weight:bold; }}
.rollback {{ background:none; color:var(--dim); border:1px solid var(--border); }}
.rollback:hover {{ color:var(--text); border-color:var(--dim); }}
.actions {{ display:flex; gap:14px; align-items:center; margin-top:22px; }}
.actions label {{ color:var(--dim); font-size:12px; }}
.conflicts {{ border:1px solid var(--gold); border-radius:6px; padding:10px 14px;
  margin-top:14px; font-size:12px; }}
.conflicts b {{ color:var(--gold); }}
textarea {{ width:100%; height:220px; background:var(--card); color:var(--text);
  border:1px solid var(--border); border-radius:6px; font:12px 'JetBrains Mono',monospace;
  padding:10px; }}
.dimtext {{ color:var(--dim); }}
.meta {{ color:var(--dim); font-size:12px; margin-top:4px; }}
a {{ color:var(--gold); }}
</style></head><body>
<header><b>OVERLORD</b><span class="sub">agent hypervisor — mission control</span>
<span class="right" id="status">{status}</span></header>
<div class="layout">
<aside><div id="list">{list_html}</div>
<h2>policy</h2><textarea id="policy" spellcheck="false">{policy_text}</textarea>
<div class="actions"><button class="rollback" onclick="savePolicy()">save policy</button>
<span id="polmsg" class="dimtext"></span></div>
</aside>
<main id="detail">{detail_html}</main>
</div>
<script>
let SEL = null;
const BOOT = {boot};
const esc = s => String(s).replace(/[&<>"]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c]));
const j = (u, opt) => fetch(u, opt).then(r => r.json());

async function loadList(pre) {{
  const d = pre || await j('/api/sessions');
  document.getElementById('status').textContent = d.backend + ' backend · ' + d.sessions.length + ' sessions';
  const el = document.getElementById('list');
  if (!d.sessions.length) {{ el.innerHTML = '<span class="dimtext">no sessions yet</span>'; return; }}
  if (SEL === null && !pre) {{ const p = d.sessions.filter(m => m.status === 'pending'); if (p.length) select(p[p.length - 1].id); }}
  el.innerHTML = d.sessions.slice().reverse().map(m => {{
    const g = m.grants || {{}};
    const badges =
      `<span class="chip ${{m.status}}">${{m.status}}</span>` +
      (g.jail ? '<span class="chip grant">jail</span>' : '') +
      (g.net === 'none' ? '<span class="chip grant">net:none</span>' : '') +
      (m.timed_out ? '<span class="chip">timed-out</span>' : '');
    return `<div class="sess ${{m.id===SEL?'sel':''}}" onclick="select('${{m.id}}')">
      <div class="sid">${{m.id}} <span class="dimtext">exit=${{m.exit_code ?? '…'}}</span></div>
      <div class="tgt">${{esc(m.target)}}</div><div>${{badges}}</div></div>`;
  }}).join('');
}}

async function select(sid) {{
  SEL = sid;
  renderDetail(await j('/api/session/' + sid));
  loadList();
}}

function renderDetail(d) {{
  const m = d.meta, g = m.grants || {{}};
  let html = `<h2>session ${{m.id}}</h2>
    <div class="cmdline">${{esc((m.cmd||[]).join(' '))}}</div>
    <div class="meta">target ${{esc(m.target)}} · ${{m.backend}} backend · exit=${{m.exit_code}}
      · ${{m.started}} → ${{m.finished || ''}}
      ${{g.jail?' · jail':''}}${{g.net==='none'?' · net:none':''}}${{g.timeout?' · timeout '+g.timeout+'s':''}}</div>`;
  html += '<h2>changes</h2>';
  if (d.changes.length) {{
    html += '<table>' + d.changes.map(([k, p]) => {{
      const prov = d.provenance.find(r => r.path === p) || {{}};
      const hb = (prov.before_sha256 || '').slice(0, 12), ha = (prov.after_sha256 || '').slice(0, 12);
      return `<tr><td class="k-${{k}}">${{k}}</td><td>${{esc(p)}}</td>
        <td class="hash">${{hb || '·'}} → ${{ha || '·'}}</td></tr>`;
    }}).join('') + '</table>';
  }} else html += '<span class="dimtext">no changes recorded</span>';
  if (m.status === 'pending') {{
    html += `<div class="actions">
      <button class="commit" onclick="commit('${{sid}}')">COMMIT</button>
      <button class="rollback" onclick="rollback('${{sid}}')">ROLLBACK</button>
      <label><input type="checkbox" id="merge"> merge</label>
      <label><input type="checkbox" id="force"> force</label></div>
      <div id="conflicts"></div>`;
  }} else if (m.status === 'committed') {{
    html += `<div class="meta">committed ${{m.committed || ''}}${{m.forced ? ' (forced)' : ''}}
      ${{(m.merged_paths||[]).length ? ' · ' + m.merged_paths.length + ' merged' : ''}}</div>`;
  }}
  document.getElementById('detail').innerHTML = html;
}}

async function commit(sid) {{
  const body = JSON.stringify({{ merge: merge.checked, force: force.checked }});
  const r = await j('/api/session/' + sid + '/commit', {{ method: 'POST', body }});
  if (r.error) {{ conflicts.innerHTML = `<div class="conflicts"><b>refused</b> — ${{esc(r.error)}}</div>`; return; }}
  if (!r.committed) {{
    conflicts.innerHTML = `<div class="conflicts"><b>target drifted — refusing:</b><br>` +
      r.conflicts.map(([why, p]) => `${{why}} · ${{esc(p)}}`).join('<br>') +
      `<br><span class="dimtext">retry with merge (needs --merge-base) or force</span></div>`;
    return;
  }}
  select(sid);
}}
async function rollback(sid) {{
  await j('/api/session/' + sid + '/rollback', {{ method: 'POST', body: '{{}}' }});
  SEL = null; document.getElementById('detail').innerHTML = '<span class="dimtext">rolled back</span>';
  loadList();
}}
async function savePolicy() {{
  const r = await j('/api/policy', {{ method: 'PUT', body: policy.value }});
  polmsg.textContent = r.error ? ('error: ' + r.error) : 'saved';
  setTimeout(() => polmsg.textContent = '', 2500);
}}
if (BOOT.detail) {{ SEL = BOOT.detail.meta.id; }}
setInterval(() => {{ loadList(); }}, 2500);
</script></body></html>"""


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _render_list(metas, sel):
    if not metas:
        return '<span class="dimtext">no sessions yet</span>'
    rows = []
    for m in reversed(metas):
        g = m.get("grants") or {}
        badges = f'<span class="chip {m.get("status")}">{m.get("status")}</span>'
        if g.get("jail"):
            badges += '<span class="chip grant">jail</span>'
        if g.get("net") == "none":
            badges += '<span class="chip grant">net:none</span>'
        if m.get("timed_out"):
            badges += '<span class="chip">timed-out</span>'
        cls = "sess sel" if m["id"] == sel else "sess"
        rows.append(
            f'<div class="{cls}" onclick="select(\'{m["id"]}\')">'
            f'<div class="sid">{m["id"]} <span class="dimtext">exit='
            f'{m.get("exit_code", "…")}</span></div>'
            f'<div class="tgt">{_esc(m.get("target"))}</div><div>{badges}</div></div>'
        )
    return "".join(rows)


def _render_detail(payload):
    if payload is None:
        return '<span class="dimtext">select a session</span>'
    m, g = payload["meta"], payload["meta"].get("grants") or {}
    prov = {r["path"]: r for r in payload["provenance"]}
    grantline = "".join([
        " · jail" if g.get("jail") else "",
        " · net:none" if g.get("net") == "none" else "",
        f" · timeout {g['timeout']}s" if g.get("timeout") else "",
    ])
    html = [
        f'<h2>session {m["id"]}</h2>',
        f'<div class="cmdline">{_esc(" ".join(m.get("cmd", [])))}</div>',
        f'<div class="meta">target {_esc(m.get("target"))} · {m.get("backend")} '
        f'backend · exit={m.get("exit_code")} · {m.get("started")} → '
        f'{m.get("finished", "")}{grantline}</div>',
        "<h2>changes</h2>",
    ]
    if payload["changes"]:
        rows = []
        for k, p in payload["changes"]:
            r = prov.get(p, {})
            hb, ha = (r.get("before_sha256") or "")[:12], (r.get("after_sha256") or "")[:12]
            rows.append(f'<tr><td class="k-{k}">{k}</td><td>{_esc(p)}</td>'
                        f'<td class="hash">{hb or "·"} → {ha or "·"}</td></tr>')
        html.append("<table>" + "".join(rows) + "</table>")
    else:
        html.append('<span class="dimtext">no changes recorded</span>')
    if m.get("status") == "pending":
        html.append(
            f'<div class="actions">'
            f'<button class="commit" onclick="commit(\'{m["id"]}\')">COMMIT</button>'
            f'<button class="rollback" onclick="rollback(\'{m["id"]}\')">ROLLBACK</button>'
            f'<label><input type="checkbox" id="merge"> merge</label>'
            f'<label><input type="checkbox" id="force"> force</label></div>'
            f'<div id="conflicts"></div>')
    elif m.get("status") == "committed":
        merged = len(m.get("merged_paths") or [])
        html.append(f'<div class="meta">committed {m.get("committed", "")}'
                    f'{" (forced)" if m.get("forced") else ""}'
                    f'{" · " + str(merged) + " merged" if merged else ""}</div>')
    return "".join(html)


def _session_payload(sid):
    meta = core.load_meta(sid)
    upper = os.path.join(core.session_path(sid), "upper")
    changes = core.compute_diff(upper, meta["target"]) if os.path.isdir(upper) else []
    prov_path = os.path.join(core.session_path(sid), "provenance.jsonl")
    provenance = []
    if os.path.isfile(prov_path):
        with open(prov_path) as f:
            provenance = [json.loads(line) for line in f]
    if not changes and provenance:  # committed sessions: show from the record
        changes = [[r["kind"], r["path"]] for r in provenance]
    return {"meta": meta, "changes": changes, "provenance": provenance}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200, raw=None, ctype="application/json"):
        body = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        try:
            if self.path == "/":
                metas = [core.load_meta(s) for s in core.list_sessions()]
                backend = core.detect_backend() or "none"
                boot = {"backend": backend, "sessions": metas, "detail": None}
                pending = [m for m in metas if m.get("status") == "pending"]
                sel = None
                if pending:
                    sel = pending[-1]["id"]
                    boot["detail"] = _session_payload(sel)
                policy_text = ""
                if os.path.isfile(core.POLICY_FILE):
                    with open(core.POLICY_FILE) as f:
                        policy_text = f.read()
                page = PAGE.format(
                    **PALETTE, boot=json.dumps(boot),
                    status=f"{backend} backend · {len(metas)} sessions",
                    list_html=_render_list(metas, sel),
                    detail_html=_render_detail(boot["detail"]),
                    policy_text=_esc(policy_text),
                )
                self._send(None, raw=page.encode(), ctype="text/html; charset=utf-8")
            elif self.path == "/api/sessions":
                metas = [core.load_meta(s) for s in core.list_sessions()]
                self._send({"backend": core.detect_backend() or "none",
                            "sessions": metas})
            elif self.path == "/api/policy":
                text = ""
                if os.path.isfile(core.POLICY_FILE):
                    with open(core.POLICY_FILE) as f:
                        text = f.read()
                self._send({"text": text})
            elif self.path.startswith("/api/session/"):
                self._send(_session_payload(self.path.rsplit("/", 1)[-1]))
            else:
                self._send({"error": "not found"}, 404)
        except SystemExit as e:
            self._send({"error": str(e)}, 400)
        except Exception as e:
            self._send({"error": f"{type(e).__name__}: {e}"}, 500)

    def do_POST(self):
        try:
            parts = self.path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["api", "session"]:
                sid, action = parts[2], parts[3]
                req = self._body()
                if action == "commit":
                    self._send(core.commit_session(
                        sid, merge=bool(req.get("merge")), force=bool(req.get("force"))))
                elif action == "rollback":
                    self._send({"target": core.rollback_session(sid)})
                else:
                    self._send({"error": "unknown action"}, 404)
            else:
                self._send({"error": "not found"}, 404)
        except SystemExit as e:
            self._send({"error": str(e)}, 400)
        except Exception as e:
            self._send({"error": f"{type(e).__name__}: {e}"}, 500)

    def do_PUT(self):
        try:
            if self.path == "/api/policy":
                n = int(self.headers.get("Content-Length") or 0)
                text = self.rfile.read(n).decode()
                json.loads(text)  # must be valid JSON before it becomes law
                os.makedirs(os.path.dirname(core.POLICY_FILE), exist_ok=True)
                with open(core.POLICY_FILE, "w") as f:
                    f.write(text)
                self._send({"saved": True})
            else:
                self._send({"error": "not found"}, 404)
        except Exception as e:
            self._send({"error": f"{type(e).__name__}: {e}"}, 400)


def serve(port=7777):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"OVERLORD mission control: http://127.0.0.1:{port}  (local only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
