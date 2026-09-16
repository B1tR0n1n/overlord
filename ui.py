"""OVERLORD mission control — localhost web UI served off the engine.

    overlord ui [--port 7777]

Zero dependencies, single file, binds 127.0.0.1 only. The review moment —
the receipt — rendered for human eyes: pending sessions, per-file diffs with
before/after hashes, provenance attribution, commit or rollback, policy.

Presentation is Field Systems Division: a document of record, not a console.
The register indexes sessions; the dossier is the instrument a human signs.
Serif carries the record, mono carries the system. No webfont is fetched —
the stack degrades to Georgia / Consolas so the UI works airgapped.
"""

import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import overlord as core
import chatui

# Field Systems Division tokens. Dark ground is foundational; gold is earned.
PALETTE = dict(
    bg="#0a0908", bg2="#0f0e0b", bg3="#161410", panel="#1a1814",
    border="#2a2620", border_lt="#3d362c",
    text="#c8bda0", text_dim="#7a7060", text_bright="#ede5d0",
    accent="#c9a227", accent_dim="#8b7320", accent_glow="rgba(201,162,39,.12)",
    red="#a63d2f", green="#4a7a45",
)

CSS = """
:root{
  --bg:#0a0908; --bg2:#0f0e0b; --bg3:#161410; --panel:#1a1814;
  --border:#2a2620; --border-lt:#3d362c;
  --text:#c8bda0; --text-dim:#7a7060; --text-bright:#ede5d0;
  --accent:#c9a227; --accent-dim:#8b7320; --accent-glow:rgba(201,162,39,.12);
  --red:#a63d2f; --green:#4a7a45;
  --mono:'JetBrains Mono','Fira Code',ui-monospace,SFMono-Regular,Consolas,monospace;
  --serif:'Cormorant Garamond',Georgia,'Times New Roman',serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{background:var(--bg);color:var(--text);font-family:var(--mono);
  font-size:13px;line-height:1.5;-webkit-font-smoothing:antialiased}

/* the coordinate system beneath the content — structural, barely visible */
.grid-bg{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.08;
  background-image:linear-gradient(var(--border) 1px,transparent 1px),
                   linear-gradient(90deg,var(--border) 1px,transparent 1px);
  background-size:80px 80px}
.noise{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.03;
  width:100%;height:100%}

.frame{position:relative;z-index:1;display:grid;grid-template-rows:auto 1fr;height:100vh}

/* ---- masthead: a document header, not a navbar ---------------------- */
.masthead{display:flex;align-items:flex-end;gap:22px;padding:18px 26px 14px;
  border-bottom:1px solid var(--accent)}
.mark{font-family:var(--mono);font-size:19px;font-weight:600;letter-spacing:7px;
  color:var(--accent);text-transform:uppercase}
.mark-sub{font-family:var(--serif);font-size:17px;color:var(--text-dim);
  font-style:italic;padding-bottom:2px}
.mark-sub .mc{text-transform:uppercase;font-style:normal;font-family:var(--mono);
  font-size:9px;letter-spacing:4px;color:var(--accent-dim)}
.masthead .desig{margin-left:auto;text-align:right}
.desig-l{font-family:var(--mono);font-size:9px;letter-spacing:5px;
  text-transform:uppercase;color:var(--accent-dim)}
.desig-v{font-family:var(--mono);font-size:10px;letter-spacing:2px;
  text-transform:uppercase;color:var(--text-dim);margin-top:3px}

.body{display:grid;grid-template-columns:296px 1fr;min-height:0}

/* ---- 00 register: an index, not a list of cards --------------------- */
.register{border-right:1px solid var(--border);display:flex;flex-direction:column;min-height:0}
.reg-head{padding:20px 18px 0}
.reg-scroll{overflow-y:auto;flex:1;min-height:0;margin-top:14px}
.reg-item{display:block;width:100%;text-align:left;background:none;
  border:0;border-bottom:1px solid var(--border);border-left:2px solid transparent;
  padding:11px 16px;cursor:pointer;font-family:var(--mono);
  transition:background .3s ease,border-color .3s ease}
.reg-item:hover{background:var(--accent-glow)}
.reg-item.sel{border-left-color:var(--accent);background:var(--accent-glow)}
.reg-top{display:flex;align-items:baseline;gap:8px}
.reg-idx{font-size:9px;letter-spacing:2px;color:var(--text-dim);flex:none}
.reg-sid{font-size:11px;color:var(--text-bright);letter-spacing:.5px}
.reg-item.sel .reg-sid{color:var(--accent)}
.reg-tgt{font-size:10px;color:var(--text-dim);margin:3px 0 6px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.reg-marks{display:flex;gap:6px;flex-wrap:wrap}
.reg-empty{padding:0 18px;font-family:var(--serif);font-size:16px;
  font-style:italic;color:var(--text-dim)}

/* ---- dossier: the instrument -------------------------------------- */
.dossier{overflow-y:auto;padding:26px 34px 60px;min-height:0}
.sheet{max-width:940px}
.sec{margin-bottom:38px}
.sec-label{font-family:var(--mono);font-size:9px;letter-spacing:5px;
  text-transform:uppercase;color:var(--accent-dim)}
.sec-title{font-family:var(--serif);font-size:27px;font-weight:600;
  letter-spacing:-.6px;color:var(--text-bright);margin-top:3px;line-height:1.15}
.sec-title .sid{font-family:var(--mono);font-size:16px;letter-spacing:1px;
  font-weight:400;color:var(--text)}
.rule{width:60px;height:1px;background:var(--accent);margin:13px 0 22px}
.rule.tight{margin:11px 0 0}
.rule.head{margin:11px 0 14px}
.manifest th.c-kind{width:130px}
.manifest th.c-integrity{width:210px}
#policy{margin-top:8px}

.cmdline{font-family:var(--mono);font-size:12px;color:var(--text-bright);
  background:var(--bg2);border:1px solid var(--border);border-left:2px solid var(--accent);
  padding:12px 16px;word-break:break-all}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:1px;background:var(--border);border:1px solid var(--border);margin-top:1px}
.fact{background:var(--bg2);padding:11px 14px}
.fact-k{font-family:var(--mono);font-size:9px;letter-spacing:3px;
  text-transform:uppercase;color:var(--text-dim)}
.fact-v{font-family:var(--mono);font-size:12px;color:var(--text-bright);
  margin-top:5px;word-break:break-all}
.fact-v.ts{word-break:normal;overflow-wrap:normal;font-size:11px;letter-spacing:-.2px}

/* stamps, not chips — bordered, tracked, never rounded */
.stamp{display:inline-block;font-family:var(--mono);font-size:9px;letter-spacing:3px;
  text-transform:uppercase;padding:3px 9px;border:1px solid currentColor;
  color:var(--text-dim);white-space:nowrap}
.stamp.pending,.stamp.open{color:var(--accent)}
.stamp.committed{color:var(--green)}
.stamp.rolled-back{color:var(--text-dim)}
.stamp.grant{color:var(--accent-dim)}
.stamp.alarm{color:var(--red)}
.grants{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px;align-items:center}
.grants-l{font-family:var(--mono);font-size:9px;letter-spacing:4px;
  text-transform:uppercase;color:var(--text-dim);margin-right:4px}

/* ---- 02 manifest: line items on a bill of lading ------------------- */
.manifest{width:100%;border-collapse:collapse}
.manifest th{font-family:var(--mono);font-size:9px;letter-spacing:3px;font-weight:500;
  text-transform:uppercase;color:var(--text-dim);text-align:left;
  padding:0 14px 9px 0;border-bottom:1px solid var(--border-lt)}
.manifest td{padding:11px 14px 11px 0;border-bottom:1px solid var(--border);
  vertical-align:top}
.manifest tr:hover td{background:var(--accent-glow)}
.mk{font-family:var(--mono);font-size:10px;letter-spacing:2px;text-transform:uppercase;
  white-space:nowrap}
.mk .g{display:inline-block;width:14px;color:var(--accent)}
.k-added .g{color:var(--accent)}
.k-modified .g{color:var(--text)}
.k-deleted .g{color:var(--red)}
.k-replaced-dir .g{color:var(--accent)}
.mpath{font-family:var(--mono);font-size:12px;color:var(--text-bright);
  word-break:break-all}
.k-deleted .mpath{color:var(--text-dim);text-decoration:line-through}
.cause{font-size:10px;color:var(--text-dim);margin-top:5px;line-height:1.6}
.cause .arrow{color:var(--accent-dim);margin-right:5px}
.cause b{color:var(--text);font-weight:400}
.cause .cid{color:var(--text-dim);opacity:.7}
.hash{font-family:var(--mono);font-size:10px;color:var(--text-dim);white-space:nowrap}
.hash .to{color:var(--accent-dim);margin:0 5px}
.empty{font-family:var(--serif);font-size:17px;font-style:italic;color:var(--text-dim)}

/* ---- 03 savepoints: the chain of decisions ------------------------- */
.sp{width:100%;border-collapse:collapse}
.sp td{padding:10px 14px 10px 0;border-bottom:1px solid var(--border);
  vertical-align:top;font-size:12px}
.sp tr:hover td{background:var(--accent-glow)}
.sp .n{font-family:var(--mono);color:var(--accent);width:52px;white-space:nowrap}
.sp .n.dropped{color:var(--text-dim);text-decoration:line-through}
.sp .what{color:var(--text-bright)}
.sp .what b{font-weight:400;color:var(--text)}
.sp .paths{font-family:var(--mono);font-size:10px;color:var(--text-dim);margin-top:4px;
  line-height:1.7}
.sp .ctl{width:180px;white-space:nowrap;text-align:right}
.sp .ctl .opt{display:inline-flex;margin-right:12px}
.sp .btn-quiet{padding:6px 12px;font-size:9px}
.sp-note{font-family:var(--serif);font-size:15px;font-style:italic;color:var(--text-dim);
  margin-top:14px}

.sp .btn-quiet+.btn-quiet{margin-left:6px}

/* ---- countersignature ---------------------------------------------- */
.sig{border:1px solid var(--border-lt);background:var(--bg3);padding:14px 16px;margin-bottom:18px}
.sig .sig-l{font-family:var(--mono);font-size:9px;letter-spacing:3px;text-transform:uppercase;
  color:var(--text-dim);margin-bottom:8px}
.sig .reason{font-family:var(--serif);font-size:15px;color:var(--text);margin-top:8px}
.sig .who{font-family:var(--mono);font-size:11px;color:var(--text-dim);margin-top:6px}
.stamp.approve{color:var(--green)}
.stamp.reject{color:var(--red)}
.stamp.stale{color:var(--text-dim);text-decoration:line-through}
.sig .req{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px}
.sig select,.sig input[type=text]{background:var(--bg2);color:var(--text);border:1px solid var(--border);
  font-family:var(--mono);font-size:11px;padding:7px 9px}

/* ---- blame: who put this line here --------------------------------- */
.blame-wrap{padding:20px 18px;border-top:1px solid var(--border)}
.blame-wrap input{width:100%;background:var(--bg2);color:var(--text);border:1px solid var(--border);
  font-family:var(--mono);font-size:11px;padding:9px 11px;margin-top:8px}
.blame-wrap input:focus{outline:none;border-color:var(--accent-dim)}
.linkish{background:none;border:0;padding:0;font:inherit;color:inherit;cursor:pointer;
  text-decoration:underline dotted var(--accent-dim);text-underline-offset:3px}
.linkish:hover{color:var(--accent)}
.legend{display:grid;gap:1px;background:var(--border);border:1px solid var(--border);margin-bottom:18px}
.legend .v{background:var(--bg2);padding:11px 14px;font-size:12px}
.legend .v .k{font-family:var(--mono);font-size:10px;letter-spacing:2px;color:var(--accent);
  margin-right:8px}
.legend .v .task{font-family:var(--serif);font-size:15px;color:var(--text-bright);margin-top:4px}
.legend .v .said{font-family:var(--serif);font-style:italic;color:var(--text-dim);margin-top:4px}
.legend .v .cause{margin-top:4px}
.bl{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px}
.bl td{padding:2px 10px 2px 0;border-bottom:1px solid var(--border);white-space:pre;vertical-align:top}
.bl td.ln{color:var(--text-dim);text-align:right;width:44px;user-select:none}
.bl td.own{width:150px;letter-spacing:1px}
.bl td.code{color:var(--text-bright);overflow-x:auto;max-width:0}
.own-origin{color:var(--text-dim)}
.own-drift{color:var(--red)}
.own-0{color:var(--accent)}.own-1{color:var(--green)}.own-2{color:#8ab4f8}
.own-3{color:#d7a6ff}.own-4{color:#f5a97f}.own-5{color:#7fd8d8}
.bl tr:hover td{background:var(--accent-glow)}

/* ---- 04 disposition ------------------------------------------------ */
.disposition{border:1px solid var(--border-lt);background:var(--bg2);padding:22px 24px}
.disp-note{font-family:var(--serif);font-size:17px;color:var(--text-dim);
  margin-bottom:18px;max-width:60ch}
.acts{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.btn{font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:2px;
  text-transform:uppercase;padding:11px 28px;border:1px solid;cursor:pointer;
  background:none;transition:background .3s ease,color .3s ease,border-color .3s ease}
.btn-commit{background:var(--accent);color:var(--bg);border-color:var(--accent)}
.btn-commit:hover{background:transparent;color:var(--accent)}
.btn-void{background:transparent;color:var(--text-dim);border-color:var(--border-lt)}
.btn-void:hover{color:var(--red);border-color:var(--red)}
.btn-quiet{background:transparent;color:var(--text-dim);border-color:var(--border-lt);
  padding:9px 20px;font-weight:500}
.btn-quiet:hover{color:var(--accent);border-color:var(--accent)}
.opt{display:flex;align-items:center;gap:7px;font-family:var(--mono);font-size:10px;
  letter-spacing:2px;text-transform:uppercase;color:var(--text-dim);cursor:pointer}
.opt input{accent-color:var(--accent);cursor:pointer}
.refusal{border:1px solid var(--red);border-left:2px solid var(--red);
  background:var(--bg3);padding:14px 16px;margin-top:18px;font-size:12px}
.refusal b{color:var(--red);font-family:var(--mono);font-size:10px;letter-spacing:3px;
  text-transform:uppercase;display:block;margin-bottom:8px}
.refusal .why{color:var(--text-dim)}
.refusal .hint{font-family:var(--serif);font-style:italic;font-size:15px;
  color:var(--text-dim);margin-top:10px}

/* ---- 05 policy ----------------------------------------------------- */
.policy-wrap{padding:20px 18px;border-top:1px solid var(--border)}
textarea{width:100%;height:150px;background:var(--bg2);color:var(--text);
  border:1px solid var(--border);font-family:var(--mono);font-size:11px;
  line-height:1.6;padding:11px;resize:vertical}
textarea:focus{outline:none;border-color:var(--accent-dim)}
.polmsg{font-family:var(--mono);font-size:10px;letter-spacing:2px;
  text-transform:uppercase;color:var(--text-dim)}
.polmsg.ok{color:var(--green)}
.polmsg.err{color:var(--red)}
.polrow{display:flex;gap:12px;align-items:center;margin-top:12px}

a{color:var(--accent);text-decoration:none}
:focus-visible{outline:1px solid var(--accent);outline-offset:2px}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:var(--border-lt)}
::-webkit-scrollbar-thumb:hover{background:var(--accent)}

/* system coming online — staggered, and only if motion is welcome */
@keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
.sec{animation:fadeUp .5s ease both}
.sec:nth-child(2){animation-delay:.06s}
.sec:nth-child(3){animation-delay:.12s}
.sec:nth-child(4){animation-delay:.18s}
@media (prefers-reduced-motion:reduce){.sec{animation:none}
  *{transition-duration:0s!important}}

@media (max-width:900px){
  .body{grid-template-columns:1fr;grid-template-rows:auto 1fr}
  .register{border-right:0;border-bottom:1px solid var(--border);max-height:38vh}
  .dossier{padding:20px 18px 50px}
  .masthead{flex-wrap:wrap;gap:12px;padding:14px 18px 12px}
  .masthead .desig{margin-left:0;text-align:left}
}

/* A printed dossier is an audit artifact, not the product surface:
   ink-economical on purpose. Delete this block to print the dark identity. */
@media print{
  .grid-bg,.noise,.register,.disposition,.policy-wrap{display:none!important}
  body,.frame,.dossier{background:#fff;color:#000;height:auto;overflow:visible}
  .masthead{border-bottom:1px solid #000}
  .mark{color:#000}
  .sec-title,.mpath,.fact-v,.cmdline{color:#000}
  .sec-label,.fact-k,.hash,.cause{color:#444}
  .rule{background:#000}
  .cmdline{background:none;border-color:#000}
  .sec{animation:none}
}
"""

SHELL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OVERLORD — mission control</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%230a0908'/%3E%3Crect x='4.5' y='4.5' width='23' height='23' fill='none' stroke='%232a2620'/%3E%3Crect x='10' y='10' width='12' height='12' fill='none' stroke='%23c9a227' stroke-width='2'/%3E%3Crect x='15' y='0' width='2' height='8' fill='%23c9a227'/%3E%3C/svg%3E">
<style nonce="__NONCE__">__CSS__</style></head><body>
<div class="grid-bg"></div>
<svg class="noise" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><filter id="fsd-noise">
<feTurbulence type="fractalNoise" baseFrequency="0.8" numOctaves="4" stitchTiles="stitch"/>
</filter><rect width="100%" height="100%" filter="url(#fsd-noise)"/></svg>
<div class="frame">
<header class="masthead">
  <span class="mark">OVERLORD</span>
  <span class="mark-sub">agent hypervisor &mdash; <span class="mc">mission control</span></span>
  <div class="desig">
    <div class="desig-l">Field Systems Division</div>
    <div class="desig-v" id="status">__STATUS__</div>
  </div>
</header>
<div class="body">
  <nav class="register" aria-label="Session register">
    <div class="reg-head">
      <div class="sec-label">00 &mdash; Register</div>
      <div class="rule tight"></div>
    </div>
    <div class="reg-scroll" id="list">__REGISTER__</div>
    <div class="blame-wrap">
      <div class="sec-label">06 &mdash; Blame</div>
      <div class="rule head"></div>
      <label for="blamepath" class="fact-k">who put each line here &mdash; path</label>
      <input id="blamepath" type="text" spellcheck="false" placeholder="/srv/app/src/lib.py">
    </div>
    <div class="policy-wrap">
      <div class="sec-label">05 &mdash; Policy</div>
      <div class="rule head"></div>
      <label for="policy" class="fact-k">broker ceiling &mdash; json</label>
      <textarea id="policy" spellcheck="false">__POLICY__</textarea>
      <div class="polrow">
        <button class="btn btn-quiet" id="seal">Seal</button>
        <span id="polmsg" class="polmsg"></span>
      </div>
    </div>
  </nav>
  <main class="dossier" id="detail" aria-live="polite"><div class="sheet">__DOSSIER__</div></main>
</div></div>
<script nonce="__NONCE__">
/* One renderer. The server owns all markup (and therefore all escaping);
   the client fetches rendered fragments and swaps them in. Anything not
   server-rendered below is either static or set via textContent. */
let SEL = __SEL__;
const $ = id => document.getElementById(id);
const j = (u, opt) => fetch(u, opt).then(r => r.json());

async function loadList() {
  const d = await j('/api/view?sel=' + encodeURIComponent(SEL || ''));
  $('status').innerHTML = d.status;
  $('list').innerHTML = d.register;
}

async function select(sid) {
  SEL = sid;
  const d = await j('/api/view/session/' + encodeURIComponent(sid));
  $('detail').innerHTML = d.dossier;
  loadList();
}

async function commit(sid) {
  // savepoints unticked in section 03 are dropped from the replay
  const drop = [...document.querySelectorAll('[data-keep]')]
    .filter(el => !el.checked).map(el => el.dataset.keep).join(',');
  const body = JSON.stringify({
    merge: !!($('merge') || {}).checked,
    force: !!($('force') || {}).checked,
    countersigned: !!($('countersigned') || {}).checked,
    drop: drop || null,
  });
  const r = await j('/api/session/' + encodeURIComponent(sid) + '/commit',
                    { method: 'POST', body });
  if (r.committed) return select(sid);
  const box = $('conflicts');
  if (r.rejected) { alertBox('rejected by ' + r.rejected.reviewer + ': ' + r.rejected.reason); return; }
  if (r.conflicts_html) { box.innerHTML = r.conflicts_html; return; }
  box.innerHTML = '<div class="refusal"><b>Refused</b><span class="why"></span></div>';
  box.querySelector('.why').textContent = r.error || 'unknown error';
}

async function rollback(sid) {
  await j('/api/session/' + encodeURIComponent(sid) + '/rollback',
          { method: 'POST', body: '{}' });
  SEL = null;
  $('detail').innerHTML =
    '<div class="sheet"><section class="sec">' +
    '<div class="sec-label">01 &mdash; Dossier</div>' +
    '<h1 class="sec-title">Voided</h1><div class="rule"></div>' +
    '<div class="empty">The overlay was discarded. The target is byte-identical.</div>' +
    '</section></div>';
  loadList();
}

async function blame(path) {
  const d = await j('/api/view/blame?path=' + encodeURIComponent(path));
  $('detail').innerHTML = d.dossier;
}

async function fork(sid, at) {
  const r = await j('/api/session/' + encodeURIComponent(sid) + '/fork',
                    { method: 'POST', body: JSON.stringify({ at: Number(at) }) });
  if (r.error) { alertBox(r.error); return; }
  return select(r.sid);
}

async function review(sid) {
  const provider = ($('rev-provider') || {}).value || 'anthropic';
  const model = ($('rev-model') || {}).value || null;
  const box = $('sig-status');
  if (box) box.textContent = 'reviewing…';
  const r = await j('/api/session/' + encodeURIComponent(sid) + '/review',
                    { method: 'POST', body: JSON.stringify({ provider, model }) });
  if (r.error) { if (box) box.textContent = 'refused: ' + r.error; return; }
  return select(sid);
}

function alertBox(text) {
  const box = $('conflicts');
  if (!box) return;
  box.innerHTML = '<div class="refusal"><b>Refused</b><span class="why"></span></div>';
  box.querySelector('.why').textContent = text;
}

async function rewind(sid, to) {
  const r = await j('/api/session/' + encodeURIComponent(sid) + '/rewind',
                    { method: 'POST', body: JSON.stringify({ to: Number(to) }) });
  if (r.error) {
    const box = $('conflicts');
    if (box) {
      box.innerHTML = '<div class="refusal"><b>Refused</b><span class="why"></span></div>';
      box.querySelector('.why').textContent = r.error;
    }
    return;
  }
  return select(sid);
}

async function savePolicy() {
  const el = $('polmsg');
  const r = await j('/api/policy', { method: 'PUT', body: $('policy').value });
  el.textContent = r.error ? ('rejected: ' + r.error) : 'sealed';
  el.className = 'polmsg ' + (r.error ? 'err' : 'ok');
  setTimeout(() => { el.textContent = ''; el.className = 'polmsg'; }, 3000);
}

// keyboard: the register is operable without a mouse
document.addEventListener('keydown', e => {
  if (e.target.id === 'blamepath' && e.key === 'Enter') return blame(e.target.value);
  if (e.target.tagName === 'TEXTAREA' || e.target.tagName === 'INPUT') return;
  if (!['j', 'k', 'ArrowDown', 'ArrowUp'].includes(e.key)) return;
  const items = [...document.querySelectorAll('.reg-item')];
  if (!items.length) return;
  const cur = items.findIndex(el => el.classList.contains('sel'));
  const step = (e.key === 'j' || e.key === 'ArrowDown') ? 1 : -1;
  const next = items[Math.min(items.length - 1, Math.max(0, cur < 0 ? 0 : cur + step))];
  if (next) { next.click(); next.focus(); e.preventDefault(); }
});

// Delegation: no inline handlers anywhere, so the CSP can forbid them outright.
document.addEventListener('click', e => {
  const b = e.target.closest('[data-select],[data-commit],[data-void],[data-rewind],'
                             + '[data-fork],[data-review],[data-blame],#seal');
  if (!b) return;
  if (b.id === 'seal') return savePolicy();
  if (b.dataset.blame !== undefined) return blame(b.dataset.blame);
  if (b.dataset.fork !== undefined) return fork(b.dataset.sid, b.dataset.fork);
  if (b.dataset.review !== undefined) return review(b.dataset.review);
  if (b.dataset.select !== undefined) return select(b.dataset.select);
  if (b.dataset.commit !== undefined) return commit(b.dataset.commit);
  if (b.dataset.void !== undefined) return rollback(b.dataset.void);
  if (b.dataset.rewind !== undefined) return rewind(b.dataset.sid, b.dataset.rewind);
});

setInterval(() => loadList(), 2500);
</script></body></html>"""


# Session ids are minted as %Y%m%d-%H%M%S plus six hex. Anything else never
# reaches the filesystem: these arrive in a URL path segment.
def _sid(raw):
    """Boundary check; core.validate_session_id is the one definition of a valid id."""
    return core.validate_session_id(raw or "")


def _esc(s):
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&#39;"))


GLYPH = {"added": "+", "modified": "~", "deleted": "\u2212", "replaced-dir": "\u00b1"}


def _grant_marks(m):
    """Capability grants only — the envelope the session ran under."""
    g = m.get("grants") or {}
    out = ""
    if g.get("jail"):
        out += '<span class="stamp grant">jail</span>'
    if g.get("net") == "none":
        out += '<span class="stamp grant">net:none</span>'
    if g.get("timeout"):
        out += f'<span class="stamp grant">timeout {_esc(g["timeout"])}s</span>'
    if g.get("merge_base"):
        out += '<span class="stamp grant">merge-base</span>'
    if m.get("agent"):
        out += f'<span class="stamp grant">agent {_esc(m["agent"])}</span>'
    return out


def _marks(m):
    """Status stamp plus the grant envelope — used in the register."""
    out = (f'<span class="stamp {_esc(m.get("status"))}">'
           f'{_esc(m.get("status"))}</span>') + _grant_marks(m)
    if m.get("timed_out"):
        out += '<span class="stamp alarm">timed-out</span>'
    return out


def _render_register(metas, sel):
    if not metas:
        return '<div class="reg-empty">No records.</div>'
    rows, rev = [], list(reversed(metas))
    for i, m in enumerate(rev):
        n = str(len(rev) - i).zfill(2)
        cls = "reg-item sel" if m["id"] == sel else "reg-item"
        cur = ' aria-current="true"' if m["id"] == sel else ""
        rows.append(
            f'<button type="button" class="{cls}" data-select="{_esc(m["id"])}"{cur}>'
            f'<span class="reg-top"><span class="reg-idx">{n}</span>'
            f'<span class="reg-sid">{_esc(m["id"])}</span></span>'
            f'<div class="reg-tgt">{_esc(m.get("target"))}</div>'
            f'<div class="reg-marks">{_marks(m)}</div></button>'
        )
    return "".join(rows)


def _render_dossier(payload):
    if payload is None:
        return ('<section class="sec"><div class="sec-label">01 &mdash; Dossier</div>'
                '<h1 class="sec-title">No record selected</h1><div class="rule"></div>'
                '<div class="empty">Choose an entry from the register.</div></section>')
    m = payload["meta"]
    prov = {r["path"]: r for r in payload["provenance"]}

    grants_html = _grant_marks(m) or '<span class="stamp">unscoped</span>'
    if m.get("timed_out"):
        grants_html += '<span class="stamp alarm">timed-out</span>'

    h = [
        '<section class="sec"><div class="sec-label">01 &mdash; Dossier</div>',
        f'<h1 class="sec-title">Session <span class="sid">{_esc(m["id"])}</span></h1>',
        '<div class="rule"></div>',
        f'<div class="cmdline">{_esc(" ".join(m.get("cmd") or [])) or "&mdash;"}</div>',
        '<div class="facts">',
        f'<div class="fact"><div class="fact-k">Target</div>'
        f'<div class="fact-v">{_esc(m.get("target"))}</div></div>',
        f'<div class="fact"><div class="fact-k">Backend</div>'
        f'<div class="fact-v">{_esc(m.get("backend"))}</div></div>',
        f'<div class="fact"><div class="fact-k">Exit</div>'
        f'<div class="fact-v">{_esc(m.get("exit_code"))}</div></div>',
        f'<div class="fact"><div class="fact-k">Opened</div>'
        f'<div class="fact-v ts">{_esc(m.get("started"))}</div></div>',
        f'<div class="fact"><div class="fact-k">Closed</div>'
        f'<div class="fact-v ts">{_esc(m.get("finished")) or "&hellip;"}</div></div>',
        _lineage_facts(m),
        '</div>',
        f'<div class="grants"><span class="grants-l">Grants</span>{grants_html}</div>',
        '</section>',
    ]

    changes = payload["changes"]
    n = len(changes)
    h += ['<section class="sec"><div class="sec-label">02 &mdash; Manifest</div>',
          f'<h2 class="sec-title">{n} line item{"" if n == 1 else "s"} held in escrow</h2>',
          '<div class="rule"></div>']
    if changes:
        rows = []
        for k, p in changes:
            r = prov.get(p, {})
            c = r.get("caused_by")
            hb = (r.get("before_sha256") or "")[:12] or "\u00b7"
            ha = (r.get("after_sha256") or "")[:12] or "\u00b7"
            cause = ""
            if c:
                summary = f' &middot; {_esc(c.get("summary"))}' if c.get("summary") else ""
                cause = (f'<div class="cause"><span class="arrow">&#8627;</span>'
                         f'turn <b>{_esc(c.get("turn"))}</b> &middot; '
                         f'<b>{_esc(c.get("tool"))}</b>{summary} '
                         f'<span class="cid">{_esc(c.get("tool_call_id"))}</span></div>')
            shown = _esc(p)
            if m.get("status") == "committed" and not p.endswith("/") and k != "deleted":
                full = os.path.join(m.get("target") or "", p)
                shown = f'<button type="button" class="linkish" data-blame="{_esc(full)}">{_esc(p)}</button>'
            rows.append(
                f'<tr class="k-{_esc(k)}">'
                f'<td class="mk k-{_esc(k)}"><span class="g">{GLYPH.get(k, "&middot;")}</span>'
                f'{_esc(k)}</td>'
                f'<td><div class="mpath">{shown}</div>{cause}</td>'
                f'<td class="hash">{hb}<span class="to">&rarr;</span>{ha}</td></tr>')
        h.append('<table class="manifest"><thead><tr>'
                 '<th class="c-kind">Disposition</th>'
                 '<th>Path &amp; attribution</th>'
                 '<th class="c-integrity">Integrity</th></tr></thead><tbody>'
                 + "".join(rows) + '</tbody></table>')
    else:
        h.append('<div class="empty">Nothing was written. The tree is as it was.</div>')
    h.append('</section>')

    h.append(_render_savepoints(m, payload.get("savepoints")))

    if m.get("status") == "pending":
        h.append(
            '<section class="sec"><div class="sec-label">04 &mdash; Disposition</div>'
            '<h2 class="sec-title">Nothing has touched the tree yet</h2>'
            '<div class="rule"></div><div class="disposition">'
            + _render_signature(m, payload.get("review")) +
            '<p class="disp-note">Committing replays this manifest onto the real tree, '
            'after verifying it has not drifted since the snapshot. Voiding discards the '
            'overlay and leaves the target byte-identical. Savepoints unticked above are '
            'dropped from the replay.</p><div class="acts">'
            f'<button class="btn btn-commit" data-commit="{_esc(m["id"])}">Commit</button>'
            f'<button class="btn btn-void" data-void="{_esc(m["id"])}">Void</button>'
            '<label class="opt"><input type="checkbox" id="merge"> merge</label>'
            '<label class="opt"><input type="checkbox" id="force"> force</label>'
            '<label class="opt"><input type="checkbox" id="countersigned"> countersigned</label>'
            '</div><div id="conflicts"></div></div></section>')
    elif m.get("status") == "committed":
        merged = len(m.get("merged_paths") or [])
        cells = (f'<div class="fact"><div class="fact-k">Committed</div>'
                 f'<div class="fact-v">{_esc(m.get("committed"))}</div></div>')
        if m.get("forced"):
            cells += ('<div class="fact"><div class="fact-k">Override</div>'
                      '<div class="fact-v">forced past drift</div></div>')
        if merged:
            cells += (f'<div class="fact"><div class="fact-k">Merged</div>'
                      f'<div class="fact-v">{merged} path(s)</div></div>')
        if m.get("layers_dropped"):
            cells += ('<div class="fact"><div class="fact-k">Dropped</div><div class="fact-v">'
                      f'savepoints {_esc(", ".join("@%s" % n for n in m["layers_dropped"]))}'
                      '</div></div>')
        rev = (m.get("reviews") or [None])[-1]
        if m.get("countersigned") and rev:
            cells += ('<div class="fact"><div class="fact-k">Countersigned</div>'
                      f'<div class="fact-v">{_esc(rev.get("reviewer"))}</div></div>')
        elif m.get("overrode_rejection") and rev:
            cells += ('<div class="fact"><div class="fact-k">Override</div>'
                      f'<div class="fact-v">forced past {_esc(rev.get("reviewer"))}\'s rejection'
                      '</div></div>')
        h.append('<section class="sec"><div class="sec-label">04 &mdash; Disposition</div>'
                 '<h2 class="sec-title">Sealed &mdash; replayed onto the tree</h2>'
                 f'<div class="rule"></div><div class="facts">{cells}</div></section>')
    return "".join(h)


def _render_savepoints(m, savepoints):
    """Section 03: the chain of decisions — one row per layer, what caused
    it, what it changed. Pending sessions can rewind to a row or untick it
    so the commit drops it; committed ones show what was applied."""
    if not savepoints:
        return ""
    pending = m.get("status") == "pending"
    dropped = set(m.get("layers_dropped") or [])
    n = len(savepoints)
    h = ['<section class="sec"><div class="sec-label">03 &mdash; Savepoints</div>',
         f'<h2 class="sec-title">{n} savepoint{"" if n == 1 else "s"} &mdash; '
         'one per command that wrote</h2>', '<div class="rule"></div>',
         '<table class="sp"><tbody>']
    for sp in savepoints:
        c = sp.get("cause") or {}
        if c:
            summary = f' &middot; {_esc(c.get("summary"))}' if c.get("summary") else ""
            what = (f'turn <b>{_esc(c.get("turn"))}</b> &middot; <b>{_esc(c.get("tool"))}</b>'
                    f'{summary} <span class="cid">{_esc(c.get("tool_call_id"))}</span>')
        elif sp.get("cmd"):
            what = _esc(" ".join(sp["cmd"]))
        else:
            what = "&mdash;"
        paths = "".join(f'<div>{GLYPH.get(k, "&middot;")} {_esc(p)}</div>' for k, p in sp["paths"])
        if not sp["paths"]:
            paths = "<div>no writes</div>"
        ctl = ""
        if pending:
            ctl = (f'<label class="opt"><input type="checkbox" checked data-keep="{sp["n"]}"> '
                   'keep</label>')
            if sp["n"] < n - 1:
                ctl += (f'<button class="btn btn-quiet" data-rewind="{sp["n"]}" '
                        f'data-sid="{_esc(m["id"])}">Rewind here</button>')
            ctl += (f'<button class="btn btn-quiet" data-fork="{sp["n"]}" '
                    f'data-sid="{_esc(m["id"])}">Fork here</button>')
        cls = "n dropped" if sp["n"] in dropped else "n"
        h.append(f'<tr><td class="{cls}">@{sp["n"]}</td>'
                 f'<td class="what">{what}<div class="paths">{paths}</div></td>'
                 f'<td class="ctl">{ctl}</td></tr>')
    h.append('</tbody></table>')
    if m.get("rewinds"):
        h.append('<p class="sp-note">' + " ".join(
            f'Rewound to @{_esc(r["to"])} at {_esc(r["at"])}, {len(r["layers"])} savepoint(s) discarded.'
            for r in m["rewinds"]) + '</p>')
    if pending:
        h.append('<p class="sp-note">Rewinding discards every savepoint above the chosen one; '
                 'an agent session\'s transcript is cut to match, so '
                 '<code>overlord resume</code> continues the model from there.</p>')
    h.append('</section>')
    return "".join(h)


def _lineage_facts(m):
    out = ""
    if m.get("forked_from"):
        f = m["forked_from"]
        out += ('<div class="fact"><div class="fact-k">Forked from</div><div class="fact-v">'
                f'<button type="button" class="linkish" data-select="{_esc(f["session"])}">'
                f'{_esc(f["session"])}</button> @{_esc(f["at"])}</div></div>')
    if m.get("forks"):
        links = " ".join(
            f'<button type="button" class="linkish" data-select="{_esc(f["session"])}">'
            f'{_esc(f["session"])}</button> @{_esc(f["at"])}' for f in m["forks"])
        out += f'<div class="fact"><div class="fact-k">Forks</div><div class="fact-v">{links}</div></div>'
    return out


def _render_signature(m, review):
    """The countersignature block inside a pending disposition: the latest
    verdict, whether it still binds to this diff, and the means to ask."""
    h = ['<div class="sig"><div class="sig-l">Countersignature</div>']
    rev = (review or {}).get("record")
    if rev:
        fresh = (review or {}).get("fresh")
        verdict = rev.get("verdict")
        cls = verdict if verdict in ("approve", "reject") else ""
        label = {"approve": "approved", "reject": "rejected"}.get(verdict, "no verdict")
        h.append(f'<span class="stamp {cls}{"" if fresh else " stale"}">{label}</span>')
        if not fresh:
            h.append('<span class="stamp">stale &mdash; diff changed since</span>')
        if rev.get("same_model"):
            h.append('<span class="stamp alarm">same model as agent</span>')
        if rev.get("reason"):
            h.append(f'<div class="reason">{_esc(rev["reason"])}</div>')
        h.append(f'<div class="who">{_esc(rev.get("reviewer"))} &middot; {_esc(rev.get("ts"))}</div>')
    else:
        h.append('<span class="stamp">unsigned</span>')
    h.append('<div class="req">'
             '<select id="rev-provider"><option value="anthropic">anthropic</option>'
             '<option value="openai">openai</option></select>'
             '<input type="text" id="rev-model" placeholder="model (default)">'
             f'<button class="btn btn-quiet" data-review="{_esc(m["id"])}">Request countersignature</button>'
             '<span id="sig-status" class="polmsg"></span></div></div>')
    return "".join(h)


def _render_blame(res):
    """A blame sheet: the recorded versions of a file and who owns each line."""
    h = ['<section class="sec"><div class="sec-label">06 &mdash; Blame</div>',
         f'<h1 class="sec-title">{_esc(os.path.basename(res["path"]))}</h1>',
         '<div class="rule"></div>',
         f'<div class="cmdline">{_esc(res["path"])}</div>']
    vs = res.get("versions") or []
    if not vs:
        h.append('<div class="empty" style="margin-top:18px">No committed session recorded this path.</div>')
        h.append('</section>')
        return "".join(h)
    state = {"current": "content matches the last commit",
             "drifted": "content changed outside OVERLORD since the last commit",
             "deleted": "deleted by the last commit",
             "recreated-outside": "deleted by the last commit, recreated outside"}.get(
                 res.get("state"), res.get("state"))
    h.append(f'<p class="disp-note" style="margin-top:18px">{len(vs)} recorded version(s) &mdash; '
             f'{_esc(state)}</p>')
    h.append('<div class="legend">')
    for i, v in enumerate(vs):
        c = v.get("cause") or {}
        cause = ""
        if c:
            cause = (f'<div class="cause"><span class="arrow">&#8627;</span>turn <b>{_esc(c.get("turn"))}</b>'
                     f' &middot; <b>{_esc(c.get("tool"))}</b> &middot; {_esc(c.get("summary"))}</div>')
        task = f'<div class="task">{_esc(v["task"])}</div>' if v.get("task") else ""
        said = f'<div class="said">&ldquo;{_esc(" ".join((v.get("said") or "").split())[:240])}&rdquo;</div>'             if v.get("said") else ""
        h.append(f'<div class="v"><span class="k own-{i % 6}">[{i}]</span>'
                 f'<button type="button" class="linkish" data-select="{_esc(v["sid"])}">{_esc(v["sid"])}</button>'
                 f' &middot; {_esc(v.get("committed"))} &middot; {_esc(v.get("agent") or "command")}'
                 f' &middot; {_esc(v.get("kind"))}{task}{cause}{said}</div>')
    h.append('</div>')
    lines = res.get("lines")
    if lines is None:
        h.append(f'<div class="empty">{_esc(res.get("lines_note") or "line attribution unavailable")}</div>')
    else:
        rows = []
        for ln in lines:
            o = ln["owner"]
            if isinstance(o, int):
                c = (vs[o].get("cause") or {})
                tag = f'[{o}] t{c.get("turn")} {c.get("tool")}' if c else f'[{o}]'
                cls = f"own-{o % 6}"
            else:
                tag, cls = o, f"own-{o}"
            rows.append(f'<tr><td class="ln">{ln["n"]}</td><td class="own {cls}">{_esc(tag)}</td>'
                        f'<td class="code">{_esc(ln["text"])}</td></tr>')
        h.append('<table class="bl"><tbody>' + "".join(rows) + '</tbody></table>')
    h.append('</section>')
    return "".join(h)


def _render_refusal(result):
    """Drift refusal, rendered here so the client never builds markup."""
    rows = "<br>".join(f'{_esc(why)} &middot; {_esc(path)}'
                       for why, path in result.get("conflicts") or [])
    return ('<div class="refusal"><b>Target drifted &mdash; refusing</b>'
            f'<div class="why">{rows}</div>'
            '<div class="hint">Retry with merge (needs &mdash;merge-base), '
            'or force past it deliberately.</div></div>')


def _session_payload(sid):
    sid = core.validate_session_id(sid)
    meta = core.load_meta(sid)
    upper = core.session_file(sid, "upper")
    live = os.path.isdir(upper)
    changes = core.session_stack(sid, meta)[0] if live else []
    prov_path = core.session_file(sid, core.PROVENANCE_FILE)
    provenance = []
    if os.path.isfile(prov_path):
        with open(prov_path) as f:
            provenance = [json.loads(line) for line in f]
    if not changes and provenance:  # committed sessions: show from the record
        changes = [[r["kind"], r["path"]] for r in provenance]
    savepoints = []
    if live:
        savepoints = core.session_savepoints(sid, meta)
    elif meta.get("layers"):
        # layers are gone after commit; the record still says what each did
        by_layer = {}
        for r in provenance:
            if "layer" in r:
                by_layer.setdefault(r["layer"], []).append([r["kind"], r["path"]])
        savepoints = [{"n": i, "cause": l.get("cause"), "cmd": l.get("cmd"),
                       "label": l.get("label"), "started": l.get("started"),
                       "paths": by_layer.get(i, [])} for i, l in enumerate(meta["layers"])]
    review = None
    if meta.get("reviews"):
        rec, fresh = (meta["reviews"][-1], False)
        if live:
            import review as review_mod
            rec, fresh = review_mod.review_state(sid, meta)
        review = {"record": rec, "fresh": fresh}
    return {"meta": meta, "changes": changes, "provenance": provenance,
            "savepoints": savepoints, "review": review}


def _build_page(status, register_html, dossier_html, policy_text, sel, nonce):
    """Token substitution, not str.format — the CSS and JS are full of braces."""
    page = SHELL
    for token, value in (("__CSS__", CSS),
                         ("__STATUS__", status),
                         ("__REGISTER__", register_html),
                         ("__DOSSIER__", dossier_html),
                         ("__POLICY__", policy_text),
                         ("__SEL__", sel),
                         ("__NONCE__", nonce)):
        page = page.replace(token, value)
    return page


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    # --- browser-facing hardening -------------------------------------
    #
    # This server binds loopback and has no auth, which is not the same as
    # being unreachable: any page the user happens to be visiting can send it
    # a cross-origin request, and a simple request needs no CORS preflight to
    # arrive. Without the checks below, a drive-by page could POST a commit
    # and apply an agent's pending changes to the real tree — the one thing
    # the whole design exists to keep under human control. So:
    #   * Host must be loopback, which is what stops DNS rebinding turning
    #     an attacker's domain into a same-origin path to this port;
    #   * a cross-origin state-changing request is refused outright.

    def _own_origins(self):
        port = self.server.server_address[1]
        return {f"http://127.0.0.1:{port}", f"http://localhost:{port}",
                f"http://[::1]:{port}"}

    def _host_ok(self):
        host = (self.headers.get("Host") or "").strip()
        port = self.server.server_address[1]
        return host in {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    def _origin_ok(self):
        """State-changing requests must not come from another origin."""
        origin = self.headers.get("Origin")
        if origin is not None and origin != "null" and origin not in self._own_origins():
            return False
        site = self.headers.get("Sec-Fetch-Site")
        return site in (None, "same-origin", "none")

    def _guard(self, state_changing):
        if not self._host_ok():
            self._send({"error": "bad host header"}, 421)
            return False
        if state_changing and not self._origin_ok():
            self._send({"error": "cross-origin request refused"}, 403)
            return False
        return True

    def _send(self, obj, code=200, raw=None, ctype="application/json", nonce=None):
        body = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if nonce:
            # Nothing loads off-origin; the two inline blocks carry the nonce,
            # so injected markup cannot execute even if escaping were wrong.
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; "
                             f"style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; "
                             "img-src data:; connect-src 'self'; "
                             "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _views(self, sel):
        """Server-rendered fragments: register + status line."""
        metas = [core.load_meta(s) for s in core.list_sessions()]
        backend = core.detect_backend() or "none"
        return {"status": f"{_esc(backend)} backend &middot; {len(metas)} records",
                "register": _render_register(metas, sel)}

    def do_GET(self):
        try:
            if not self._guard(state_changing=False):
                return
            parsed = urlparse(self.path)
            path, query = parsed.path, parse_qs(parsed.query)
            if path == "/":
                nonce = secrets.token_urlsafe(16)
                self._send(None, raw=chatui.chat_shell(nonce).encode(),
                           ctype="text/html; charset=utf-8", nonce=nonce)
                return
            if chatui.handle_get(self, path, query):
                return
            if path == "/api/view":
                self._send(self._views((query.get("sel") or [None])[0] or None))
                return
            if path == "/api/view/blame":
                res = core.blame_path((query.get("path") or [""])[0])
                self._send({"dossier": '<div class="sheet">' + _render_blame(res) + "</div>"})
                return
            if path == "/api/blame":
                self._send(core.blame_path((query.get("path") or [""])[0]))
                return
            if path.startswith("/api/view/session/"):
                sid = _sid(path.rsplit("/", 1)[-1])
                self._send({"dossier": '<div class="sheet">'
                            + _render_dossier(_session_payload(sid)) + "</div>"})
                return
            if path == "/console":
                metas = [core.load_meta(s) for s in core.list_sessions()]
                pending = [m for m in metas if m.get("status") == "pending"]
                sel = pending[-1]["id"] if pending else None
                policy_text = ""
                if os.path.isfile(core.POLICY_FILE):
                    with open(core.POLICY_FILE) as f:
                        policy_text = f.read()
                views = self._views(sel)
                nonce = secrets.token_urlsafe(16)
                page = _build_page(
                    status=views["status"],
                    register_html=views["register"],
                    dossier_html=_render_dossier(
                        _session_payload(sel) if sel else None),
                    policy_text=_esc(policy_text),
                    sel=json.dumps(sel),
                    nonce=nonce,
                )
                self._send(None, raw=page.encode(), ctype="text/html; charset=utf-8",
                           nonce=nonce)
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
                self._send(_session_payload(_sid(parsed.path.rsplit("/", 1)[-1])))
            else:
                self._send({"error": "not found"}, 404)
        except (core.OverlordError, SystemExit) as e:
            self._send({"error": str(e)}, 400)
        except Exception as e:
            self._send({"error": f"{type(e).__name__}: {e}"}, 500)

    def do_POST(self):
        try:
            if not self._guard(state_changing=True):
                return
            parts = self.path.strip("/").split("/")
            if parts[:2] == ["api", "chats"]:
                if chatui.handle_post(self, parts, self._body()):
                    return
                self._send({"error": "not found"}, 404)
                return
            if len(parts) == 4 and parts[:2] == ["api", "session"]:
                sid, action = _sid(parts[2]), parts[3]
                req = self._body()
                if action == "commit":
                    result = core.commit_session(
                        sid, merge=bool(req.get("merge")), force=bool(req.get("force")),
                        only=req.get("only") or None, drop=req.get("drop") or None,
                        countersigned=bool(req.get("countersigned")))
                    if not result.get("committed"):
                        result["conflicts_html"] = _render_refusal(result)
                    self._send(result)
                elif action == "rollback":
                    self._send({"target": core.rollback_session(sid)})
                elif action == "rewind":
                    to = req.get("to")
                    if not isinstance(to, int) or isinstance(to, bool):
                        raise core.OverlordError("error: rewind needs an integer savepoint")
                    self._send({"to": to, "changes": core.rewind_session(sid, to)})
                elif action == "fork":
                    at = req.get("at")
                    if at is not None and (not isinstance(at, int) or isinstance(at, bool)):
                        raise core.OverlordError("error: fork needs an integer savepoint")
                    self._send({"sid": core.fork_session(sid, at)})
                elif action == "review":
                    import agent as agent_mod
                    import review as review_mod
                    provider = agent_mod.make_provider(
                        str(req.get("provider") or "anthropic"), req.get("model") or None,
                        script_env=review_mod.SCRIPT_ENV)
                    rec = review_mod.run_review(sid, provider,
                                                allow_same=bool(req.get("same_model")))
                    self._send({"review": rec})
                else:
                    self._send({"error": "unknown action"}, 404)
            else:
                self._send({"error": "not found"}, 404)
        except (core.OverlordError, SystemExit) as e:
            self._send({"error": str(e)}, 400)
        except Exception as e:
            self._send({"error": f"{type(e).__name__}: {e}"}, 500)

    def do_PUT(self):
        try:
            if not self._guard(state_changing=True):
                return
            if self.path == "/api/settings":
                n = int(self.headers.get("Content-Length") or 0)
                chatui.handle_put(self, self.path, self.rfile.read(n).decode())
                return
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
        except (core.OverlordError, SystemExit) as e:
            self._send({"error": str(e)}, 400)
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
