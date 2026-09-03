/**
 * Single-file HTML report.
 *
 * Constraints that shaped this: one file, no external assets, no network, no
 * server. It has to open from `file://` on a machine with no internet, because
 * that is where a CI artifact gets read. Everything -- CSS, JS, data -- is
 * inlined, and the whole thing stays comfortably under 2 MB for a normal run.
 */
import { LIMITATIONS } from '../analyze.js';

const SEVERITY_ORDER = ['will-break', 'may-break', 'info'];

const SEVERITY_COPY = {
  'will-break': {
    label: 'Will break',
    blurb:
      'Behaves differently on a real HTTPS origin, and the difference is defined by a specification or by shipped browser behaviour.',
  },
  'may-break': {
    label: 'May break',
    blurb: 'Depends on something not visible from here: your deployment topology, your proxy, or your production configuration.',
  },
  info: { label: 'Info', blurb: 'Worth knowing. Not a defect.' },
};

/**
 * @param {object} result The analyze() document.
 * @returns {string} Complete HTML document.
 */
export function renderHtml(result) {
  const counts = result.counts;
  const total = counts['will-break'] + counts['may-break'] + counts.info;
  const generated = new Date(result.finishedAt);

  return `<!doctype html>
<html lang="en" data-theme="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>notlocalhost - ${esc(result.target.url)}</title>
<style>${STYLE}</style>
</head>
<body>
<a class="skip" href="#findings">Skip to findings</a>
<header class="masthead">
  <div class="wrap">
    <div class="brand">
      <span class="mark">notlocalhost</span>
      <span class="ver">v${esc(result.tool.version)}</span>
    </div>
    <h1>Your localhost is lying to you.<span class="sub">Here is exactly how.</span></h1>
    <p class="target"><code>${esc(result.target.url)}</code>${
      result.target.status ? ` <span class="pill">HTTP ${esc(result.target.status)}</span>` : ''
    }</p>
    <div class="scoreboard">
      ${scoreCard('will-break', counts['will-break'])}
      ${scoreCard('may-break', counts['may-break'])}
      ${scoreCard('info', counts.info)}
    </div>
    ${
      counts['will-break'] === 0 && counts['may-break'] === 0
        ? `<p class="clean">No will-break or may-break findings in what was exercised. That is not the same as safe &mdash; see <a href="#limitations">what this does not tell you</a>.</p>`
        : ''
    }
  </div>
</header>

<main class="wrap">

<section class="panel" aria-labelledby="run-h">
  <h2 id="run-h">The run</h2>
  <dl class="kv">
    <dt>Target</dt><dd><code>${esc(result.target.finalUrl)}</code></dd>
    <dt>Browser</dt><dd>${esc(result.browser.name ?? 'unknown')} ${esc(result.browser.version ?? '')}</dd>
    <dt>Started</dt><dd>${esc(new Date(result.startedAt).toLocaleString())}</dd>
    <dt>Duration</dt><dd>${esc(fmtMs(result.coverage.timing?.totalMs))}</dd>
    <dt>Login flow</dt><dd>${flowCell(result.coverage.flow)}</dd>
    <dt>Requests seen</dt><dd>${esc(result.coverage.requests)}</dd>
    <dt><code>Set-Cookie</code> seen</dt><dd>${esc(result.coverage.cookiesObserved)}</dd>
    <dt>Bytes scanned</dt><dd>${esc(fmtBytes(result.coverage.bytesScanned))} across ${esc(result.coverage.bodiesScanned)} responses</dd>
    <dt>Other loopback listeners</dt><dd>${
      result.coverage.portScanSkipped
        ? '<span class="muted">not probed</span>'
        : result.coverage.otherLoopbackListeners.length
          ? result.coverage.otherLoopbackListeners.map((p) => `<code>127.0.0.1:${esc(p)}</code>`).join(' ')
          : '<span class="muted">none found on the common dev ports</span>'
    }</dd>
  </dl>
</section>

<section class="panel model" aria-labelledby="model-h">
  <h2 id="model-h">The assumption everything below rests on</h2>
  <p>${esc(result.deploymentModel.description)}</p>
  ${
    Object.keys(result.deploymentModel.mapping).length
      ? `<table class="map"><thead><tr><th>Local origin</th><th></th><th>Assumed deployed origin</th></tr></thead><tbody>${Object.entries(
          result.deploymentModel.mapping,
        )
          .map(
            ([from, to]) =>
              `<tr><td><code>${esc(from)}</code></td><td class="arrow">&rarr;</td><td><code>https://${esc(to)}</code></td></tr>`,
          )
          .join('')}</tbody></table>`
      : '<p class="muted">No local origins were mapped during this run.</p>'
  }
  <p class="muted">Change it with <code>--domain</code>, <code>--map local=host</code> and <code>--cross-site</code>.</p>
</section>

${
  result.warnings.length
    ? `<section class="panel warn" aria-labelledby="warn-h">
  <h2 id="warn-h">Warnings from this run</h2>
  <ul>${result.warnings.map((w) => `<li><pre>${esc(w)}</pre></li>`).join('')}</ul>
</section>`
    : ''
}

<section id="findings" aria-labelledby="findings-h">
  <div class="findings-head">
    <h2 id="findings-h">Findings <span class="muted">(${esc(total)})</span></h2>
    <div class="filters" role="group" aria-label="Filter findings by severity">
      ${SEVERITY_ORDER.map(
        (s) =>
          `<button class="filter on" data-sev="${s}" aria-pressed="true"><i class="dot ${s}"></i>${esc(
            SEVERITY_COPY[s].label,
          )} <span class="n">${esc(counts[s])}</span></button>`,
      ).join('')}
      <input type="search" id="q" placeholder="Filter text&hellip;" aria-label="Filter findings by text">
    </div>
  </div>

  ${SEVERITY_ORDER.map((sev) => renderGroup(sev, result.findings.filter((f) => f.severity === sev))).join('')}
  <p class="empty" hidden>Nothing matches those filters.</p>
</section>

<section class="panel" id="limitations" aria-labelledby="lim-h">
  <h2 id="lim-h">What this does not tell you</h2>
  <p>Written before launch, and kept honest on purpose. A tool that overstates its reach is worse than no tool.</p>
  <ul class="limits">${(result.limitations ?? LIMITATIONS).map((l) => `<li>${esc(l)}</li>`).join('')}</ul>
</section>

<footer>
  <p>Generated ${esc(generated.toLocaleString())} by notlocalhost v${esc(result.tool.version)} &middot;
  schema v${esc(result.schemaVersion)} &middot; no telemetry, no network calls, one file.</p>
</footer>
</main>

<script id="data" type="application/json">${jsonForScript(result)}</script>
<script>${SCRIPT}</script>
</body>
</html>`;
}

function renderGroup(severity, findings) {
  if (!findings.length) return '';
  const copy = SEVERITY_COPY[severity];
  return `<div class="group" data-sev="${severity}">
  <div class="group-head">
    <h3><i class="dot ${severity}"></i>${esc(copy.label)}</h3>
    <p class="muted">${esc(copy.blurb)}</p>
  </div>
  ${findings.map((f, i) => renderFinding(f, `${severity}-${i}`)).join('')}
</div>`;
}

function renderFinding(f, domId) {
  return `<article class="finding ${f.severity}" id="f-${esc(domId)}" data-sev="${f.severity}" data-text="${esc(
    `${f.id} ${f.title} ${f.summary} ${f.evidence.map((e) => `${e.label} ${e.value}`).join(' ')}`.toLowerCase(),
  )}">
  <header>
    <h4>${esc(f.title)}</h4>
    <code class="rule">${esc(f.id)}</code>
  </header>
  <div class="summary">${f.summary.split('\n\n').map((p) => `<p>${esc(p)}</p>`).join('')}</div>
  ${
    f.evidence.length
      ? `<details open><summary>Evidence <span class="n">${esc(f.evidence.length)}</span></summary>
    <table class="evidence"><tbody>${f.evidence
      .map((e) => `<tr><th scope="row">${esc(e.label)}</th><td><pre>${esc(e.value)}</pre></td></tr>`)
      .join('')}</tbody></table></details>`
      : ''
  }
  ${
    f.fix.length
      ? `<details open class="fix"><summary>Fix</summary><ol>${f.fix.map((s) => `<li>${esc(s)}</li>`).join('')}</ol></details>`
      : ''
  }
  ${
    f.refs.length
      ? `<p class="refs">${f.refs
          .map((r) => `<a href="${esc(r.url)}" rel="noreferrer noopener" target="_blank">${esc(r.title)}</a>`)
          .join('')}</p>`
      : ''
  }
</article>`;
}

function scoreCard(severity, n) {
  return `<div class="score ${severity}${n ? '' : ' zero'}">
    <span class="n">${esc(n)}</span>
    <span class="l">${esc(SEVERITY_COPY[severity].label)}</span>
  </div>`;
}

function flowCell(flow) {
  if (!flow) {
    return '<span class="warnflag">none &mdash; only the logged-out page was exercised. The interesting cookies appear after login; pass <code>--flow</code>.</span>';
  }
  if (!flow.ok) return `<span class="warnflag">${esc(flow.path)} failed: ${esc(flow.error ?? 'unknown error')}</span>`;
  return `<code>${esc(flow.path)}</code> ran successfully`;
}

// ---------------------------------------------------------------------------

/** HTML-escape. Everything user-controlled goes through this. */
function esc(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Embed JSON in a <script> without letting a `</script>` inside a captured
 * cookie value or bundle snippet close the tag and turn the report into an
 * XSS vector for whoever opens it.
 */
function jsonForScript(obj) {
  return JSON.stringify(obj)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function fmtBytes(n) {
  if (!n) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function fmtMs(ms) {
  if (ms == null) return 'unknown';
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

// ---------------------------------------------------------------------------

const STYLE = `
:root{
  --bg:#fbfaf8; --panel:#ffffff; --ink:#16151a; --muted:#6b6a75; --line:#e6e3dd;
  --will:#c02a2a; --may:#a86a00; --info:#2b6ca3;
  --will-bg:#fdf0ef; --may-bg:#fdf6e8; --info-bg:#eef5fb;
  --accent:#16151a; --code-bg:#f4f2ee;
  --radius:10px;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#111114; --panel:#18181c; --ink:#eceaf2; --muted:#9a98a5; --line:#2a2a31;
    --will:#ff7b72; --may:#e3b341; --info:#79c0ff;
    --will-bg:#2a1719; --may-bg:#2a2317; --info-bg:#16222e;
    --accent:#eceaf2; --code-bg:#1f1f25;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:980px;margin:0 auto;padding:0 24px}
.skip{position:absolute;left:-9999px}
.skip:focus{left:8px;top:8px;background:var(--panel);padding:8px;z-index:10}
code,pre{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;font-size:.86em}
code{background:var(--code-bg);padding:.12em .38em;border-radius:4px;word-break:break-word}
pre{margin:0;white-space:pre-wrap;word-break:break-word;background:none;padding:0}
a{color:inherit;text-decoration:underline;text-underline-offset:2px;text-decoration-color:var(--line)}
a:hover{text-decoration-color:currentColor}
.muted{color:var(--muted)}

.masthead{border-bottom:1px solid var(--line);padding:40px 0 32px;background:var(--panel)}
.brand{display:flex;align-items:baseline;gap:8px;margin-bottom:22px}
.mark{font-weight:700;letter-spacing:-.02em}
.ver{color:var(--muted);font-size:12px}
.masthead h1{font-size:30px;line-height:1.22;letter-spacing:-.022em;margin:0 0 12px;font-weight:650;max-width:22ch}
.masthead h1 .sub{display:block;color:var(--muted);font-weight:450}
.target{margin:0 0 24px}
.pill{display:inline-block;border:1px solid var(--line);border-radius:99px;padding:1px 8px;font-size:12px;color:var(--muted)}
.scoreboard{display:flex;gap:12px;flex-wrap:wrap}
.score{border:1px solid var(--line);border-radius:var(--radius);padding:12px 18px;min-width:120px;background:var(--bg)}
.score .n{display:block;font-size:26px;font-weight:650;letter-spacing:-.02em;line-height:1.1}
.score .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em}
.score.will-break{background:var(--will-bg);border-color:color-mix(in srgb,var(--will) 30%,var(--line))}
.score.will-break .n{color:var(--will)}
.score.may-break{background:var(--may-bg);border-color:color-mix(in srgb,var(--may) 30%,var(--line))}
.score.may-break .n{color:var(--may)}
.score.info{background:var(--info-bg);border-color:color-mix(in srgb,var(--info) 30%,var(--line))}
.score.info .n{color:var(--info)}
.score.zero{background:var(--bg);border-color:var(--line);opacity:.55}
.score.zero .n{color:var(--muted)}
.clean{margin:22px 0 0;padding:12px 16px;border-left:3px solid var(--info);background:var(--info-bg);border-radius:0 6px 6px 0}

main{padding:32px 0 64px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:22px 24px;margin:0 0 22px}
.panel h2{font-size:15px;margin:0 0 14px;letter-spacing:-.01em}
.panel.warn{border-color:color-mix(in srgb,var(--may) 40%,var(--line));background:var(--may-bg)}
.panel.warn ul{margin:0;padding-left:20px}
.kv{display:grid;grid-template-columns:minmax(140px,auto) 1fr;gap:6px 20px;margin:0}
.kv dt{color:var(--muted);font-size:13px}
.kv dd{margin:0}
.warnflag{color:var(--may)}
table.map{border-collapse:collapse;margin:10px 0}
table.map th{text-align:left;font-size:12px;color:var(--muted);font-weight:500;padding:2px 14px 6px 0}
table.map td{padding:2px 14px 2px 0;vertical-align:top}
table.map .arrow{color:var(--muted)}

.findings-head{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin:34px 0 16px}
.findings-head h2{font-size:19px;margin:0;letter-spacing:-.015em}
.filters{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.filter{font:inherit;font-size:12px;background:var(--panel);color:var(--ink);border:1px solid var(--line);
  border-radius:99px;padding:5px 12px;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
.filter[aria-pressed="false"]{opacity:.42}
.filter .n{color:var(--muted)}
#q{font:inherit;font-size:13px;padding:5px 11px;border:1px solid var(--line);border-radius:99px;
  background:var(--panel);color:var(--ink);min-width:170px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex:0 0 auto}
.dot.will-break{background:var(--will)}
.dot.may-break{background:var(--may)}
.dot.info{background:var(--info)}

.group{margin:0 0 30px}
.group-head{margin:0 0 12px}
.group-head h3{font-size:13px;text-transform:uppercase;letter-spacing:.08em;margin:0 0 3px;
  display:flex;align-items:center;gap:8px}
.group-head p{margin:0;font-size:13px;max-width:74ch}

.finding{background:var(--panel);border:1px solid var(--line);border-left-width:3px;
  border-radius:var(--radius);padding:18px 20px;margin:0 0 12px}
.finding.will-break{border-left-color:var(--will)}
.finding.may-break{border-left-color:var(--may)}
.finding.info{border-left-color:var(--info)}
.finding>header{display:flex;justify-content:space-between;gap:14px;align-items:baseline;flex-wrap:wrap;margin-bottom:8px}
.finding h4{font-size:15.5px;margin:0;letter-spacing:-.01em;line-height:1.4;flex:1 1 340px}
.rule{color:var(--muted);font-size:11.5px;background:none;padding:0}
.summary p{margin:0 0 10px;max-width:78ch}
details{margin:8px 0 0;border-top:1px solid var(--line);padding-top:8px}
summary{cursor:pointer;font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}
summary .n{text-transform:none;letter-spacing:0}
table.evidence{border-collapse:collapse;width:100%;margin-top:8px}
table.evidence th{text-align:left;vertical-align:top;font-weight:500;color:var(--muted);
  padding:3px 14px 3px 0;white-space:nowrap;font-size:12.5px}
table.evidence td{vertical-align:top;padding:3px 0;font-size:12.5px}
.fix ol{margin:8px 0 0;padding-left:20px}
.fix li{margin:0 0 5px;max-width:78ch}
.refs{margin:10px 0 0;display:flex;gap:14px;flex-wrap:wrap;font-size:12px}
.refs a{color:var(--muted)}
.limits{margin:0;padding-left:20px}
.limits li{margin:0 0 7px;max-width:80ch}
.empty{text-align:center;color:var(--muted);padding:36px 0}
footer{border-top:1px solid var(--line);margin-top:40px;padding-top:18px;color:var(--muted);font-size:12.5px}
@media print{
  .filters,.skip{display:none}
  .finding,.panel{break-inside:avoid;border-left-width:1px}
  details{display:block}
  details>*{display:revert}
}
@media (max-width:640px){
  .kv{grid-template-columns:1fr}
  .kv dt{margin-top:8px}
  .masthead h1{font-size:24px}
}
`;

const SCRIPT = `
(function(){
  var active = {'will-break':true,'may-break':true,'info':true};
  var q = document.getElementById('q');
  var empty = document.querySelector('.empty');

  function apply(){
    var term = (q.value||'').trim().toLowerCase();
    var shown = 0;
    document.querySelectorAll('.finding').forEach(function(el){
      var sev = el.dataset.sev;
      var ok = active[sev] && (!term || el.dataset.text.indexOf(term) !== -1);
      el.hidden = !ok;
      if (ok) shown++;
    });
    document.querySelectorAll('.group').forEach(function(g){
      g.hidden = !g.querySelector('.finding:not([hidden])');
    });
    empty.hidden = shown !== 0;
  }

  document.querySelectorAll('.filter').forEach(function(b){
    b.addEventListener('click', function(){
      var sev = b.dataset.sev;
      active[sev] = !active[sev];
      b.setAttribute('aria-pressed', String(active[sev]));
      apply();
    });
  });
  q.addEventListener('input', apply);

  // Deep-link to a finding: #f-will-break-0
  if (location.hash) {
    var el = document.querySelector(location.hash);
    if (el) el.scrollIntoView();
  }
})();
`;

export const _internal = { esc, jsonForScript };
