import fs from 'node:fs';
import path from 'node:path';

const SEV_COLOR = { critical: '#b3261e', high: '#d4550a', medium: '#b58900', low: '#1a73e8', info: '#5f6368' };
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export function renderHtml(report) {
  const counts = report.summary.counts;
  const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const cards = sevOrder.map((s) => `
    <div class="card" style="border-top-color:${SEV_COLOR[s]}">
      <div class="num" style="color:${SEV_COLOR[s]}">${counts[s] ?? 0}</div>
      <div class="lbl">${s}</div>
    </div>`).join('');
  const rows = report.findings.map((f) => `
    <tr>
      <td data-label="Severity"><span class="badge" style="background:${SEV_COLOR[f.severity]}">${f.severity}</span></td>
      <td data-label="Finding"><strong>${esc(f.title)}</strong><div class="id">${esc(f.id)} · ${esc(f.category)}</div></td>
      <td data-label="Evidence (confirmed)">${Object.entries(f.evidence).map(([k, v]) => String(v).includes('\n')
        ? `<div><span class="ek">${esc(k)}</span><details class="evdet"><summary>Show / hide</summary><pre class="evpre">${esc(v)}</pre></details></div>`
        : `<div><span class="ek">${esc(k)}</span>: ${esc(v)}</div>`).join('')}${f.unverified ? `<div class="unv">Not verified: ${esc(f.unverified)}</div>` : ''}</td>
      <td data-label="Risk">${esc(f.risk)}</td>
      <td data-label="Recommendation">${esc(f.recommendation)}${f.verify ? `<div class="unv">Verify: ${esc(f.verify)}</div>` : ''}</td>
    </tr>`).join('');
  const exposure = report.exposure_map.map((e) => `
    <div class="expo">
      <div class="expo-h">${esc(e.area)} <span class="expo-n" style="background:${e.max ? SEV_COLOR[e.max] : '#9aa0a6'}">${e.count} finding${e.count === 1 ? '' : 's'}</span></div>
      <div class="expo-b">${esc(e.summary)}</div>
    </div>`).join('');
  const steps = report.next_steps.map((s) => `<li>${esc(s)}</li>`).join('');
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Container Security Inspector - audit report</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, 'Segoe UI', Roboto, Arial, sans-serif; margin: 0; background: #f6f7f9; color: #202124; }
  header { background: #0b2545; color: #fff; padding: 38px 32px 30px; }
  header h1 { margin: 0 0 6px; font-size: 22px; }
  header .sub { opacity: .85; font-size: 13px; }
  main { padding: 24px 32px 48px; max-width: 1280px; margin: 0 auto; }
  .cards { display: flex; gap: 12px; margin: 20px 0 28px; flex-wrap: wrap; }
  .card { background: #fff; border: 1px solid #e0e3e7; border-top: 4px solid #ccc; border-radius: 8px; padding: 12px 20px; min-width: 110px; }
  .card .num { font-size: 28px; font-weight: 700; }
  .card .lbl { text-transform: uppercase; font-size: 11px; letter-spacing: .08em; color: #5f6368; }
  h2 { font-size: 16px; margin: 28px 0 12px; }
  .expo-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(330px, 1fr)); gap: 12px; }
  .expo { background: #fff; border: 1px solid #e0e3e7; border-radius: 8px; padding: 14px 16px; }
  .expo-h { font-weight: 600; margin-bottom: 6px; }
  .expo-n { color: #fff; font-size: 11px; border-radius: 10px; padding: 2px 8px; font-weight: 600; }
  .expo-b { font-size: 13px; color: #444; }
  table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e0e3e7; border-radius: 8px; overflow: hidden; }
  table { table-layout: fixed; }
  col.c-sev { width: 104px; } col.c-find { width: 240px; } col.c-ev { width: 27%; }
  th, td { text-align: left; vertical-align: top; padding: 10px 12px; font-size: 13px; border-bottom: 1px solid #eceef1; word-break: break-word; overflow-wrap: anywhere; }
  th { background: #f0f2f5; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: #5f6368; }
  .badge { color: #fff; white-space: nowrap; display: inline-block; border-radius: 10px; padding: 3px 10px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
  .id { color: #5f6368; font-size: 12px; margin-top: 3px; }
  .ek { color: #5f6368; font-family: ui-monospace, monospace; font-size: 12px; }
  .unv { margin-top: 6px; color: #7a5c00; font-size: 12px; }
  .evdet { margin: 4px 0 2px; }
  .evdet > summary { cursor: pointer; list-style: none; display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: #1a73e8; user-select: none; }
  .evdet > summary::before { content: '\u{1F441}'; } /* eye: values hidden by default */
  .evdet[open] > summary::before { content: '\u{1F441}'; opacity: .45; }
  .evdet > summary::-webkit-details-marker { display: none; }
  .evdet > summary::after { content: 'hidden by default - visual concealment only, not encryption'; font-size: 10.5px; color: #9aa0a6; }
  .evdet[open] > summary::after { content: none; }
  .evpre { white-space: pre-wrap; word-break: break-word; overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; line-height: 1.45; background: #f6f8fa; border: 1px solid #e0e3e7; border-radius: 6px; padding: 8px 10px; margin: 4px 0 2px; }
  @media print {
    body { background: #fff; }
    table, thead, tbody, tr, td { display: block; width: 100%; }
    thead { display: none; }
    colgroup { display: none; }
    tr { border: 1px solid #d7dbe0; border-radius: 8px; margin-bottom: 12px; padding: 8px 4px; break-inside: avoid; page-break-inside: avoid; }
    td { border-bottom: none; padding: 6px 12px; }
    td::before { content: attr(data-label); display: block; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: #5f6368; margin-bottom: 2px; }
    .expo, .card, .meta, .caveat { break-inside: avoid; page-break-inside: avoid; }
  }
  @media (max-width: 700px) {
    main { padding: 16px 12px 40px; }
    header { padding: 48px 16px 26px; }
    table, thead, tbody, tr, td { display: block; width: 100%; }
    thead { display: none; }
    colgroup { display: none; }
    tr { border-bottom: 2px solid #d7dbe0; padding: 8px 0; }
    td { border-bottom: none; padding: 6px 12px; }
    td::before { content: attr(data-label); display: block; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: #5f6368; margin-bottom: 2px; }
  }
  .note { font-size: 13px; color: #5f6368; max-width: 900px; }
  .meta, .caveat { background: #fff; border: 1px solid #e0e3e7; border-radius: 8px; padding: 14px 16px; font-size: 13px; color: #444; }
  .caveat { border-left: 4px solid #b58900; margin-top: 16px; }
  ul { margin: 8px 0 0; padding-left: 20px; }
  li { margin-bottom: 6px; }
</style></head>
<body>
<header>
  <h1>Container Security Inspector</h1>
  <div class="sub">Read-only audit · ${esc(report.meta.target_label)} · ${esc(report.meta.generated_at)} · no active network probes · secret values never retained or exported</div>
</header>
<main>
  <div class="cards">${cards}</div>

  <h2>Exposure map</h2>
  <div class="expo-grid">${exposure}</div>

  <h2 id="findings">Findings (${report.findings.length})</h2>
  <p class="note">Evidence shows confirmed facts only. Risk describes possible consequences when the relevant authorization, credential validity, or business need is unknown - those are listed as "Not verified" and were not tested (no connections, no cloud calls, no secret values).</p>
  <table>
    <colgroup><col class="c-sev"><col class="c-find"><col class="c-ev"><col><col></colgroup>
    <thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Risk</th><th>Recommendation</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>

  <h2>Recommended next steps</h2>
  <div class="meta"><ul>${steps}</ul></div>

  <div class="caveat">
    <strong>Scope and limits.</strong> ${esc(report.meta.caveat)}
  </div>
</main>
</body></html>`;
}

export function writeHtml(report, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, 'report.html');
  fs.writeFileSync(file, renderHtml(report));
  return file;
}
