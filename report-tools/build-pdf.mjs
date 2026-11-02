// Markdown -> HTML (markdown-it, GitHub-style heading slugs) -> Chromium PDF with
// rendered Mermaid diagrams, PDF outline (bookmarks) and clickable internal/external links.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import MarkdownIt from 'markdown-it';
import anchor from 'markdown-it-anchor';
import puppeteer from 'puppeteer';

// Usage: node build-pdf.mjs <in.md> <out.pdf> [--landscape] [--compact]
const argv = process.argv.slice(2);
const flags = new Set(argv.filter(a => a.startsWith('--')));
const [mdPath, outPdf] = argv.filter(a => !a.startsWith('--'));
const landscape = flags.has('--landscape');
const compact = flags.has('--compact');
const md = fs.readFileSync(mdPath, 'utf8');
const docTitle = (md.match(/^# (.+)$/m) || [null, 'Report'])[1].trim();

// GitHub-style slugify, identical to linkify.py gh_slug()
const ghSlug = (s) => s.trim().toLowerCase()
  .replace(/[^\p{L}\p{N}\s\-_]/gu, '')   // \w equivalent incl. underscore
  .replace(/\s/g, '-');

const mdit = new MarkdownIt({ html: true, linkify: false, typographer: false });
// mermaid fences -> <pre class="mermaid">
const defaultFence = mdit.renderer.rules.fence;
mdit.renderer.rules.fence = (tokens, idx, opts, env, self) => {
  const t = tokens[idx];
  if (t.info.trim() === 'mermaid') {
    return `<pre class="mermaid">${t.content.replace(/</g, '&lt;')}</pre>\n`;
  }
  return defaultFence(tokens, idx, opts, env, self);
};
// external links open in new tab (harmless in PDF) and keep href
mdit.use(anchor, {
  slugify: ghSlug,
  uniqueSlugStartIndex: 1,
  permalink: false,
});

// Build a TOC from headings (## and ###) with anchors (sequence must match anchor plugin's uniqueness)
const seen = new Map();
const toc = [];
for (const line of md.split('\n')) {
  const m = line.match(/^(#{2,3})\s+(.*)$/);
  if (!m) continue;
  const level = m[1].length;
  let title = m[2].replace(/`([^`]*)`/g, '$1').replace(/\[([^\]]*)\]\([^)]*\)/g, '$1').trim();
  let slug = ghSlug(title);
  const n = seen.get(slug) || 0; seen.set(slug, n + 1); if (n) slug = `${slug}-${n}`;
  if (title === 'Contents') continue;
  toc.push({ level, title, slug });
}
const tocHtml = `<nav class="toc"><h2 id="table-of-contents">Table of contents</h2><ul>` +
  toc.map(t => `<li class="l${t.level}"><a href="#${t.slug}">${t.title}</a></li>`).join('') + `</ul></nav>`;

// Remove the plain-text "## Contents" list from the markdown (replaced by the generated TOC)
const mdNoContents = md.replace(/\n## Contents\n[\s\S]*?\n---\n/, '\n%%TOC%%\n\n---\n');
let body = mdit.render(mdNoContents).replace('<p>%%TOC%%</p>', tocHtml);
// bold-only paragraphs are table group labels: keep them with the table that follows
body = body.replace(/<p><strong>([^<]+)<\/strong><\/p>\s*(<table>)/g, '<p class="tlabel"><strong>$1</strong></p>$2');
// tables with 8 or more columns size columns by content instead of equal widths
body = body.replace(/<table>([\s\S]*?<\/thead>)/g, (m, head) => ((head.match(/<th>/g) || []).length >= 8 ? '<table class="auto">' : '<table>') + head);
body = body.replace(/(<h([23])[^>]*>(?:(?!<h[23])[\s\S])*?<\/h\2>)\s*(<pre class="mermaid">[\s\S]*?<\/pre>)/g, '<div class="keep">$1$3</div>');

const mermaidJs = fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), 'node_modules/mermaid/dist/mermaid.min.js'), 'utf8');
const css = `
  @page { size: A4${landscape ? ' landscape' : ''}; margin: ${compact ? '10mm 10mm 12mm 10mm' : '12mm 12mm 14mm 12mm'}; }
  html { font-size: ${compact ? '8pt' : '9pt'}; }
  body { font-family: -apple-system, "Helvetica Neue", Helvetica, Arial, sans-serif; line-height: 1.3; color: #111; max-width: 100%; }
  h1 { font-size: 18pt; margin: 0 0 4pt; border-bottom: 2px solid #76b900; padding-bottom: 6pt; }
  h2 { font-size: ${compact ? '11pt' : '12.5pt'}; margin-top: 12pt; margin-bottom: 4pt; border-bottom: 1px solid #ccc; padding-bottom: 3pt; break-after: avoid; }
  h3 { font-size: ${compact ? '9.5pt' : '10.5pt'}; margin-top: 9pt; margin-bottom: 3pt; break-after: avoid; }
  h4 { font-size: 9.5pt; break-after: avoid; }
  p, li { orphans: 3; widows: 3; }
  a { color: #0b5fa5; text-decoration: none; }
  a[href^="http"]::after { content: ""; }
  code { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 0.86em; background: #f3f4f6; padding: 0 3px; border-radius: 3px; overflow-wrap: anywhere; }
  pre { background: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 4px; padding: 6px 8px; font-size: 7.5pt; line-height: 1.3; overflow-x: hidden; white-space: pre-wrap; word-break: break-word; break-inside: avoid; }
  pre code { background: none; padding: 0; font-size: inherit; }
  table { border-collapse: collapse; width: 100%; table-layout: fixed; font-size: ${compact ? '6.8pt' : '7.6pt'}; margin: 4pt 0 8pt; break-inside: auto; }
  td, th { overflow-wrap: anywhere; }
  html, body { max-width: 100%; overflow-x: hidden; }
  thead { display: table-header-group; }
  tr { break-inside: avoid; }
  th, td { border: 1px solid #d0d4d9; padding: ${compact ? '1.2pt 2.5pt' : '2pt 3.5pt'}; vertical-align: top; text-align: left; }
  th { background: #eef2f6; }
  td code, th code { font-size: 0.92em; overflow-wrap: anywhere; }
  table.auto { table-layout: auto; }
  table.auto td:nth-child(2) { min-width: 28%; }
  table.auto td:nth-child(2) code { white-space: nowrap; }
  blockquote { border-left: 3px solid #ccc; margin: 0; padding: 0 10px; color: #444; }
  hr { border: 0; border-top: 1px solid #ddd; margin: 8pt 0; }
  p { margin: 4pt 0; } ul, ol { margin: 3pt 0; padding-left: 16pt; } li { margin: 1pt 0; }
  nav.toc ul { list-style: none; padding-left: 0; columns: 2; column-gap: 18pt; }
  nav.toc li.l2 { margin-top: 3pt; font-weight: 600; break-inside: avoid; }
  nav.toc li.l3 { margin-left: 12pt; font-weight: 400; font-size: 8.5pt; }
  nav.toc { margin-bottom: 10pt; }
  .mermaid { background: #fff; border: 1px solid #e1e4e8; border-radius: 4px; padding: 4px; text-align: center; break-inside: avoid; }
  .mermaid svg { display: block; margin: 0 auto; }
  .keep { break-inside: avoid; }
  .tlabel { break-after: avoid; margin: 6pt 0 2pt; }
  h2, h3, h4, .tlabel { break-after: avoid-page; }
`;
const html = `<!doctype html><html><head><meta charset="utf-8"><title>${docTitle}</title>
<style>${css}</style></head><body>${body}
<script>${mermaidJs}</script>
<script>
  mermaid.initialize({ startOnLoad: false, theme: 'neutral', securityLevel: 'loose', markdownAutoWrap: false, flowchart: { useMaxWidth: false, htmlLabels: true, wrappingWidth: 4000, nodeSpacing: 30, rankSpacing: 40 }, state: { useMaxWidth: false }, themeVariables: { fontSize: '11px' } });
  window.__mermaidDone = mermaid.run({ querySelector: '.mermaid' }).then(() => {
    const MAXH = 150 * 3.7795;
    window.__sizes = [];
    document.querySelectorAll('.mermaid svg').forEach(svg => {
      try { const bb = svg.getBBox(); if (bb.width > 0 && bb.height > 0) svg.setAttribute('viewBox', (bb.x - 10) + ' ' + (bb.y - 10) + ' ' + (bb.width + 20) + ' ' + (bb.height + 20)); } catch (e) {}
      const vb = svg.viewBox.baseVal; const ratio = vb.width / vb.height;
      const cw = svg.parentElement.clientWidth - 16;
      let w = Math.min(cw, vb.width), h = w / ratio; if (h > MAXH) { h = MAXH; w = h * ratio; }
      svg.removeAttribute('width'); svg.removeAttribute('height'); svg.style.maxWidth = 'none';
      svg.style.width = w + 'px'; svg.style.height = h + 'px';
      window.__sizes.push([Math.round(vb.width), Math.round(vb.height), Math.round(w), Math.round(h)]);
    });
    window.__ok = true; }).catch(e => { window.__err = String(e); });
</script></body></html>`;
const htmlPath = path.join(os.tmpdir(), path.basename(outPdf).replace(/\.pdf$/, '.html'));
fs.writeFileSync(htmlPath, html);

const browser = await puppeteer.launch({ headless: true, args: ['--allow-file-access-from-files'] });
const page = await browser.newPage();
await page.setViewport({ width: landscape ? 1040 : 680, height: 960 });
await page.emulateMediaType('print');
page.on('console', m => { if (m.type() === 'error') console.error('[page]', m.text()); });
await page.goto('file://' + path.resolve(htmlPath), { waitUntil: 'load' });
await page.waitForFunction('window.__ok === true || window.__err', { timeout: 60000 });
const err = await page.evaluate('window.__err');
if (err) { console.error('mermaid error:', err); }
const nDiagrams = await page.evaluate('document.querySelectorAll(".mermaid svg").length');
console.log('diagram sizes [vbW, vbH, w, h]:', JSON.stringify(await page.evaluate('window.__sizes')));
const nLinks = await page.evaluate('document.querySelectorAll("a[href]").length');
const overflow = await page.evaluate(() => {
  const vw = document.documentElement.clientWidth; const out = [];
  for (const el of document.body.querySelectorAll('*')) { const r = el.getBoundingClientRect(); if (r.right > vw + 1) out.push([el.tagName, el.className && String(el.className).slice(0,20), Math.round(r.right - vw), (el.textContent||'').trim().slice(0,40)]); }
  return { vw, scrollWidth: document.documentElement.scrollWidth, overflowing: out.slice(0, 8), count: out.length };
});
console.log('layout check:', JSON.stringify(overflow));
await page.pdf({ path: outPdf, format: 'A4', landscape, printBackground: true, outline: true, tagged: true,
  displayHeaderFooter: true, headerTemplate: '<span></span>',
  footerTemplate: '<div style="width:100%;text-align:center;font-size:8pt;color:#666;font-family:Helvetica,Arial,sans-serif;">' + docTitle + ' &nbsp;·&nbsp; page <span class="pageNumber"></span> of <span class="totalPages"></span></div>',
  margin: compact ? { top: '12mm', bottom: '14mm', left: '11mm', right: '11mm' } : { top: '16mm', bottom: '18mm', left: '15mm', right: '15mm' } });
await browser.close();
console.log(`PDF written: ${outPdf}  diagrams rendered: ${nDiagrams}  links: ${nLinks}`);
