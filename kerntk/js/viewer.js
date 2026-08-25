// Standalone reader for one exported PDF analysis.
//
// Everything is client-side: the payload sits next to this file as two
// AES-GCM blobs, the key is derived from a token in the URL fragment, and the
// source PDF is rendered in-browser by PDF.js. There is no backend — see
// export_pdf_reader.js for how a bundle is produced.
//
// The analysis (small) is decrypted on unlock; the PDF (large) is fetched and
// decrypted lazily, on the first citation click.

import * as pdfjsLib from './pdf.min.mjs';

pdfjsLib.GlobalWorkerOptions.workerSrc = new URL('./pdf.worker.min.mjs', import.meta.url).href;

const $ = (id) => document.getElementById(id);
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

let DOC_TITLE = '';    // set on unlock; used for the download filename
let MANIFEST = null;   // plaintext: kdf params + per-entry IVs
let KEY = null;        // derived CryptoKey, kept for the lazy PDF decrypt
let PDFDOC = null;     // PDF.js document, loaded once
let pdfLoading = null; // in-flight load, so two fast clicks share one decrypt

// ── unlock ──────────────────────────────────────────────────

async function deriveKey(token, kdf) {
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(token), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64(kdf.salt), iterations: kdf.iterations, hash: kdf.hash },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}

// Entries are stored as ciphertext||tag, which is exactly what Web Crypto wants.
async function openEntry(name) {
  const entry = MANIFEST.entries[name];
  const res = await fetch(`./data/${name}.enc`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`${name}.enc: HTTP ${res.status}`);
  const blob = await res.arrayBuffer();
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(entry.iv) }, KEY, blob);
}

async function unlock(token) {
  const msg = $('gate-msg');
  const btn = $('gate-go');
  msg.className = 'gate-msg';
  msg.textContent = 'Ontgrendelen…';
  btn.disabled = true;
  try {
    if (!MANIFEST) {
      const r = await fetch('./data/manifest.json', { cache: 'no-store' });
      if (!r.ok) throw new Error('manifest ontbreekt (HTTP ' + r.status + ')');
      MANIFEST = await r.json();
    }
    KEY = await deriveKey(token, MANIFEST.kdf);
    // The analysis doubles as the key check: AES-GCM authenticates, so a wrong
    // token throws here rather than yielding garbage.
    const plain = await openEntry('analysis');
    render(JSON.parse(new TextDecoder().decode(plain)));
  } catch (err) {
    KEY = null;
    btn.disabled = false;
    msg.className = 'gate-msg err';
    // A failed AES-GCM decrypt throws a bare OperationError — that is a wrong
    // key, not a broken file, and saying so is more useful than the raw name.
    msg.textContent = (err && err.name === 'OperationError')
      ? 'Onjuiste sleutel.'
      : 'Kon het document niet openen: ' + (err && err.message ? err.message : err);
  }
}

function boot() {
  window.__viewerBooted = true; // tells index.html's watchdog the module loaded
  // The token travels in the FRAGMENT: unlike a query string it is never sent
  // to the server, so it stays out of host and proxy logs.
  const fromHash = decodeURIComponent((location.hash || '').replace(/^#/, '')).trim();
  const fromQuery = decodeURIComponent((location.search || '').replace(/^\?/, '')).trim();
  const token = fromHash || fromQuery;
  $('gate-go').addEventListener('click', () => unlock($('gate-key').value.trim()));
  $('gate-key').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') unlock($('gate-key').value.trim());
  });
  // Changing only the fragment is a same-document navigation, so pasting a new
  // token into the address bar would otherwise do nothing.
  window.addEventListener('hashchange', () => {
    const t = decodeURIComponent((location.hash || '').replace(/^#/, '')).trim();
    if (t) { try { history.replaceState(null, '', location.pathname); } catch (_) {} unlock(t); }
  });
  if (token) {
    // Drop it from the address bar so it does not linger in screenshots.
    try { history.replaceState(null, '', location.pathname); } catch (_) {}
    unlock(token);
  } else {
    $('gate-key').focus();
  }
}

// ── analysis rendering ──────────────────────────────────────

function escHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Markdown fallback: analyses are usually stored as HTML, but older ones kept
// the model's markdown headings.
function mdToHtml(text) {
  if (!text || (!text.includes('\n##') && !/^#{1,4}\s/m.test(text))) return text;
  return text
    .replace(/^#### (.+)$/gm, '<h5>$1</h5>')
    .replace(/^### (.+)$/gm, '<h4>$1</h4>')
    .replace(/^## (.+)$/gm, '<h3>$1</h3>')
    .replace(/^# (.+)$/gm, '<h3>$1</h3>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>[\s\S]*?<\/li>)/g, '<ul>$1</ul>')
    .replace(/<\/ul>\s*<ul>/g, '')
    .replace(/\n{2,}/g, '\n')
    .split('\n')
    .map((line) => {
      line = line.trim();
      if (!line) return '';
      if (/^<(h[1-5]|ul|li|ol|p|div|table|blockquote)/.test(line)) return line;
      return '<p>' + line + '</p>';
    })
    .join('\n');
}

// "[p.11, 68]" / "[p.20-22]" → a clickable <sup> carrying every cited page.
function citeToSup(html) {
  const CITE = '\\[p\\.(\\d+(?:\\s*[,\\u2013\\u2014\\-]\\s*(?:p\\.)?\\d+)*)\\]';
  function attrs(pages) {
    // Expand "20-22" to 20,21,22 so every cited page is directly reachable;
    // plain lists ("11, p.68") pass through untouched.
    const nums = [];
    String(pages).split(',').forEach((part) => {
      const r = part.match(/(\d+)\s*[–—-]\s*(?:p\.)?\s*(\d+)/);
      if (r) {
        let a = parseInt(r[1], 10), b = parseInt(r[2], 10);
        if (a > b) { const t = a; a = b; b = t; }
        if (b - a <= 20) { for (let i = a; i <= b; i++) nums.push(i); return; }
      }
      (part.match(/\d+/g) || []).forEach((n) => nums.push(parseInt(n, 10)));
    });
    const uniq = nums.filter((n, i) => n > 0 && nums.indexOf(n) === i);
    return ' class="pdf-cite" data-page="' + (uniq[0] || '') + '" data-pages="' + uniq.join(',') +
      '" role="button" tabindex="0" title="Toon pagina ' + (uniq[0] || '') + ' van het originele document"';
  }
  // 1) Citations the analysis already stores inside a <sup> — upgrade in place.
  html = html.replace(new RegExp('<sup(?![^>]*pdf-cite)([^>]*)>(' + CITE + ')<\/sup>', 'g'),
    (m, had, inner, pages) => '<sup' + (had || '') + attrs(pages) + '>' + inner + '</sup>');
  // 2) Bare citations (the `pre` guard skips anything already wrapped).
  return html.replace(new RegExp('(<sup[^>]*>)?(' + CITE + ')(<\/sup>)?', 'g'),
    (m, pre, inner, pages) => (pre ? m : '<sup' + attrs(pages) + '>' + inner + '</sup>'));
}

// Split on <h3> headings into collapsible sections. Anything before the first
// heading is the analysis' opening paragraph — returned separately so it can
// stay above the collapse control instead of being buried by it.
// keepOpen: a predicate on the heading text for a section that must NOT be
// folded away. A TK meta-analysis puts its introduction under a heading of its
// own, and an introduction you have to unfold is not an introduction.
function wrapSections(html, keepOpen) {
  const parts = html.split(/(<h3[^>]*>[\s\S]*?<\/h3>)/i);
  const sections = [];
  let lead = '';
  let current = null;
  for (const part of parts) {
    if (/^<h3[^>]*>/i.test(part)) {
      if (current) sections.push(current);
      current = { heading: part.replace(/<\/?h3[^>]*>/gi, '').trim(), content: '' };
    } else if (current) {
      current.content += part;
    } else {
      lead += part;
    }
  }
  if (current) sections.push(current);
  // Collapsed by default: an analysis is long, and the headings are the map.
  return {
    lead: lead.trim(),
    sections: sections.map((sec) =>
      (keepOpen && keepOpen(sec.heading)
        ? '<h3 class="pdf-section-plain">' + sec.heading + '</h3>' + sec.content
        : '<details class="pdf-section"><summary class="pdf-section-summary">' + sec.heading +
          '</summary><div class="pdf-section-body">' + sec.content + '</div></details>')).join(''),
  };
}

// Chevrons pointing apart = "expand", pointing together = "collapse".
const ICON_EXPAND = '<path d="M4 7l4-3 4 3"/><path d="M4 9l4 3 4-3"/>';
const ICON_COLLAPSE = '<path d="M4 4l4 3 4-3"/><path d="M4 12l4-3 4 3"/>';
const chevrons = (paths) =>
  '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" ' +
  'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">' + paths + '</svg>';

// Sits directly above the collapsible sections, right-aligned. Sections start
// collapsed, so the toggle starts as "expand all".
function sectionsBar(hasPdf) {
  return '<div class="pdf-sections-bar">' +
    (hasPdf
      ? '<button type="button" class="pdf-dl-src">' +
          '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" ' +
            'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">' +
            '<path d="M8 2v8"/><path d="M4.5 7L8 10.5 11.5 7"/><path d="M3 13h10"/></svg>' +
          '<span>Download bron-PDF</span>' +
        '</button>'
      : '') +
    '<button type="button" class="pdf-collapse-all" aria-label="Alle secties uitklappen">' +
      chevrons(ICON_EXPAND) +
      '<span>Alles uitklappen</span>' +
    '</button></div>';
}

function wireCollapseAll(container) {
  const btn = container.querySelector('.pdf-collapse-all');
  if (!btn) return;
  btn.addEventListener('click', () => {
    const secs = container.querySelectorAll('details.pdf-section');
    if (!secs.length) return;
    let anyOpen = false;
    secs.forEach((s) => { if (s.open) anyOpen = true; });
    secs.forEach((s) => { s.open = !anyOpen; });
    const expand = anyOpen; // we just collapsed them, so next action is expand
    const lbl = btn.querySelector('span');
    if (lbl) lbl.textContent = expand ? 'Alles uitklappen' : 'Alles inklappen';
    btn.setAttribute('aria-label', expand ? 'Alle secties uitklappen' : 'Alle secties inklappen');
    const svg = btn.querySelector('svg');
    if (svg) svg.innerHTML = expand ? ICON_EXPAND : ICON_COLLAPSE;
  });
}

// Download the decrypted source PDF. The bytes come from the PDF.js document so
// there is no second copy of a large file in memory, and the first click pays
// for the fetch + decrypt if no citation has been opened yet.
function wireDownloadSource(container) {
  const btn = container.querySelector('.pdf-dl-src');
  if (!btn) return;
  const lbl = btn.querySelector('span');
  btn.addEventListener('click', async () => {
    if (btn.disabled) return;
    btn.disabled = true;
    const original = lbl.textContent;
    lbl.textContent = 'Ontsleutelen…';
    try {
      const doc = await loadPdf();
      const bytes = await doc.getData();
      const url = URL.createObjectURL(new Blob([bytes], { type: 'application/pdf' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = (DOC_TITLE || 'bron').replace(/[^\w.\- ]+/g, '_').slice(0, 80) + '.pdf';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      lbl.textContent = original;
    } catch (_) {
      lbl.textContent = 'Mislukt — opnieuw';
    }
    btn.disabled = false;
  });
}

// ── reading settings ────────────────────────────────────────
// Text size, typeface and light/dark, persisted per origin so the choice
// survives reloads and carries across bundles on the same host.

const FS_STEPS = [11, 12, 13, 14, 15, 16, 17, 18, 20, 22];
const DEFAULT_FS = 14;
const DEFAULT_FONT = 'ro-sans';
const FONT_STACKS = {
  system: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
  inter: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
  roboto: '"Roboto", -apple-system, BlinkMacSystemFont, sans-serif',
  'open-sans': '"Open Sans", -apple-system, BlinkMacSystemFont, sans-serif',
  lato: '"Lato", -apple-system, BlinkMacSystemFont, sans-serif',
  'ro-sans': '"RijksoverheidSans", -apple-system, BlinkMacSystemFont, sans-serif',
};
// Versioned: earlier builds persisted their defaults on first paint, so a
// returning reader would otherwise be stuck with the old default size and font.
const PREFS_KEY = 'pdfviewer.prefs.v2';

function loadPrefs() {
  try { return JSON.parse(localStorage.getItem(PREFS_KEY)) || {}; } catch (_) { return {}; }
}
function savePrefs(p) {
  try { localStorage.setItem(PREFS_KEY, JSON.stringify(p)); } catch (_) { /* private mode */ }
}

const SUN = '<svg viewBox="0 0 20 20" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round">' +
  '<circle cx="10" cy="10" r="3.6"/><path d="M10 2v1.8M10 16.2V18M18 10h-1.8M3.8 10H2M15.7 4.3l-1.3 1.3M5.6 14.4l-1.3 1.3M15.7 15.7l-1.3-1.3M5.6 5.6L4.3 4.3"/></svg>';
const MOON = '<svg viewBox="0 0 20 20" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round">' +
  '<path d="M16.5 12.4A7 7 0 0 1 7.6 3.5a7 7 0 1 0 8.9 8.9z"/></svg>';

function wireSettings() {
  const prefs = loadPrefs();
  const root = document.documentElement;
  const bar = $('topbar');
  const upBtn = $('fs-up');
  const downBtn = $('fs-down');
  const fontSel = $('font-pick');
  const themeBtn = $('theme-toggle');

  // Size ──
  let fsIdx = FS_STEPS.indexOf(prefs.fs);
  if (fsIdx === -1) fsIdx = FS_STEPS.indexOf(DEFAULT_FS);
  function applyFs(persist) {
    root.style.setProperty('--fs', FS_STEPS[fsIdx] + 'px');
    downBtn.disabled = fsIdx === 0;
    upBtn.disabled = fsIdx === FS_STEPS.length - 1;
    if (persist) { prefs.fs = FS_STEPS[fsIdx]; savePrefs(prefs); }
  }
  upBtn.addEventListener('click', () => { if (fsIdx < FS_STEPS.length - 1) { fsIdx++; applyFs(true); } });
  downBtn.addEventListener('click', () => { if (fsIdx > 0) { fsIdx--; applyFs(true); } });
  applyFs(false);

  // Typeface ──
  function applyFont(name, persist) {
    const stack = FONT_STACKS[name] || FONT_STACKS[DEFAULT_FONT];
    root.style.setProperty('--font-stack', stack);
    fontSel.value = FONT_STACKS[name] ? name : DEFAULT_FONT;
    if (persist) { prefs.font = fontSel.value; savePrefs(prefs); }
  }
  fontSel.addEventListener('change', () => applyFont(fontSel.value, true));
  applyFont(prefs.font || DEFAULT_FONT, false);

  // Light / dark ──
  // Until the reader picks one, follow the system: no data-theme attribute, so
  // the prefers-color-scheme block in the stylesheet decides.
  const systemDark = () => window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  function applyTheme(theme, persist) {
    if (theme === 'dark' || theme === 'light') root.setAttribute('data-theme', theme);
    else root.removeAttribute('data-theme');
    const isDark = theme === 'dark' || (theme !== 'light' && systemDark());
    themeBtn.innerHTML = isDark ? SUN : MOON;
    themeBtn.setAttribute('aria-label', isDark ? 'Lichte modus' : 'Donkere modus');
    themeBtn.title = isDark ? 'Lichte modus' : 'Donkere modus';
    if (persist) { prefs.theme = theme; savePrefs(prefs); }
  }
  themeBtn.addEventListener('click', () => {
    const isDark = root.getAttribute('data-theme') === 'dark' ||
      (!root.hasAttribute('data-theme') && systemDark());
    applyTheme(isDark ? 'light' : 'dark', true);
  });
  applyTheme(prefs.theme || 'auto', false);

  bar.hidden = false;
}

function fmtDate(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return '';
  const mo = ['jan', 'feb', 'mrt', 'apr', 'mei', 'jun', 'jul', 'aug', 'sep', 'okt', 'nov', 'dec'];
  return d.getDate() + ' ' + mo[d.getMonth()] + ' ' + d.getFullYear();
}

// "claude-opus-5" → "Claude Opus 5"; "claude-sonnet-4-6" → "Claude Sonnet 4.6".
// A trailing date stamp (claude-haiku-4-5-20251001) is dropped.
function fmtModel(id) {
  const parts = String(id || '').split('-').filter((x) => !/^\d{8}$/.test(x));
  if (!parts.length) return '';
  const words = [], nums = [];
  for (const part of parts) {
    if (/^\d+$/.test(part)) nums.push(part);
    else words.push(part.charAt(0).toUpperCase() + part.slice(1));
  }
  return (words.join(' ') + (nums.length ? ' ' + nums.join('.') : '')).trim();
}

function fmtInt(n) { return Math.round(n).toLocaleString('nl-NL'); }

// Rough page equivalent of the summary itself, from its word count. Printed
// with a ~ because it is an estimate, not a rendered page count.
function summaryPages(html) {
  const words = String(html || '').replace(/<[^>]+>/g, ' ').trim().split(/\s+/).filter(Boolean).length;
  return Math.max(1, Math.round(words / 450));
}

const IS_INTRO = (h) => /^\s*(?:\d+[.)]\s*)?(?:inleiding|introductie|introduction)\b/i.test(h);

function render(data) {
  const isTk = data.kind === 'tk';
  DOC_TITLE = data.title || '';
  document.title = data.title || (isTk ? 'Tweede Kamer meta-analyse' : 'PDF summary');
  $('gate').hidden = true;
  $('doc').hidden = false;
  wireSettings();
  // Only after unlock: the shell itself stays anonymous, so the URL still says
  // nothing about what it points at.
  // Named for what it is. The page ships with "PDF summary" in the markup, so a
  // TK bundle that still shows that is running a viewer older than this line — the
  // quickest way to tell a stale deployment from a broken one.
  const kicker = $('doc-kicker');
  if (kicker) kicker.textContent = isTk ? 'Tweede Kamer meta-analyse' : 'PDF summary';
  // The markup ships with the PDF wording; a TK bundle searches an analysis.
  const searchBox = $('pdf-search-input');
  if (searchBox && isTk) searchBox.placeholder = 'Zoek in deze analyse…';
  $('doc-title').textContent = data.title || (isTk ? 'Tweede Kamer meta-analyse' : 'PDF summary');

  const bits = [];
  if (isTk) {
    if (data.queries && data.queries.length) bits.push('Zoektermen: ' + data.queries.join(', '));
    if (data.articleCount) bits.push(data.articleCount + ' parlementaire documenten');
    if (data.dateFrom && data.dateTo) {
      bits.push(data.dateFrom === data.dateTo ? data.dateFrom : data.dateFrom + ' – ' + data.dateTo);
    }
  }
  if (data.pageCount) {
    bits.push("Origineel document: " + data.pageCount + ' pagina' + (data.pageCount === 1 ? '' : "'s"));
  }
  // "Samenvatting" described the wrong thing: this is how long the piece you are
  // about to read is, not how much was summarised.
  bits.push('Documentlengte: ~' + summaryPages(data.html) + " pagina's");
  try { wireMadePanel(data); } catch (e) { console.warn('[viewer] made-panel:', e); }
  if (data.model) bits.push('Model: ' + fmtModel(data.model));
  const tok = (data.inputTokens || 0) + (data.outputTokens || 0);
  // Older analyses predate token accounting; estimate from the text so the line
  // stays complete, and mark it with ~ so it is not read as a measured figure.
  if (tok) bits.push('Tokens: ' + fmtInt(tok));
  else if (data.html) bits.push('Tokens: ~' + fmtInt(data.html.replace(/<[^>]+>/g, ' ').length / 4));
  if (data.created_at) bits.push(fmtDate(data.created_at));
  $('doc-meta').textContent = bits.join('  |  ');

  const bodyEl = $('doc-body');
  const hasPdf = !!(MANIFEST.entries && MANIFEST.entries.source);
  // A TK analysis is already HTML and its references are [N] links into a
  // source list, not page citations — so neither the markdown step nor the
  // page-citation rewrite applies to it.
  const parts = isTk
    ? wrapSections(data.html || '', IS_INTRO)
    : wrapSections(citeToSup(mdToHtml(data.html || '')));
  bodyEl.innerHTML =
    (parts.lead ? '<div class="doc-lead">' + parts.lead + '</div>' : '') +
    (parts.sections || hasPdf ? sectionsBar(hasPdf) : '') +
    '<div id="pdf-sections">' + (parts.sections || parts.lead ? parts.sections : '<em>Geen inhoud.</em>') + '</div>';

  const sectionsEl = $('pdf-sections');
  wireCollapseAll(bodyEl);
  if (!isTk) wireDownloadSource(bodyEl);
  if (isTk) wireTkReferences(bodyEl);
  wireSearch(sectionsEl);
  // On bodyEl, not sectionsEl: the opening paragraph sits outside the sections
  // and its citations must be clickable too.
  bodyEl.classList.toggle('pdf-cites-live', hasPdf);
  bodyEl.addEventListener('click', (e) => {
    const cite = e.target.closest && e.target.closest('.pdf-cite');
    if (!cite || !hasPdf) return;
    e.preventDefault();
    const pages = (cite.getAttribute('data-pages') || '').split(',').filter(Boolean).map(Number);
    openPagePopup(parseInt(cite.getAttribute('data-page'), 10) || 1, pages);
  });

  $('doc-foot').textContent = isTk
    ? 'Klik op een verwijzing om het bijbehorende Kamerstuk op tweedekamer.nl te openen.'
    : hasPdf
      ? 'Klik op een paginaverwijzing om die pagina uit het originele PDF-document te bekijken.'
      : 'Het originele PDF-document is niet meegeleverd; paginaverwijzingen zijn niet aanklikbaar.';
}

// [N] references in a TK analysis point at a numbered source list at the end of
// the document. Send them straight to the document on tweedekamer.nl where the
// list has a link, and otherwise open the section holding the list — which is
// folded shut like every other section.
function wireTkReferences(bodyEl) {
  const urls = {};
  bodyEl.querySelectorAll('li[id^="tkl-doc-"] > a[href]').forEach((a) => {
    const m = a.parentNode.id.match(/^tkl-doc-(\d+)$/);
    if (m) urls[m[1]] = a.getAttribute('href');
  });
  bodyEl.querySelectorAll('sup > a[href^="#tkl-doc-"]').forEach((a) => {
    const n = (a.getAttribute('href').match(/#tkl-doc-(\d+)/) || [])[1];
    if (n && urls[n]) {
      a.setAttribute('href', urls[n]);
      a.setAttribute('target', '_blank');
      a.setAttribute('rel', 'noopener');
    }
  });
  bodyEl.addEventListener('click', (e) => {
    const a = e.target.closest && e.target.closest('a[href^="#tkl-doc-"]');
    if (!a) return;
    const target = bodyEl.querySelector(a.getAttribute('href'));
    const det = target && target.closest('details.pdf-section');
    if (det && !det.open) det.open = true;
  });
}

// ── search ──────────────────────────────────────────────────
// Sections containing the term open with matches marked and non-matching
// blocks hidden; sections without a match stay shut.

function wireSearch(bodyEl) {
  const input = $('pdf-search-input');
  const clearBtn = $('pdf-search-clear');
  const countEl = $('pdf-search-count');
  if (!input || !bodyEl) return;

  const origHtml = bodyEl.innerHTML; // pristine copy — re-applied before each search
  let priorOpen = null;              // open/closed state from before searching
  let timer = null;

  const sections = () => bodyEl.querySelectorAll('details.pdf-section');
  const terms = (q) => String(q || '').trim().split(/\s+/).filter(Boolean);
  const esc = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const hasAll = (text, ts) => {
    const low = String(text || '').toLowerCase();
    return ts.every((t) => low.indexOf(t.toLowerCase()) !== -1);
  };

  // Wrap matches by walking TEXT NODES — a regex over innerHTML would corrupt
  // tags and attribute values.
  function mark(root, re) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
    const nodes = [];
    let n;
    while ((n = walker.nextNode())) {
      if (n.parentNode && n.parentNode.nodeName === 'MARK') continue;
      nodes.push(n);
    }
    let hits = 0;
    nodes.forEach((node) => {
      const text = node.nodeValue;
      if (!text) return;
      re.lastIndex = 0;
      if (!re.test(text)) return;
      re.lastIndex = 0;
      const frag = document.createDocumentFragment();
      let last = 0, m;
      while ((m = re.exec(text))) {
        if (!m[0]) { re.lastIndex++; continue; }
        if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
        const el = document.createElement('mark');
        el.className = 'pdf-hit';
        el.textContent = m[0];
        frag.appendChild(el);
        last = m.index + m[0].length;
        hits++;
      }
      if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
      node.parentNode.replaceChild(frag, node);
    });
    return hits;
  }

  function apply(q) {
    const ts = terms(q);
    bodyEl.innerHTML = origHtml; // drop previous marks/hiding
    bodyEl.classList.toggle('pdf-searching', ts.length > 0);
    if (!ts.length) {
      if (priorOpen) {
        sections().forEach((sec, i) => { sec.open = !!priorOpen[i]; });
        priorOpen = null;
      }
      if (countEl) countEl.textContent = '';
      if (clearBtn) clearBtn.style.display = 'none';
      return;
    }
    if (!priorOpen) {
      priorOpen = [];
      sections().forEach((sec) => priorOpen.push(sec.open));
    }
    if (clearBtn) clearBtn.style.display = '';

    const re = new RegExp('(' + ts.map(esc).join('|') + ')', 'gi');
    let hits = 0, secHits = 0;
    sections().forEach((sec) => {
      const summary = sec.querySelector('.pdf-section-summary');
      const body = sec.querySelector('.pdf-section-body');
      const headMatch = hasAll(summary ? summary.textContent : '', ts);
      const bodyMatch = hasAll(body ? body.textContent : '', ts);
      if (!headMatch && !bodyMatch) { sec.open = false; sec.classList.add('pdf-sec-nomatch'); return; }
      sec.classList.remove('pdf-sec-nomatch');
      sec.open = true;
      secHits++;
      if (body) {
        if (!headMatch) {
          // Hide blocks that don't match; a heading-only match keeps everything.
          body.querySelectorAll(':scope > *').forEach((el) => {
            if (!hasAll(el.textContent, ts)) el.classList.add('pdf-search-hidden');
          });
          body.querySelectorAll('li').forEach((li) => {
            if (!hasAll(li.textContent, ts)) li.classList.add('pdf-search-hidden');
          });
        }
        hits += mark(body, re);
      }
      if (summary) hits += mark(summary, re);
    });
    if (countEl) {
      countEl.textContent = hits
        ? hits + (hits === 1 ? ' resultaat' : ' resultaten') + ' in ' + secHits + ' sectie' + (secHits === 1 ? '' : 's')
        : 'geen resultaten';
    }
  }

  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => apply(input.value), 180);
  });
  if (clearBtn) clearBtn.addEventListener('click', () => {
    input.value = '';
    apply('');
    input.focus();
  });
}

// ── source PDF ──────────────────────────────────────────────

// Decrypt and open the source once; concurrent callers share the same promise.
function loadPdf() {
  if (PDFDOC) return Promise.resolve(PDFDOC);
  if (pdfLoading) return pdfLoading;
  pdfLoading = openEntry('source')
    .then((buf) => pdfjsLib.getDocument({ data: new Uint8Array(buf) }).promise)
    .then((doc) => { PDFDOC = doc; pdfLoading = null; return doc; })
    .catch((err) => { pdfLoading = null; throw err; });
  return pdfLoading;
}

// Keep rasterised pages well inside mobile Safari's canvas budget: a 2x render
// of an A4 at 300dpi would blow past it on an older iPad.
const MAX_CANVAS_PX = 6e6;
const MAX_CANVAS_SIDE = 4096;

async function renderPageCanvas(doc, pageNo, cssWidth) {
  const page = await doc.getPage(pageNo);
  const base = page.getViewport({ scale: 1 });
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  let scale = Math.max(0.4, (cssWidth * dpr) / base.width);
  const cap = Math.min(
    Math.sqrt(MAX_CANVAS_PX / (base.width * base.height)),
    MAX_CANVAS_SIDE / Math.max(base.width, base.height));
  if (scale > cap) scale = cap;

  const vp = page.getViewport({ scale });
  const canvas = document.createElement('canvas');
  canvas.className = 'pdfpage-canvas';
  canvas.width = Math.round(vp.width);
  canvas.height = Math.round(vp.height);
  canvas.style.width = Math.round(vp.width / dpr) + 'px';
  await page.render({ canvasContext: canvas.getContext('2d', { alpha: false }), viewport: vp }).promise;
  return canvas;
}

// Rebuild readable lines from the positioned text items PDF.js hands back.
async function pageText(doc, pageNo) {
  const page = await doc.getPage(pageNo);
  const tc = await page.getTextContent();
  let out = '', lastY = null;
  for (const item of tc.items) {
    if (typeof item.str !== 'string') continue;
    const y = item.transform ? Math.round(item.transform[5]) : null;
    if (lastY !== null && y !== null && Math.abs(y - lastY) > 2) out += '\n';
    out += item.str;
    if (item.hasEOL) out += '\n';
    lastY = y;
  }
  return out.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}

function openPagePopup(page, pages) {
  const ov = document.createElement('div');
  ov.className = 'pdfpage-overlay';
  ov.innerHTML =
    '<div class="pdfpage-popup" role="dialog" aria-label="Bronpagina">' +
      '<div class="pdfpage-head">' +
        '<div class="pdfpage-title">Bronpagina <span class="pdfpage-num"></span></div>' +
        '<button class="pdfpage-close" type="button" aria-label="Sluiten">&times;</button>' +
      '</div>' +
      '<div class="pdfpage-refs" style="display:none"></div>' +
      '<div class="pdfpage-body"><div class="pdfpage-loading">Document ontsleutelen…</div></div>' +
      '<div class="pdfpage-foot">' +
        '<button class="pdfpage-nav" data-dir="-1" type="button" aria-label="Vorige pagina">&#8249;</button>' +
        '<button class="pdfpage-nav" data-dir="1" type="button" aria-label="Volgende pagina">&#8250;</button>' +
        '<button class="pdfpage-toggle" type="button">Toon tekst</button>' +
        '<a class="pdfpage-open" download>Open origineel</a>' +
        '<button class="pdfpage-close-foot" type="button">Sluiten</button>' +
      '</div>' +
    '</div>';
  document.body.appendChild(ov);
  requestAnimationFrame(() => ov.classList.add('open'));

  let objectUrl = null;
  function close() {
    ov.classList.remove('open');
    if (objectUrl) URL.revokeObjectURL(objectUrl);
    setTimeout(() => ov.remove(), 200);
    document.removeEventListener('keydown', onKey);
  }
  function onKey(e) {
    if (e.key === 'Escape') close();
    else if (e.key === 'ArrowLeft') step(-1);
    else if (e.key === 'ArrowRight') step(1);
  }
  document.addEventListener('keydown', onKey);
  ov.querySelector('.pdfpage-close').addEventListener('click', close);
  ov.querySelector('.pdfpage-close-foot').addEventListener('click', close);
  ov.addEventListener('click', (e) => { if (e.target === ov) close(); });

  const body = ov.querySelector('.pdfpage-body');
  const numEl = ov.querySelector('.pdfpage-num');
  const refsEl = ov.querySelector('.pdfpage-refs');
  const toggleBtn = ov.querySelector('.pdfpage-toggle');
  const openLink = ov.querySelector('.pdfpage-open');

  const refList = (pages && pages.length ? pages : [page])
    .map(Number).filter((n) => n > 0)
    .filter((n, i, a) => a.indexOf(n) === i)
    .sort((a, b) => a - b);
  let cur = page;
  let mode = 'page';
  let token = 0; // guards against a slower render overtaking a newer one

  refsEl.addEventListener('click', (e) => {
    const chip = e.target.closest && e.target.closest('.pdfpage-ref');
    if (!chip) return;
    const n = parseInt(chip.getAttribute('data-p'), 10);
    if (!n || n === cur) return;
    cur = n;
    draw();
  });
  toggleBtn.addEventListener('click', () => {
    mode = mode === 'text' ? 'page' : 'text';
    draw();
  });
  ov.querySelectorAll('.pdfpage-nav').forEach((btn) => {
    btn.addEventListener('click', () => step(parseInt(btn.getAttribute('data-dir'), 10)));
  });
  function step(dir) {
    const next = cur + dir;
    if (next < 1 || (PDFDOC && next > PDFDOC.numPages)) return;
    cur = next;
    draw();
  }

  openLink.addEventListener('click', async (e) => {
    if (objectUrl) return; // already prepared — let the normal download proceed
    e.preventDefault();
    try {
      const doc = await loadPdf();
      const bytes = await doc.getData();
      objectUrl = URL.createObjectURL(new Blob([bytes], { type: 'application/pdf' }));
      openLink.href = objectUrl;
      openLink.click();
    } catch (_) { /* the popup already shows the failure */ }
  });

  function syncChrome() {
    numEl.textContent = String(cur) + (PDFDOC ? ' / ' + PDFDOC.numPages : '');
    if (refList.length > 1) {
      refsEl.style.display = 'flex';
      refsEl.innerHTML = '<span class="pdfpage-refs-label">Verwijzing:</span>' +
        refList.map((n) => '<button type="button" class="pdfpage-ref' + (n === cur ? ' active' : '') +
          '" data-p="' + n + '">' + n + '</button>').join('');
    } else {
      refsEl.style.display = 'none';
      refsEl.innerHTML = '';
    }
    toggleBtn.textContent = mode === 'text' ? 'Toon pagina' : 'Toon tekst';
    const navs = ov.querySelectorAll('.pdfpage-nav');
    navs[0].disabled = cur <= 1;
    navs[1].disabled = !!(PDFDOC && cur >= PDFDOC.numPages);
  }

  async function draw() {
    const mine = ++token;
    syncChrome();
    if (!PDFDOC && !pdfLoading) body.innerHTML = '<div class="pdfpage-loading">Document ontsleutelen…</div>';
    try {
      const doc = await loadPdf();
      if (mine !== token) return;
      if (cur < 1 || cur > doc.numPages) {
        body.innerHTML = '<div class="pdfpage-empty">Pagina ' + cur + ' bestaat niet — het document heeft ' +
          doc.numPages + ' pagina\'s.</div>';
        syncChrome();
        return;
      }
      body.innerHTML = '<div class="pdfpage-loading">Pagina laden…</div>';
      if (mode === 'text') {
        const t = await pageText(doc, cur);
        if (mine !== token) return;
        body.innerHTML = t
          ? '<pre class="pdfpage-text"></pre>'
          : '<div class="pdfpage-empty">Geen tekstlaag op deze pagina (waarschijnlijk een scan).</div>';
        if (t) body.querySelector('.pdfpage-text').textContent = t;
      } else {
        const width = Math.max(240, body.clientWidth - 28);
        const canvas = await renderPageCanvas(doc, cur, width);
        if (mine !== token) return;
        body.innerHTML = '';
        body.appendChild(canvas);
      }
      body.scrollTop = 0;
      syncChrome();
    } catch (err) {
      if (mine !== token) return;
      body.innerHTML = '<div class="pdfpage-empty">Pagina kon niet geladen worden.<br>' +
        escHtml(err && err.message ? err.message : String(err)) + '</div>';
    }
  }

  draw();
}

boot();

// ── Hoe deze analyse is gemaakt ──────────────────────────────────────────────
// The reader's info panel, carried into the bundle. Everything here comes off
// `madeOf`, which the exporter trims out of the analysis record — so a shared
// link can be judged on how the piece was made, not only on what it says.
// Absent from an older bundle, in which case the button never appears.
function wireMadePanel(data) {
  const made = data && data.madeOf;
  const btn = document.getElementById('made-btn');
  if (!btn || (!made && !data.runLog)) return;
  btn.hidden = false;

  const esc = (x) => String(x == null ? '' : x)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const nf = (n) => (Number(n) || 0).toLocaleString('nl-NL');
  const rows = [];
  const row = (l, v) => {
    if (v === null || v === undefined || v === '') return;
    rows.push('<div class="made-row"><span>' + esc(l) + '</span><span>' + esc(v) + '</span></div>');
  };
  // A heading is only worth drawing if something follows it — the first version
  // of this panel printed "DEKKING" and "FIGUREN" over nothing at all.
  const sec = (t) => rows.push('<div class="made-sec" data-sec>' + esc(t) + '</div>');
  const raw = (h) => rows.push(h);
  const pre = (t, body) => {
    if (!body) return;
    raw('<div class="made-row" style="display:block"><span style="display:block;margin-bottom:3px">' +
      esc(t) + '</span><pre class="made-pre">' + esc(body) + '</pre></div>');
  };
  const modelLine = (id, local, ctx) =>
    (id || '?') + (local ? ' (lokaal' : ' (cloud') + (ctx ? ', context ~' + nf(ctx) + ' tok)' : ')');

  const m = (made && made.models) || {};
  const fr = (made && made.fitReport) || {};
  const dc = made && made.docCounts;

  if (made) {
    sec('Opdracht');
    if (made.queries && made.queries.length) row('Zoektermen', made.queries.join(', '));
    if (made.language) row('Taal', made.language === 'en' ? 'Engels' : 'Nederlands');
    if (made.period && made.period.label) row('Periode documenten', made.period.label);
    row('Documenten', dc
      ? nf(dc.found) + ' gevonden · ' + nf(dc.downloaded) + ' opgehaald · ' +
        nf(dc.parsed) + ' met tekst · ' + nf(made.fetchedCount) + ' gebruikt'
      : (made.fetchedCount ? nf(made.fetchedCount) : null));
    if (made.dateFrom && made.dateTo) row('Periode', made.dateFrom + ' – ' + made.dateTo);
    if (made.words) row('Lengte artikel', nf(made.words) + ' woorden');
    if (made.tokens) row('Tokens totaal', nf(made.tokens.input) + ' in · ' + nf(made.tokens.output) + ' uit');
    if (made.durationMs) row('Duur', Math.round(made.durationMs / 60000) + ' min');

    sec('Instellingen');
    if (made.length) row('Lengte-instelling', made.length);
    if (made.articleCharCap) row('Tekstlimiet per document', nf(made.articleCharCap) + ' tekens');
    if (made.pages) row("Zoekpagina's per bron", nf(made.pages));
    if (made.maxCloudContextTokens) row('Contextlimiet cloud', nf(made.maxCloudContextTokens) + ' tok');

    sec('Modellen');
    if (m.summarize) row('Samenvattingen', modelLine(m.summarize, m.summarizeLocal, m.summarizeCtx));
    if (m.final) row('Finale analyse', modelLine(m.final, m.finalLocal, m.finalCtx));
    if (made.promptTranslation && made.promptTranslation.model)
      row('Prompts vertaald via', made.promptTranslation.model);
    if (made.polish && made.polish.applied)
      row('Naredactie', made.polish.model + (made.polish.dutch ? ' (Nederlands)' : ' (Engels)'));

    sec('Verloop en contextbudget');
    row('Schrijfwijze', made.sectioned ? 'sectie voor sectie' : 'in één keer');
    if (made.batches) row('Batches samengevat', nf(made.batches));
    if (made.reducePasses) row('Reductiepassen', nf(made.reducePasses));
    if (fr.perBatchTok) row('Doel per batch', '~' + nf(fr.perBatchTok) + ' tok');
    if (fr.inputBudgetTok) row('Budget-opbouw', '~' + nf(fr.inputBudgetTok) + ' tok invoerruimte');
    if (fr.finalPromptTok) row('Finale prompt', '~' + nf(fr.finalPromptTok) + ' tok' +
      (m.finalCtx ? ' van ~' + nf(m.finalCtx) : ''));
    if (fr.totalChars) row('Brontekst totaal', nf(fr.totalChars) + ' tekens');

    // Which documents fell out, and where. The numbers point into the article's
    // own source list, which is on this page — so the titles come from there
    // rather than being stored a second time.
    const cov = made.coverage || {};
    const ns = cov.notSummarised || [], nc = cov.notCited || [];
    if (ns.length || nc.length) {
      sec('Wat er buiten viel');
      raw('<div class="made-note">De nummers verwijzen naar de bronnenlijst onderaan het artikel.</div>');
      const list = (label, nums) => {
        if (!nums.length) return;
        raw('<div class="made-row" style="display:block">' +
          '<span style="display:block;margin-bottom:3px">' + esc(label) + ' (' + nf(nums.length) + ')</span>' +
          '<div class="made-nums">' + nums.map((x) => '<span>' + esc(x) + '</span>').join('') + '</div></div>');
      };
      list('Niet in de samenvattingen terechtgekomen', ns);
      list('Wel samengevat, niet aangehaald in het artikel', nc);
    }

    if (made.skippedArticles && made.skippedArticles.length) {
      sec('Niet meegenomen');
      raw('<div class="made-note">' + nf(made.skippedArticles.length) +
        ' document(en) zonder bruikbare tekst.</div>');
      raw('<div class="made-skip">' + made.skippedArticles.slice(0, 200).map((x) =>
        '<div>' + esc(x.title || x.url || '?') + (x.reason ? ' — ' + esc(x.reason) : '') + '</div>').join('') +
        '</div>');
    }

    if (made.sectionStats && made.sectionStats.length) {
      sec('Lengte per sectie');
      made.sectionStats.forEach((x) => row(x.heading || '?',
        (x.words ? nf(x.words) + ' woorden' : '') +
        (x.minWords ? ' (ondergrens ' + nf(x.minWords) + ')' : '')));
    }

    // Both prompts: the one that summarised every batch and the one that wrote
    // the article. The batch prompt was missing here entirely.
    const pr = made.prompts || {};
    if (pr.batch || pr.sectionPrefix || (pr.sections && pr.sections.length) || pr.final) {
      sec('Gebruikte prompts');
      pre('Batch-samenvatting prompt', pr.batch);
      if (pr.mode === 'sections' && pr.sections && pr.sections.length) {
        pre('Gedeelde sectie-instructie', pr.sectionPrefix);
        pr.sections.forEach((x, i) => pre('Sectie ' + (i + 1) + ': ' + (x.heading || ''), x.instruction));
      } else if (pr.final) {
        pre(pr.mode === 'single' ? 'Finale analyse prompt (integraal)' : 'Finale analyse prompt', pr.final);
      }
    }

    // The server already wraps these in their own captioned block, so this
    // section gets no heading of its own — that was the duplicated "FIGUREN".
    if (made.madeFigures) raw('<div class="made-figs">' + made.madeFigures + '</div>');
  }

  let logDrawn = false;
  if (data.runLog) {
    sec('Logboek van de run');
    raw('<div id="made-log-slot"><button type="button" class="made-btn" id="made-log-btn">Toon logboek (' +
      Math.round(data.runLog.length / 1024) + ' kB)</button></div>');
  }

  // Drop any heading with nothing under it.
  const h = rows.filter((r, i) => !/data-sec/.test(r) ||
    (rows[i + 1] !== undefined && !/data-sec/.test(rows[i + 1]))).join('');

  const ov = document.getElementById('made-overlay');
  const body = document.getElementById('made-body');
  const open = () => {
    body.innerHTML = h;
    ov.classList.add('open');
    const lb = document.getElementById('made-log-btn');
    if (lb) lb.addEventListener('click', () => {
      if (logDrawn) return;
      logDrawn = true;
      document.getElementById('made-log-slot').innerHTML =
        '<pre class="made-pre made-log">' + esc(data.runLog) + '</pre>';
    });
  };
  btn.addEventListener('click', open);
  ov.addEventListener('click', (e) => {
    if (e.target === ov || e.target.closest('#made-x')) ov.classList.remove('open');
  });
}
