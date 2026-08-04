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

// Split on <h3> headings into collapsible sections.
function wrapSections(html) {
  const parts = html.split(/(<h3[^>]*>[\s\S]*?<\/h3>)/i);
  const sections = [];
  let current = null;
  for (const part of parts) {
    if (/^<h3[^>]*>/i.test(part)) {
      if (current) sections.push(current);
      current = { heading: part.replace(/<\/?h3[^>]*>/gi, '').trim(), content: '' };
    } else if (current) {
      current.content += part;
    } else {
      sections.push({ heading: null, content: part });
    }
  }
  if (current) sections.push(current);
  return sections.map((sec) => sec.heading
    ? '<details class="pdf-section" open><summary class="pdf-section-summary">' + sec.heading +
      '</summary><div class="pdf-section-body">' + sec.content + '</div></details>'
    : sec.content).join('');
}

function collapseAllBar() {
  return '<div class="pdf-sections-bar">' +
    '<button type="button" class="pdf-collapse-all" aria-label="Alle secties inklappen">' +
      '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" ' +
        'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">' +
        '<path d="M4 4l4 3 4-3"/><path d="M4 12l4-3 4 3"/></svg>' +
      '<span>Alles inklappen</span>' +
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
    const lbl = btn.querySelector('span');
    if (lbl) lbl.textContent = anyOpen ? 'Alles uitklappen' : 'Alles inklappen';
  });
}

function fmtDate(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return '';
  const mo = ['jan', 'feb', 'mrt', 'apr', 'mei', 'jun', 'jul', 'aug', 'sep', 'okt', 'nov', 'dec'];
  return d.getDate() + ' ' + mo[d.getMonth()] + ' ' + d.getFullYear();
}

function render(data) {
  document.title = data.title || 'PDF-analyse';
  $('gate').hidden = true;
  $('doc').hidden = false;
  $('doc-title').textContent = data.title || 'PDF-analyse';

  const bits = [];
  if (data.pageCount) bits.push(data.pageCount + ' pagina' + (data.pageCount === 1 ? '' : "'s"));
  if (data.created_at) bits.push('geanalyseerd ' + fmtDate(data.created_at));
  if (data.model) bits.push(data.model);
  $('doc-meta').textContent = bits.join(' · ');

  const bodyEl = $('doc-body');
  const hasPdf = !!(MANIFEST.entries && MANIFEST.entries.source);
  bodyEl.innerHTML = collapseAllBar() +
    '<div id="pdf-sections">' + (wrapSections(citeToSup(mdToHtml(data.html || ''))) || '<em>Geen inhoud.</em>') + '</div>';

  const sectionsEl = $('pdf-sections');
  wireCollapseAll(bodyEl);
  wireSearch(sectionsEl);
  sectionsEl.classList.toggle('pdf-cites-live', hasPdf);
  sectionsEl.addEventListener('click', (e) => {
    const cite = e.target.closest && e.target.closest('.pdf-cite');
    if (!cite || !hasPdf) return;
    e.preventDefault();
    const pages = (cite.getAttribute('data-pages') || '').split(',').filter(Boolean).map(Number);
    openPagePopup(parseInt(cite.getAttribute('data-page'), 10) || 1, pages);
  });

  $('doc-foot').textContent = hasPdf
    ? 'Klik op een paginaverwijzing om die pagina uit het originele PDF-document te bekijken.'
    : 'Het originele PDF-document is niet meegeleverd; paginaverwijzingen zijn niet aanklikbaar.';
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
