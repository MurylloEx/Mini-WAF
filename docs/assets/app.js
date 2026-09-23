/*
 * Mini-WAF docs — a tiny Markdown site with no build step.
 *
 * Every page is a .md file next to index.html, addressed by its real path:
 * "/guide/express" loads guide/express.md and "/" loads index.md. A section's
 * own page sits beside its folder ("/guide/integrations" is
 * guide/integrations.md) rather than inside it as index.md, because static
 * hosts answer a folder URL with any index.* file they find. The host serves
 * index.html for every extensionless path (see vercel.json). Navigation order
 * comes from _sidebar.md.
 */
(function () {
  'use strict';

  var CONFIG = {
    siteName: 'Mini-WAF',
    // Where "Edit this page" points: the docs/ folder of the repository.
    editBase: 'https://github.com/MurylloEx/Mini-WAF/edit/master/docs/',
  };

  var CALLOUT_TITLES = { tip: 'Tip', info: 'Note', warning: 'Warning', danger: 'Danger' };

  var cache = new Map();
  var pages = [];      // flat reading order: { path, title, group }
  var current = null;  // path of the rendered page
  var navigation = 0;  // bumps on every route() so a slow response cannot overwrite a newer page

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  // ---------------------------------------------------------------- utils

  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // Same shape as VitePress slugs, so existing "#the-requires-prefilter" links keep working.
  function slugify(text) {
    var s = text
      .normalize('NFKD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/[\u0000-\u001f]/g, '')
      .replace(/[\s~`!@#$%^&*()\-_+=[\]{}|\\;:"'“”‘’<>,.?/]+/g, '-')
      .replace(/-{2,}/g, '-')
      .replace(/^-+|-+$/g, '')
      .toLowerCase();
    return /^\d/.test(s) ? '_' + s : s;
  }

  function uniqueSlugger() {
    var seen = Object.create(null);
    return function (text) {
      var base = slugify(text) || 'section';
      if (!(base in seen)) { seen[base] = 0; return base; }
      seen[base] += 1;
      return base + '-' + seen[base];
    };
  }

  function fileFor(path) {
    return (path === '/' ? '/index' : path) + '.md';
  }

  function load(path) {
    var file = fileFor(path);
    if (!cache.has(file)) {
      cache.set(file, fetch(file).then(function (r) {
        if (!r.ok) throw new Error(r.status + ' ' + file);
        return r.text();
      }));
    }
    return cache.get(file);
  }

  // A trailing slash is only a spelling of the same page: "/guide/integrations/"
  // is "/guide/integrations".
  function canonical(path) {
    return path.replace(/\/index\.html$/, '/').replace(/(.)\/+$/, '$1') || '/';
  }

  function currentLocation() {
    return {
      path: canonical(decodeURI(location.pathname)),
      anchor: decodeURIComponent(location.hash.replace(/^#/, '')),
    };
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } finally { ta.remove(); }
    return Promise.resolve();
  }

  // ------------------------------------------------------------ markdown

  // Strips front matter and turns VitePress-style "::: tip Title" containers
  // into callout blocks, leaving fenced code untouched.
  function preprocess(md) {
    md = md.replace(/^---\n[\s\S]*?\n---\n/, '').replace(/\sv-pre(?=[\s>])/g, '');
    var out = [];
    var fence = null;
    md.split('\n').forEach(function (line) {
      var f = line.match(/^\s*(`{3,}|~{3,})/);
      if (f) {
        if (!fence) fence = f[1];
        else if (line.trim().indexOf(fence) === 0) fence = null;
        out.push(line);
        return;
      }
      if (fence) { out.push(line); return; }
      var open = line.match(/^:::\s*(tip|info|warning|danger)\s*(.*)$/);
      if (open) {
        var type = open[1];
        var title = open[2].trim() || CALLOUT_TITLES[type];
        out.push('', '<div class="callout callout-' + type + '"><p class="callout-title">' +
          marked.parseInline(title) + '</p>', '');
        return;
      }
      if (/^:::\s*$/.test(line)) { out.push('', '</div>', ''); return; }
      out.push(line);
    });
    return out.join('\n');
  }

  marked.use({ gfm: true });

  function render(md) {
    return marked.parse(preprocess(md));
  }

  // ------------------------------------------------------------- enhance

  var TITLE_LINE = /^(?:\/\/|#)\s+((?:[\w@.[\]-]+\/)*[\w@.[\]-]+\.(?:ts|tsx|js|mjs|cjs|json|ya?ml|sh|md))(?:\s+\((.+)\))?\s*$/;

  function enhanceCode(root) {
    $$('pre > code', root).forEach(function (code) {
      var pre = code.parentElement;
      var m = (code.className || '').match(/language-([\w-]+)/);
      var lang = m ? m[1] : '';
      var text = code.textContent.replace(/\n$/, '');
      var title = '';
      var note = '';

      var lines = text.split('\n');
      var t = lines[0].match(TITLE_LINE);
      if (t && lines.length > 1) {
        title = t[1]; note = t[2] || '';
        text = lines.slice(1).join('\n');
      }

      var language = lang === 'ts' ? 'typescript' : lang === 'sh' ? 'bash' : lang;
      if (language && window.hljs && hljs.getLanguage(language)) {
        code.innerHTML = hljs.highlight(text, { language: language, ignoreIllegals: true }).value;
      } else {
        code.textContent = text;
      }
      code.classList.add('hljs');

      var wrap = document.createElement('div');
      wrap.className = 'code' + (lang === 'bash' || lang === 'sh' ? ' code-shell' : '');
      var head = document.createElement('div');
      head.className = 'code-head';
      var label = title
        ? '<span class="code-file">' + escapeHtml(title) + '</span>' + (note ? '<span class="code-note">' + escapeHtml(note) + '</span>' : '')
        : '<span class="code-lang">' + escapeHtml(lang === 'ts' ? 'typescript' : lang || 'text') + '</span>';
      head.innerHTML = '<span class="code-dots"><i></i><i></i><i></i></span>' + label +
        '<button class="code-copy" type="button">Copy</button>';
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(head);
      wrap.appendChild(pre);

      head.querySelector('.code-copy').addEventListener('click', function (e) {
        var btn = e.currentTarget;
        copyText(text).then(function () {
          btn.textContent = 'Copied'; btn.classList.add('done');
          setTimeout(function () { btn.textContent = 'Copy'; btn.classList.remove('done'); }, 1400);
        });
      });
    });
  }

  function enhanceHeadings(root, path) {
    var slug = uniqueSlugger();
    $$('h1, h2, h3, h4', root).forEach(function (h) {
      h.id = slug(h.textContent);
      if (h.tagName === 'H1') return;
      var a = document.createElement('a');
      a.className = 'h-anchor';
      a.href = '#' + h.id;
      a.setAttribute('aria-label', 'Link to this section');
      a.textContent = '#';
      h.appendChild(a);
    });
  }

  function enhanceLinks(root) {
    $$('a[href]', root).forEach(function (a) {
      var href = a.getAttribute('href');
      if (/^https?:\/\//.test(href)) {
        a.target = '_blank'; a.rel = 'noopener';
        if (!a.closest('.btn, .fw')) a.classList.add('external');
      }
    });
  }

  function enhanceTables(root) {
    $$('table', root).forEach(function (t) {
      var w = document.createElement('div');
      w.className = 'table-wrap';
      t.parentNode.insertBefore(w, t);
      w.appendChild(t);
    });
  }

  function enhanceWidgets(root) {
    $$('[data-copy]', root).forEach(function (el) {
      el.addEventListener('click', function () {
        copyText(el.getAttribute('data-copy')).then(function () {
          el.classList.add('done');
          setTimeout(function () { el.classList.remove('done'); }, 1400);
        });
      });
    });

    $$('[data-levels]', root).forEach(function (box) {
      var tabs = $$('[data-level]', box);
      var max = Math.max.apply(null, tabs.map(function (t) { return +t.dataset.count; }));
      function pick(tab) {
        tabs.forEach(function (t) {
          var on = t === tab;
          t.classList.toggle('active', on);
          t.setAttribute('aria-selected', on ? 'true' : 'false');
        });
        box.dataset.active = tab.dataset.level;
        $('[data-out="count"]', box).textContent = tab.dataset.count;
        $('[data-out="desc"]', box).textContent = tab.dataset.desc;
        $('[data-out="fill"]', box).style.width = (100 * tab.dataset.count / max) + '%';
      }
      tabs.forEach(function (t) { t.addEventListener('click', function () { pick(t); }); });
      pick(tabs.filter(function (t) { return t.dataset.level === 'balanced'; })[0] || tabs[0]);
    });
  }

  // ------------------------------------------------------------- sidebar

  function parseSidebar(md) {
    var groups = [];
    md.replace(/<!--[\s\S]*?-->/g, '').split('\n').forEach(function (line) {
      var link = line.match(/^(\s*)-\s+\[(.+?)\]\((.+?)\)\s*$/);
      var head = line.match(/^-\s+([^[].*?)\s*$/);
      if (link) {
        if (!groups.length || !link[1]) groups.push({ title: '', items: [] });
        groups[groups.length - 1].items.push({ title: link[2], path: link[3] });
      } else if (head) {
        groups.push({ title: head[1], items: [] });
      }
    });
    return groups;
  }

  function collapsedState() {
    try { return JSON.parse(localStorage.getItem('mw-collapsed') || '{}'); } catch (e) { return {}; }
  }

  function buildSidebar(groups) {
    var nav = $('#sidebar-nav');
    var collapsed = collapsedState();
    nav.innerHTML = groups.map(function (g) {
      var items = g.items.map(function (it) {
        return '<li><a href="' + it.path + '" data-path="' + it.path + '">' + escapeHtml(it.title) + '</a></li>';
      }).join('');
      if (!g.title) return '<ul class="nav-list">' + items + '</ul>';
      var closed = collapsed[g.title] ? ' closed' : '';
      return '<div class="nav-group' + closed + '" data-group="' + escapeHtml(g.title) + '">' +
        '<button class="nav-group-title" type="button">' + escapeHtml(g.title) +
        '<svg viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg></button>' +
        '<ul class="nav-list">' + items + '</ul></div>';
    }).join('');

    $$('.nav-group-title', nav).forEach(function (btn) {
      btn.addEventListener('click', function () {
        var g = btn.parentElement;
        g.classList.toggle('closed');
        var state = collapsedState();
        state[g.dataset.group] = g.classList.contains('closed');
        try { localStorage.setItem('mw-collapsed', JSON.stringify(state)); } catch (e) {}
      });
    });
  }

  function markActive(path) {
    $$('#sidebar-nav a').forEach(function (a) {
      var on = a.dataset.path === path;
      a.classList.toggle('active', on);
      if (on) {
        var g = a.closest('.nav-group');
        if (g) g.classList.remove('closed');
        var nav = $('.sidebar');
        var r = a.getBoundingClientRect(), n = nav.getBoundingClientRect();
        if (r.top < n.top + 60 || r.bottom > n.bottom - 60) a.scrollIntoView({ block: 'center' });
      }
    });
  }

  // ------------------------------------------------------ toc & progress

  var tocHeadings = [];

  function buildToc(root, path) {
    var toc = $('#toc');
    tocHeadings = $$('h2, h3', root);
    if (tocHeadings.length < 2) { toc.innerHTML = ''; return; }
    toc.innerHTML = '<p class="toc-title">On this page</p><ul>' + tocHeadings.map(function (h) {
      var text = h.firstChild ? h.textContent.replace(/#$/, '') : '';
      return '<li class="toc-' + h.tagName.toLowerCase() + '"><a href="#' + h.id + '" data-id="' + h.id + '">' +
        escapeHtml(text) + '</a></li>';
    }).join('') + '<span class="toc-marker"></span></ul>' +
      '<a class="toc-top" href="' + path + '" data-action="top">Back to top ↑</a>';
    spy();
  }

  function spy() {
    var bar = $('.progress span');
    var doc = document.documentElement;
    var max = doc.scrollHeight - doc.clientHeight;
    bar.style.transform = 'scaleX(' + (max > 0 ? Math.min(1, doc.scrollTop / max) : 0) + ')';

    if (!tocHeadings.length) return;
    var active = tocHeadings[0];
    var nearBottom = doc.scrollTop >= max - 4;
    tocHeadings.forEach(function (h) { if (h.getBoundingClientRect().top < 140) active = h; });
    if (nearBottom) active = tocHeadings[tocHeadings.length - 1];
    var marker = $('.toc-marker');
    $$('#toc a[data-id]').forEach(function (a) {
      var on = a.dataset.id === active.id;
      a.classList.toggle('active', on);
      if (on && marker) {
        marker.style.transform = 'translateY(' + a.offsetTop + 'px)';
        marker.style.height = a.offsetHeight + 'px';
        marker.style.opacity = '1';
      }
    });
  }

  var ticking = false;
  window.addEventListener('scroll', function () {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(function () { ticking = false; spy(); });
  }, { passive: true });

  // -------------------------------------------------------------- pager

  function buildPager(path) {
    var pager = $('#pager');
    var i = pages.findIndex(function (p) { return p.path === path; });
    if (i === -1) { pager.innerHTML = ''; return; }
    var prev = pages[i - 1], next = pages[i + 1];
    pager.innerHTML =
      (prev ? '<a class="pager-link prev" href="' + prev.path + '"><span>Previous</span><strong>' + escapeHtml(prev.title) + '</strong></a>' : '<span></span>') +
      (next ? '<a class="pager-link next" href="' + next.path + '"><span>Next</span><strong>' + escapeHtml(next.title) + '</strong></a>' : '<span></span>');
  }

  function buildFoot(path, words) {
    var foot = $('#page-foot');
    if (path === '/') { foot.innerHTML = ''; return; }
    var file = fileFor(path).slice(1);
    var minutes = Math.max(1, Math.round(words / 220));
    foot.innerHTML =
      '<a class="edit" href="' + CONFIG.editBase + file + '" target="_blank" rel="noopener">' +
      '<svg viewBox="0 0 24 24"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>Edit this page on GitHub</a>' +
      '<span>' + minutes + ' min read</span>';
  }

  // ------------------------------------------------------------- router

  function scrollToAnchor(anchor, smooth) {
    if (!anchor) { window.scrollTo(0, 0); return; }
    var el = document.getElementById(anchor);
    if (el) el.scrollIntoView({ behavior: smooth ? 'smooth' : 'auto', block: 'start' });
  }

  // Keeps the scroll position with each history entry, so "back" returns to
  // where the reader was once the previous page has been rendered again.
  if ('scrollRestoration' in history) history.scrollRestoration = 'manual';

  function navigate(url) {
    history.replaceState({ y: window.scrollY }, '');
    history.pushState(null, '', url);
    route(null);
  }

  function isInternal(a) {
    return a.origin === location.origin && !a.target && !a.hasAttribute('download') &&
      !/^\/assets\//.test(a.pathname) && !/\.md$/.test(a.pathname);
  }

  function route(restoreY) {
    var r = currentLocation();
    var ticket = ++navigation;
    document.body.classList.remove('menu-open');

    if (r.path === current) { scrollToAnchor(r.anchor, true); return; }

    var doc = $('#doc');
    doc.classList.add('leaving');
    load(r.path).then(function (md) {
      if (ticket !== navigation) return;
      current = r.path;
      var isHome = r.path === '/';
      document.documentElement.classList.toggle('is-home', isHome);
      doc.innerHTML = render(md);

      var page = pages.filter(function (p) { return p.path === r.path; })[0];
      var h1 = $('h1', doc);
      if (page && page.group && h1) {
        var eyebrow = document.createElement('p');
        eyebrow.className = 'doc-eyebrow';
        eyebrow.textContent = page.group;
        h1.parentNode.insertBefore(eyebrow, h1);
      }

      enhanceHeadings(doc, r.path);
      enhanceLinks(doc);
      enhanceCode(doc);
      enhanceTables(doc);
      enhanceWidgets(doc);

      document.title = isHome || !h1
        ? CONFIG.siteName + ' · Web Application Firewall for Node.js'
        : h1.textContent + ' · ' + CONFIG.siteName;

      buildToc(doc, r.path);
      buildPager(r.path);
      buildFoot(r.path, doc.textContent.split(/\s+/).length);
      markActive(r.path);
      doc.classList.remove('leaving');
      if (typeof restoreY === 'number') window.scrollTo(0, restoreY);
      else scrollToAnchor(r.anchor, false);
      spy();
      // Web fonts can shift the layout after the first paint; re-align once they settle.
      if (r.anchor && document.fonts) document.fonts.ready.then(function () { scrollToAnchor(r.anchor, false); });
      ready();
    }).catch(function () {
      if (ticket !== navigation) return;
      current = null;
      document.documentElement.classList.toggle('is-home', false);
      doc.innerHTML = '<div class="notfound"><p class="doc-eyebrow">404</p><h1>This page slipped past the wall.</h1>' +
        '<p>There is no document at <code>' + escapeHtml(r.path) + '</code>.</p>' +
        '<p><a class="btn btn-primary" href="/">Back home</a></p></div>';
      $('#toc').innerHTML = ''; $('#pager').innerHTML = ''; $('#page-foot').innerHTML = '';
      doc.classList.remove('leaving');
      ready();
    });
  }

  // Reveals the content area once the first page has been rendered (see the
  // boot script in index.html).
  function ready() {
    delete document.documentElement.dataset.boot;
  }

  // -------------------------------------------------------------- search

  var index = null;

  function buildIndex() {
    if (index) return index;
    index = Promise.all(pages.map(function (p) {
      return load(p.path).then(function (md) { return { page: p, md: md }; }, function () { return null; });
    })).then(function (docs) {
      var entries = [];
      docs.forEach(function (d) {
        if (!d) return;
        var slug = uniqueSlugger();
        var fence = false;
        var section = { page: d.page, heading: d.page.title, anchor: '', text: [] };
        entries.push(section);
        preprocess(d.md).split('\n').forEach(function (line) {
          if (/^\s*(```|~~~)/.test(line)) { fence = !fence; return; }
          var h = !fence && line.match(/^(#{1,4})\s+(.+)$/);
          if (h) {
            var plain = h[2].replace(/`/g, '').replace(/\[(.+?)\]\(.+?\)/g, '$1');
            var id = slug(plain);
            if (h[1].length === 1) { section.anchor = ''; return; }
            section = { page: d.page, heading: plain, anchor: id, text: [] };
            entries.push(section);
            return;
          }
          section.text.push(line);
        });
      });
      entries.forEach(function (e) {
        e.text = e.text.join(' ')
          .replace(/<[^>]+>/g, ' ')
          .replace(/\[(.+?)\]\(.+?\)/g, '$1')
          .replace(/[`*>|#]+/g, ' ')
          .replace(/\s+/g, ' ')
          .trim();
        e.hay = (e.heading + ' ' + e.text).toLowerCase();
      });
      return entries;
    });
    return index;
  }

  function snippet(text, terms) {
    var lower = text.toLowerCase();
    var at = -1;
    terms.forEach(function (t) { var i = lower.indexOf(t); if (i !== -1 && (at === -1 || i < at)) at = i; });
    var start = Math.max(0, at - 50);
    var s = (start > 0 ? '…' : '') + text.slice(start, start + 150) + (text.length > start + 150 ? '…' : '');
    var html = escapeHtml(s);
    terms.forEach(function (t) {
      html = html.replace(new RegExp('(' + escapeHtml(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi'), '<mark>$1</mark>');
    });
    return html;
  }

  var results = [];
  var selected = 0;

  function runSearch(q) {
    var list = $('#palette-results');
    var terms = q.toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) {
      results = ['/guide/quick-start', '/guide/presets', '/guide/protection-levels', '/guide/integrations/express', '/guide/configuration']
        .map(function (path) {
          var p = pages.filter(function (x) { return x.path === path; })[0];
          return p && { page: p, heading: p.title, anchor: '', text: p.group };
        }).filter(Boolean);
      selected = 0;
      paint(list, results, [], 'Popular pages');
      return;
    }
    buildIndex().then(function (entries) {
      results = entries.map(function (e) {
        var score = 0;
        var head = e.heading.toLowerCase();
        for (var i = 0; i < terms.length; i++) {
          var t = terms[i];
          if (e.hay.indexOf(t) === -1) return null;
          if (head.indexOf(t) !== -1) score += 10;
          if (e.page.title.toLowerCase().indexOf(t) !== -1) score += 4;
          score += Math.min(5, e.hay.split(t).length - 1);
        }
        if (head.indexOf(q.toLowerCase()) !== -1) score += 20;
        if (!e.anchor) score += 2;
        return { e: e, score: score };
      }).filter(Boolean).sort(function (a, b) { return b.score - a.score; })
        .slice(0, 14).map(function (r) { return r.e; });
      selected = 0;
      paint(list, results, terms, '');
    });
  }

  function paint(list, items, terms, label) {
    if (!items.length) {
      list.innerHTML = '<li class="palette-empty">No results. Try a rule id like <code>preset-sqli</code> or an option like <code>decisionCache</code>.</li>';
      return;
    }
    list.innerHTML = (label ? '<li class="palette-label">' + label + '</li>' : '') + items.map(function (e, i) {
      var href = e.page.path + (e.anchor ? '#' + e.anchor : '');
      var crumb = e.anchor ? escapeHtml(e.page.title) + ' <span>›</span> ' : escapeHtml(e.page.group || '') + (e.page.group ? ' <span>›</span> ' : '');
      return '<li role="option"' + (i === selected ? ' class="sel" aria-selected="true"' : '') + '>' +
        '<a href="' + href + '" data-i="' + i + '">' +
        '<span class="r-crumb">' + crumb + '</span>' +
        '<span class="r-title">' + (terms.length ? snippet(e.heading, terms) : escapeHtml(e.heading)) + '</span>' +
        (terms.length && e.text ? '<span class="r-text">' + snippet(e.text, terms) + '</span>' : '') +
        '</a></li>';
    }).join('');
  }

  function moveSelection(delta) {
    var items = $$('#palette-results li[role="option"]');
    if (!items.length) return;
    selected = (selected + delta + items.length) % items.length;
    items.forEach(function (li, i) {
      li.classList.toggle('sel', i === selected);
      if (i === selected) li.scrollIntoView({ block: 'nearest' });
    });
  }

  function openSearch() {
    var p = $('#palette');
    p.hidden = false;
    document.body.classList.add('palette-open');
    var input = $('#palette-q');
    input.value = '';
    runSearch('');
    setTimeout(function () { input.focus(); }, 0);
    buildIndex();
  }

  function closeSearch() {
    $('#palette').hidden = true;
    document.body.classList.remove('palette-open');
  }

  // -------------------------------------------------------------- ripple

  // Every clickable element answers a click with a ripple. It is drawn in an
  // overlay sized to the element (same corners, clipped), so no element needs
  // its own positioning or overflow rules, and inline links work too. The
  // ripple takes the element's text colour: white on the red button, red on
  // links, grey on neutral controls.
  var CLICKABLE = 'a[href], button, [role="tab"], [role="option"], summary';
  var calm = window.matchMedia('(prefers-reduced-motion: reduce)');

  function ripple(el, x, y) {
    var rect = el.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    var style = getComputedStyle(el);
    // Elements inside the fixed/sticky chrome move with the viewport; the rest
    // move with the page, so the overlay follows the same frame of reference.
    var pinned = !!el.closest('.topbar, .sidebar, .toc, .palette');
    var layer = document.createElement('span');
    layer.className = 'ripple-layer';
    layer.style.position = pinned ? 'fixed' : 'absolute';
    layer.style.left = rect.left + (pinned ? 0 : window.scrollX) + 'px';
    layer.style.top = rect.top + (pinned ? 0 : window.scrollY) + 'px';
    layer.style.width = rect.width + 'px';
    layer.style.height = rect.height + 'px';
    layer.style.borderRadius = style.borderRadius;
    layer.style.color = style.color;

    var cx = x - rect.left, cy = y - rect.top;
    var r = Math.hypot(Math.max(cx, rect.width - cx), Math.max(cy, rect.height - cy));
    var wave = document.createElement('span');
    wave.className = 'ripple';
    wave.style.width = wave.style.height = 2 * r + 'px';
    wave.style.left = cx - r + 'px';
    wave.style.top = cy - r + 'px';
    layer.appendChild(wave);
    document.body.appendChild(layer);
    wave.addEventListener('animationend', function () { layer.remove(); });
  }

  document.addEventListener('pointerdown', function (e) {
    if (calm.matches || e.button !== 0) return;
    var el = e.target.closest(CLICKABLE);
    if (el) ripple(el, e.clientX, e.clientY);
  });

  // Keyboard activation (Enter/Space) has no pointer position: ripple from the centre.
  document.addEventListener('click', function (e) {
    if (calm.matches || e.detail !== 0) return;
    var el = e.target.closest(CLICKABLE);
    if (!el) return;
    var rect = el.getBoundingClientRect();
    ripple(el, rect.left + rect.width / 2, rect.top + rect.height / 2);
  });

  // --------------------------------------------------------------- wiring

  function toggleTheme() {
    var root = document.documentElement;
    var dark = root.dataset.theme
      ? root.dataset.theme === 'dark'
      : window.matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
    try { localStorage.setItem('mw-theme', root.dataset.theme); } catch (e) {}
  }

  document.addEventListener('click', function (e) {
    var el = e.target.closest('[data-action]');
    if (!el) {
      var a = e.target.closest('a[href]');
      if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      if (a.closest('#palette-results')) closeSearch();
      // Same-page anchors are left to the browser; other internal links are routed here.
      if (isInternal(a) && canonical(a.pathname) !== location.pathname) {
        e.preventDefault();
        navigate(canonical(a.pathname) + a.hash);
      }
      return;
    }
    var action = el.dataset.action;
    if (action === 'top') {
      e.preventDefault();
      history.replaceState(history.state, '', location.pathname);
      window.scrollTo({ top: 0, behavior: 'smooth' });
      return;
    }
    if (action === 'search') openSearch();
    else if (action === 'close-search') closeSearch();
    else if (action === 'theme') toggleTheme();
    else if (action === 'menu') document.body.classList.toggle('menu-open');
    else if (action === 'close-menu') document.body.classList.remove('menu-open');
  });

  $('#palette-q').addEventListener('input', function (e) { runSearch(e.target.value.trim()); });

  document.addEventListener('keydown', function (e) {
    var typing = /INPUT|TEXTAREA|SELECT/.test((e.target.tagName || '')) || e.target.isContentEditable;
    var open = !$('#palette').hidden;
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); open ? closeSearch() : openSearch(); return; }
    if (open) {
      if (e.key === 'Escape') { closeSearch(); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); moveSelection(1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); moveSelection(-1); }
      else if (e.key === 'Enter') {
        var a = $('#palette-results li.sel a');
        if (a) { e.preventDefault(); closeSearch(); navigate(a.getAttribute('href')); }
      }
      return;
    }
    if (typing) return;
    if (e.key === '/') { e.preventDefault(); openSearch(); }
    else if (e.key === '[' || e.key === ']') {
      var link = $(e.key === '[' ? '.pager-link.prev' : '.pager-link.next');
      if (link) navigate(link.getAttribute('href'));
    }
  });

  if (/Mac|iPhone|iPad/.test(navigator.platform)) $('.search-trigger kbd').textContent = '⌘ K';

  window.addEventListener('popstate', function (e) {
    route(e.state && typeof e.state.y === 'number' ? e.state.y : null);
  });

  // Links shared while the site used "#/guide/x" addresses still land on the page.
  if (/^#\//.test(location.hash)) history.replaceState(null, '', location.hash.slice(1));
  if (canonical(location.pathname) !== location.pathname) {
    history.replaceState(null, '', canonical(location.pathname) + location.search + location.hash);
  }

  // Fetch the navigation and the requested page in parallel; route() then
  // renders both in one pass (load() caches, so the page is not fetched twice).
  load(currentLocation().path).catch(function () {});
  load('/_sidebar').then(function (md) {
    var groups = parseSidebar(md);
    groups.forEach(function (g) {
      g.items.forEach(function (it) { pages.push({ path: it.path, title: it.title, group: g.title }); });
    });
    buildSidebar(groups);
  }).catch(function () {}).then(function () { route(null); });
})();
