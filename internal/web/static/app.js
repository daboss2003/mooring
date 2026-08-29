// Minimal client glue. The admin CSP is script-src 'self' (no inline scripts),
// so all behavior lives here. For now this only wires the CSRF token into any
// future htmx requests; htmx/Alpine are vendored in a later milestone (M7).
(function () {
  "use strict";
  var meta = document.querySelector('meta[name="csrf-token"]');
  var token = meta ? meta.getAttribute("content") : "";
  // When htmx is present (vendored in a later milestone), attach the token.
  document.body.addEventListener("htmx:configRequest", function (evt) {
    if (token) evt.detail.headers["X-CSRF-Token"] = token;
  });

  // ---- localise server timestamps to the viewer's own timezone ----
  // The server renders every instant as <time data-ts="<unix-seconds>">…UTC</time>
  // (the CSP forbids inline JS, so it can't localise itself). Here we rewrite each
  // element's text to the browser's local timezone — so an operator in WAT/IST/PST
  // sees their own wall-clock, not UTC. Re-run over any fragment swapped in by the
  // live poller below. The <time> fallback text stays valid (labelled UTC) if this
  // never runs. Uses textContent only (never innerHTML) — CSP/XSS-safe.
  var TS_FMT;
  try {
    TS_FMT = new Intl.DateTimeFormat(undefined, {
      year: "numeric", month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      timeZoneName: "short",
    });
  } catch (_) { TS_FMT = null; }
  function localizeTimes(root) {
    var scope = root || document;
    var nodes = scope.querySelectorAll ? scope.querySelectorAll("time[data-ts]") : [];
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      if (el.getAttribute("data-localized") === "1") continue;
      var ts = parseInt(el.getAttribute("data-ts"), 10);
      if (!ts || isNaN(ts)) continue;
      var d = new Date(ts * 1000);
      el.textContent = TS_FMT ? TS_FMT.format(d) : d.toLocaleString();
      el.setAttribute("title", d.toString());
      el.setAttribute("data-localized", "1");
    }
  }
  localizeTimes(document);

  // Lifecycle + log streaming (M4). Buttons carry data-lc-url (POST, streamed
  // response) or data-log-url (GET, SSE). The CSRF token rides the header.
  var logSource = null; // the SSE EventSource for the live log stream (null when idle)

  // ---- filterable streaming panes (live logs + deploy/build output) ----
  // A pane is a <pre id="X-output">. If a toolbar <div id="X-tools"> with an
  // <input id="X-filter"> + <span id="X-count"> exists, the pane gains a live word-filter:
  // every line is buffered ON the element (pre._lines) so the filter can re-scan the whole
  // stream, and only lines containing the filter word (case-insensitive) are shown. All
  // writes are textContent (never innerHTML) — hostile stream output is inert.
  function paneParts(pre) {
    var base = pre.id.replace(/-output$/, "");
    return {
      tools: document.getElementById(base + "-tools"),
      filter: document.getElementById(base + "-filter"),
      count: document.getElementById(base + "-count"),
    };
  }
  // paneTerms returns the filter split into words (lowercased). A line must contain
  // EVERY word to match (AND filter) — so "error worker" shows only lines mentioning both,
  // in any order. Empty ⇒ no filter (show all).
  function paneTerms(pre) {
    var f = paneParts(pre).filter;
    if (!f) return [];
    return f.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  }
  // lineMatches reports whether a line contains all the terms (case-insensitive substrings).
  function lineMatches(line, terms) {
    if (!terms.length) return true;
    var ll = line.toLowerCase();
    for (var i = 0; i < terms.length; i++) { if (ll.indexOf(terms[i]) === -1) return false; }
    return true;
  }
  // streamLevel classifies a log line's severity for color-coding — mirrors the server-side logLevel
  // (internal/web/service_logs_page.go) so the live tail and the retained history color the same way.
  // A level keyword (whole-token) classifies; a status code counts only as a status FIELD's value, so a
  // bare number like a responseTime is not mistaken for a 5xx. Returns "error" | "warn" | "debug" | "".
  var STREAM_ERR = { error: 1, err: 1, errors: 1, fatal: 1, panic: 1, critical: 1, crit: 1, alert: 1, emerg: 1, emergency: 1, exception: 1, severe: 1, failure: 1 };
  var STREAM_WARN = { warn: 1, warning: 1 };
  var STREAM_DEBUG = { debug: 1, trace: 1, verbose: 1 };
  var STREAM_STATUS_RE = /status(?:_?code)?["']?[ \t]*[:=][ \t]*["']?([1-5][0-9][0-9])\b/g;
  function streamLevel(line) {
    var hasErr = false, hasWarn = false, hasDebug = false, lower = line.toLowerCase(), tok = "";
    function classify() {
      if (!tok) return;
      // === 1 (not truthiness): a plain object inherits Object.prototype.constructor etc., so a bare
      // STREAM_ERR["constructor"] lookup would be truthy and mis-color stack-trace lines.
      if (STREAM_ERR[tok] === 1) hasErr = true;
      else if (STREAM_WARN[tok] === 1) hasWarn = true;
      else if (STREAM_DEBUG[tok] === 1) hasDebug = true;
      tok = "";
    }
    for (var i = 0; i < lower.length; i++) {
      var ch = lower.charAt(i);
      if ((ch >= "a" && ch <= "z") || (ch >= "0" && ch <= "9")) tok += ch;
      else classify();
    }
    classify();
    STREAM_STATUS_RE.lastIndex = 0;
    var m;
    while ((m = STREAM_STATUS_RE.exec(lower)) !== null) {
      if (m[1].charAt(0) === "5") hasErr = true;
      else if (m[1].charAt(0) === "4") hasWarn = true;
    }
    return hasErr ? "error" : hasWarn ? "warn" : hasDebug ? "debug" : "";
  }
  // streamLineEl builds one colorized line element (textContent only — never innerHTML, so a hostile
  // log line can't inject markup).
  function streamLineEl(line) {
    var div = document.createElement("div");
    div.className = "stream-line";
    var lvl = streamLevel(line);
    if (lvl) div.classList.add("lvl-" + lvl);
    div.textContent = line;
    return div;
  }
  function updateStreamCount(pre) {
    var p = paneParts(pre);
    if (!p.count) return;
    var q = p.filter ? p.filter.value.trim() : "";
    p.count.textContent = q ? (pre._shown + " / " + pre._lines.length + " matching") : (pre._lines.length + " lines");
  }
  // renderStream rebuilds the pane from its buffer under the current filter (on filter change);
  // live lines are appended incrementally below so streaming stays cheap.
  function renderStream(pre) {
    if (!pre._lines) return;
    var terms = paneTerms(pre);
    var shown = terms.length ? pre._lines.filter(function (l) { return lineMatches(l, terms); }) : pre._lines;
    pre._shown = shown.length;
    if (pre._colorize) {
      pre.textContent = "";
      var frag = document.createDocumentFragment();
      for (var i = 0; i < shown.length; i++) frag.appendChild(streamLineEl(shown[i]));
      pre.appendChild(frag);
    } else {
      pre.textContent = shown.length ? shown.join("\n") + "\n" : "";
    }
    pre.scrollTop = pre.scrollHeight;
    updateStreamCount(pre);
  }
  // startStream resets a pane's buffer and reveals/wires its filter toolbar (if any).
  function startStream(pre) {
    pre._lines = []; pre._pending = ""; pre._shown = 0;
    pre.textContent = "";
    var p = paneParts(pre);
    if (p.tools) p.tools.hidden = false;
    if (p.filter) {
      p.filter.value = ""; // each open starts unfiltered (a page's stream input is shared)
      if (!p.filter.getAttribute("data-wired")) {
        p.filter.addEventListener("input", function () { renderStream(pre); });
        p.filter.setAttribute("data-wired", "1");
      }
    }
    updateStreamCount(pre);
  }
  // pushStreamLine buffers one COMPLETE line and appends it if it matches the filter.
  function pushStreamLine(pre, line) {
    if (!pre._lines) pre._lines = [];
    pre._lines.push(line);
    if (pre._lines.length === 1) pre.textContent = ""; // drop any pre-stream placeholder
    if (lineMatches(line, paneTerms(pre))) {
      if (pre._colorize) pre.appendChild(streamLineEl(line));
      else pre.textContent += line + "\n";
      pre.scrollTop = pre.scrollHeight;
      pre._shown++;
    }
    updateStreamCount(pre);
  }
  // pushStreamChunk buffers a raw text chunk that may contain partial lines, holding the
  // trailing partial until its newline arrives (for byte-stream sources like deploy output).
  function pushStreamChunk(pre, text) {
    var buf = (pre._pending || "") + text;
    var parts = buf.split("\n");
    pre._pending = parts.pop();
    for (var i = 0; i < parts.length; i++) pushStreamLine(pre, parts[i]);
  }
  // flushStream emits any trailing partial line when the stream ends.
  function flushStream(pre) {
    if (pre._pending) { pushStreamLine(pre, pre._pending); pre._pending = ""; }
  }
  // teardownStream resets a pane's buffer + hides its toolbar (on Close). No-op for a
  // non-filterable pane (e.g. the config preview, which has no toolbar).
  function teardownStream(pre) {
    pre._lines = []; pre._pending = ""; pre._shown = 0;
    var p = paneParts(pre);
    if (p.tools) p.tools.hidden = true;
  }

  // showStream reveals a streaming <pre> (logs / deploy output) and ensures a "Close"
  // button sits just above it — so an opened log/output panel can always be dismissed
  // (closing also stops an active SSE log stream).
  function showStream(pre) {
    if (!pre) return;
    pre.hidden = false;
    var prev = pre.previousElementSibling;
    if (prev && prev.classList && prev.classList.contains("stream-close")) {
      prev.hidden = false;
      return;
    }
    var closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "stream-close btn btn-sm btn-ghost";
    closeBtn.textContent = "✕ Close";
    closeBtn.addEventListener("click", function () {
      // The SSE handle belongs to the log pane only — closing another stream (deploy
      // output, config preview) must not tear down a live log stream.
      if (pre.id === "log-output" && logSource) { logSource.close(); logSource = null; }
      teardownStream(pre); // reset this pane's buffer + hide its filter toolbar
      pre.hidden = true;
      pre.textContent = "";
      closeBtn.remove(); // drop the button entirely; showStream recreates it next open
    });
    pre.parentNode.insertBefore(closeBtn, pre);
  }

  document.addEventListener("click", function (evt) {
    var btn = evt.target.closest ? evt.target.closest("[data-lc-url],[data-log-url],[data-reveal-url]") : null;
    if (!btn) return;
    evt.preventDefault();

    // Reveal/hide a secret (toggle): audited POST → text/plain. Set textContent
    // (NEVER innerHTML) so a secret value can't become markup (plan §5.5).
    var revURL = btn.getAttribute("data-reveal-url");
    if (revURL) {
      var key = btn.getAttribute("data-reveal-key");
      var span = document.getElementById("reveal-" + key);
      if (!span) return;
      // Already revealed → re-hide by restoring the saved mask. No re-fetch.
      if (btn.getAttribute("data-revealed") === "1") {
        span.textContent = btn.getAttribute("data-mask") || "";
        btn.setAttribute("data-revealed", "0");
        btn.textContent = "reveal";
        return;
      }
      // First reveal: remember the mask so we can restore it on hide.
      if (btn.getAttribute("data-mask") === null) btn.setAttribute("data-mask", span.textContent);
      var body = new URLSearchParams(); body.set("key", key);
      fetch(revURL, {
        method: "POST", credentials: "same-origin",
        headers: { "X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      }).then(function (r) { return r.ok ? r.text() : null; })
        .then(function (txt) {
          if (txt !== null) {
            span.textContent = txt;
            btn.setAttribute("data-revealed", "1");
            btn.textContent = "hide";
          }
        }).catch(function () {});
      return;
    }

    var logURL = btn.getAttribute("data-log-url");
    if (logURL) {
      var logOut = document.getElementById("log-output");
      if (!logOut) return;
      if (logSource) logSource.close();
      logOut._colorize = true; // color live log lines by severity (like the retained history)
      showStream(logOut);
      startStream(logOut); // reset buffer + reveal/wire the word-filter
      logOut.textContent = "… connecting to logs …";
      logSource = new EventSource(logURL);
      logSource.onmessage = function (e) { pushStreamLine(logOut, e.data); };
      logSource.onerror = function () {
        var end = document.createElement("div"); // append a node so the colored lines aren't flattened
        end.className = "stream-line muted"; end.textContent = "[log stream ended]";
        logOut.appendChild(end); logOut.scrollTop = logOut.scrollHeight; logSource.close();
      };
      return;
    }

    var lcURL = btn.getAttribute("data-lc-url");
    if (!lcURL) return;
    var confirmMsg = btn.getAttribute("data-lc-confirm");
    if (confirmMsg && !window.confirm(confirmMsg)) return;
    var out = document.getElementById("deploy-output");
    if (out) { showStream(out); startStream(out); pushStreamLine(out, "$ " + lcURL); } // filterable build/deploy log
    btn.disabled = true;
    fetch(lcURL, {
      method: "POST",
      credentials: "same-origin",
      headers: token ? { "X-CSRF-Token": token } : {},
    }).then(function (resp) {
      var reader = resp.body.getReader();
      var dec = new TextDecoder();
      function pump() {
        return reader.read().then(function (r) {
          if (r.done) { if (out) flushStream(out); btn.disabled = false; return; }
          if (out) pushStreamChunk(out, dec.decode(r.value, { stream: true }));
          return pump();
        });
      }
      return pump();
    }).catch(function (e) {
      if (out) { flushStream(out); pushStreamLine(out, "[request failed: " + e + "]"); }
      btn.disabled = false;
    });
  });

  // Config-file preview: POST template+bindings, render with secrets masked
  // server-side, show as textContent (never innerHTML).
  var pv = document.getElementById("cfg-preview-btn");
  if (pv) {
    pv.addEventListener("click", function () {
      var form = pv.closest("form");
      if (!form) return;
      var body = new URLSearchParams();
      body.set("template", form.querySelector("[name=template]").value);
      body.set("bindings", form.querySelector("[name=bindings]").value);
      var out = document.getElementById("cfg-preview");
      fetch(form.getAttribute("action") + "/preview", {
        method: "POST", credentials: "same-origin",
        headers: { "X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      }).then(function (r) { return r.text(); })
        .then(function (t) { if (out) { showStream(out); out.textContent = t; } })
        .catch(function () {});
    });
  }

  // Draggable tile grid (M7). Tiles carry data-project; on drop we persist the
  // new order to the server (CSRF via header). Delegated so it survives the live
  // poll re-render. Dragging never navigates (we cancel the click after a drag).
  var dragEl = null;
  var didDrag = false;
  document.addEventListener("dragstart", function (e) {
    var tile = e.target.closest ? e.target.closest(".tile[data-project]") : null;
    if (!tile) return;
    dragEl = tile;
    didDrag = true;
    try { e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", tile.getAttribute("data-project")); } catch (_) {}
  });
  document.addEventListener("dragover", function (e) {
    if (!dragEl) return;
    var grid = dragEl.parentNode;
    var over = e.target.closest ? e.target.closest(".tile[data-project]") : null;
    if (!over || over === dragEl || over.parentNode !== grid) return;
    e.preventDefault();
    var tiles = Array.prototype.slice.call(grid.children);
    if (tiles.indexOf(dragEl) < tiles.indexOf(over)) grid.insertBefore(dragEl, over.nextSibling);
    else grid.insertBefore(dragEl, over);
  });
  document.addEventListener("drop", function (e) {
    if (!dragEl) return;
    e.preventDefault();
    var grid = dragEl.parentNode;
    dragEl = null;
    var order = Array.prototype.map.call(grid.querySelectorAll(".tile[data-project]"), function (t) {
      return t.getAttribute("data-project");
    }).join(",");
    var body = new URLSearchParams(); body.set("order", order);
    fetch("/settings/tile-order", {
      method: "POST", credentials: "same-origin",
      headers: { "X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    }).catch(function () {});
  });
  // Swallow the click that fires at the end of a drag so a reorder doesn't also
  // navigate into the app.
  document.addEventListener("click", function (e) {
    if (!didDrag) return;
    didDrag = false;
    var tile = e.target.closest ? e.target.closest(".tile[data-project]") : null;
    if (tile) { e.preventDefault(); }
  }, true);

  // Confirm-on-submit for any form carrying data-confirm (CSP-safe; no inline JS).
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (form && form.getAttribute && form.getAttribute("data-confirm")) {
      if (!window.confirm(form.getAttribute("data-confirm"))) e.preventDefault();
    }
  });

  // dashFocused reports whether the dashboard is the thing the operator is actively
  // looking at: the tab is visible AND the window has focus. All the live refreshers
  // below skip work (and the keepalive ping below stops) while it's false — there is no
  // reason to fetch for a dashboard nobody is watching, AND the stopped keepalive is what
  // lets an unfocused/abandoned session idle out (see the focus-loss watchdog below).
  function dashFocused() { return document.visibilityState === "visible" && document.hasFocus(); }

  // onFocusedNow runs fn each time the dashboard regains focus (and once now if it
  // already is) — so returning (a tab switch OR a window focus) refreshes immediately
  // rather than waiting out the interval with stale data on screen.
  function onFocusedNow(fn) {
    var run = function () { if (dashFocused()) fn(); };
    run();
    document.addEventListener("visibilitychange", run);
    window.addEventListener("focus", run);
  }

  // ---- focused-dashboard heartbeat ----
  // Mooring never auto-deploys, so polling git when nobody is looking is wasted
  // server work. The page pings /dash/ping on load and every ~40s WHILE focused (and
  // immediately on regaining focus); the server's git poller only fetches within a
  // short window after a ping. Unfocused -> no pings -> no polling -> session idles out.
  (function heartbeat() {
    var ping = function () {
      if (!dashFocused()) return;
      fetch("/dash/ping", { credentials: "same-origin", redirect: "error", headers: { "X-Requested-With": "fetch" } })
        .catch(function () { /* transient; next tick */ });
    };
    onFocusedNow(ping);
    setInterval(ping, 40000);
  })();

  // ---- focus-loss logout watchdog ----
  // Security: if the dashboard is left unfocused (another tab/app/screen) for the
  // session idle window, log out. The keepalive above only runs while focused, so the
  // server-side session genuinely idles out on its own; this watchdog SURFACES that as a
  // redirect to /login instead of leaving a stale page. It polls /session/status, which
  // is NON-refreshing (server uses Peek there), so the probe never keeps the session
  // alive — and a 204 (another tab is keeping it alive) means "don't redirect yet".
  (function focusLogout() {
    var layout = document.querySelector("[data-layout]");
    if (!layout) return; // only the authed shell carries data-idle-ms
    var idleMs = parseInt(layout.getAttribute("data-idle-ms") || "0", 10);
    if (!idleMs || idleMs < 60000) return; // disabled / implausibly small
    var lostAt = dashFocused() ? 0 : Date.now();
    var checking = false;
    var goLogin = function () { window.location.replace("/login"); };
    var probe = function (onAlive) {
      if (checking) return;
      checking = true;
      fetch(sessionStatusURL(), { credentials: "same-origin", redirect: "error", headers: { "X-Requested-With": "fetch" } })
        .then(function (r) { if (r.status === 204) { if (onAlive) onAlive(); } else { goLogin(); } })
        .catch(function () { goLogin(); }) // unreachable/redirected => treat as logged out
        .finally(function () { checking = false; });
    };
    var onActive = function () {
      // Returned to the dashboard: if we were away past the deadline, verify the session
      // before trusting the page; otherwise just resume (the keepalive ping refreshes it).
      if (lostAt && Date.now() - lostAt >= idleMs) { probe(null); }
      lostAt = 0;
    };
    var onInactive = function () { if (!lostAt) lostAt = Date.now(); };
    // One handler for every active/inactive signal — a focus event must be re-checked
    // against dashFocused() (a hidden tab can receive a window-focus event without being
    // the focused dashboard, which must NOT reset the idle countdown).
    var sync = function () { dashFocused() ? onActive() : onInactive(); };
    document.addEventListener("visibilitychange", sync);
    window.addEventListener("focus", sync);
    window.addEventListener("blur", sync);
    setInterval(function () {
      if (dashFocused()) { lostAt = 0; return; }
      if (!lostAt) { lostAt = Date.now(); return; }
      if (Date.now() - lostAt < idleMs) return;
      probe(null); // past the deadline: 401 -> /login; 204 -> keep watching (don't reset)
    }, 30000);
    function sessionStatusURL() { return "/session/status"; }
  })();

  // Lightweight live refresh: any element with data-poll-url is periodically
  // refreshed by fetching that fragment and swapping its innerHTML. Same-origin,
  // GET-only, cookie-authenticated; CSP-safe (this file is script-src 'self').
  // Skipped while hidden; refreshes immediately on regaining focus.
  // swapPreserving replaces a fragment's HTML while keeping interactive state that a blind swap would
  // reset: which `<details data-key>` accordions are open, and each per-route filter's typed value
  // (re-applied after the swap). Used for the Errors page live refresh (opt-in via data-poll-preserve).
  function swapPreserving(el, html) {
    var openKeys = {}, filterVals = {}, focusKey = null;
    // Remember which route the keyboard is on (a focused <summary> or in-entry link), so the swap
    // doesn't drop focus to <body>. (A focused INPUT is handled earlier by skipping the refresh.)
    var ae = document.activeElement;
    if (ae && el.contains(ae)) {
      var fd = ae.closest ? ae.closest("details[data-key]") : null;
      if (fd) focusKey = fd.getAttribute("data-key");
    }
    el.querySelectorAll("details[data-key]").forEach(function (d) {
      var k = d.getAttribute("data-key");
      if (d.open) openKeys[k] = true;
      var inp = d.querySelector(".err-filter");
      if (inp && inp.value) filterVals[k] = inp.value;
    });
    el.innerHTML = html;
    localizeTimes(el); // localize BEFORE re-applying filters, so a time-substring filter matches the displayed text
    el.querySelectorAll("details[data-key]").forEach(function (d) {
      var k = d.getAttribute("data-key");
      if (openKeys[k]) d.open = true;
      if (filterVals[k] != null) {
        var inp = d.querySelector(".err-filter");
        if (inp) { inp.value = filterVals[k]; applyErrFilter(inp); }
      }
      if (focusKey && k === focusKey) {
        var sm = d.querySelector("summary");
        if (sm) { try { sm.focus({ preventScroll: true }); } catch (e) { sm.focus(); } }
      }
    });
  }

  document.querySelectorAll("[data-poll-url]").forEach(function (el) {
    var url = el.getAttribute("data-poll-url");
    var ms = parseInt(el.getAttribute("data-poll-interval") || "5000", 10);
    if (!url || ms < 1000) return;
    var preserve = el.hasAttribute("data-poll-preserve");
    var preserveScroll = el.hasAttribute("data-poll-preserve-scroll");
    var pull = function () {
      if (!dashFocused()) return;
      // Don't yank the fragment out from under someone typing a filter in it.
      if (preserve && el.contains(document.activeElement) && document.activeElement.tagName === "INPUT") return;
      fetch(url, { credentials: "same-origin", redirect: "error", headers: { "X-Requested-With": "fetch" } })
        .then(function (r) { return r.ok ? r.text() : null; })
        .then(function (html) {
          if (html === null) return;
          var sc = preserveScroll ? el.scrollTop : 0;
          var prevH = preserveScroll ? el.scrollHeight : 0;
          if (preserve) swapPreserving(el, html); else el.innerHTML = html;
          // The log list is newest-first, so new lines PREPEND. Pinned to the top (sc===0) → stay at
          // top to see them; scrolled down → anchor by the height delta so the read content doesn't move.
          if (preserveScroll) el.scrollTop = sc === 0 ? 0 : sc + (el.scrollHeight - prevH);
          localizeTimes(el);
        })
        .catch(function () { /* transient; try again next tick */ });
    };
    setInterval(pull, ms);
    document.addEventListener("visibilitychange", function () { if (dashFocused()) pull(); });
    window.addEventListener("focus", function () { if (dashFocused()) pull(); });
  });

  // ---- kind-aware forms (alert channels + rules): show ONLY the fields that apply ----
  // A `.kind-fields[data-kind="a b c"]` group is shown only when the form's
  // [data-kind-toggle] select is one of its listed kinds; the hidden groups' inputs are
  // DISABLED so they don't submit — a field name shared across kinds (e.g. `url`,
  // `threshold`) therefore never sends the wrong kind's value.
  (function kindFields() {
    document.querySelectorAll("select[data-kind-toggle]").forEach(function (sel) {
      var form = sel.closest("form");
      if (!form) return;
      function sync() {
        form.querySelectorAll(".kind-fields").forEach(function (g) {
          var kinds = (g.getAttribute("data-kind") || "").split(/\s+/);
          var on = kinds.indexOf(sel.value) !== -1;
          g.hidden = !on;
          g.querySelectorAll("input, select, textarea").forEach(function (i) { i.disabled = !on; });
        });
      }
      sel.addEventListener("change", sync);
      sync();
    });
  })();

  // ---- modal dialogs (CSP-safe; no inline handlers) ----
  // A [data-open-dialog="id"] button opens <dialog id="id">; [data-close-dialog] (or a
  // click on the backdrop) closes the containing <dialog>.
  document.querySelectorAll("[data-open-dialog]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var d = document.getElementById(btn.getAttribute("data-open-dialog"));
      if (d && d.showModal) d.showModal();
    });
  });
  document.querySelectorAll("[data-close-dialog]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var d = btn.closest("dialog");
      if (d) d.close();
    });
  });
  document.querySelectorAll("dialog.modal").forEach(function (d) {
    d.addEventListener("click", function (e) {
      if (e.target === d) d.close(); // click on the backdrop (outside the form)
    });
  });

  // ---- shell: sidebar active link + mobile toggle + topbar title ----
  var layout = document.querySelector("[data-layout]");
  var toggle = document.querySelector("[data-menu-toggle]");
  var scrim = document.querySelector("[data-scrim]");
  if (toggle && layout) toggle.addEventListener("click", function () { layout.classList.toggle("menu-open"); });
  if (scrim && layout) scrim.addEventListener("click", function () { layout.classList.remove("menu-open"); });

  (function markActiveNav() {
    var path = location.pathname;
    document.querySelectorAll("[data-nav]").forEach(function (a) {
      var href = a.getAttribute("href");
      if (!href) return;
      var exact = a.hasAttribute("data-exact");
      var hit = exact ? path === href : (path === href || path.indexOf(href + "/") === 0);
      if (hit) a.classList.add("nav-active");
    });
  })();

  (function setTopbarTitle() {
    var h1 = document.querySelector("main.wrap h1");
    var tt = document.querySelector("[data-page-title]");
    if (h1 && tt) tt.textContent = h1.textContent.trim();
  })();

  // ---- live host charts (CSP-safe: SVG built via the DOM, no inline script) ----
  var SVGNS = "http://www.w3.org/2000/svg";
  function el(name, attrs) {
    var n = document.createElementNS(SVGNS, name);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    return n;
  }
  // drawArea renders a series into an <svg> as a grid + gradient area + line. The y-axis spans
  // 0..max (max defaults to 100 for the % charts; the per-service memory/error charts pass the
  // window peak so a ms/count series scales sensibly). The line uses non-scaling-stroke so it stays
  // crisp under the stretched viewBox. Returns true when it drew real data, false when empty.
  function drawArea(svg, values, max) {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    var W = 300, H = 140;
    var top = (max && max > 0) ? max : 100;
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("preserveAspectRatio", "none");
    [0.25, 0.5, 0.75].forEach(function (g) {
      var y = H - g * H;
      svg.appendChild(el("line", { x1: 0, y1: y, x2: W, y2: y, class: "grid-line", "vector-effect": "non-scaling-stroke" }));
    });
    if (!values || values.length < 2) return false;
    var n = values.length;
    function x(i) { return (i / (n - 1)) * W; }
    function y(v) { var c = v < 0 ? 0 : (v > top ? top : v); return H - (c / top) * H; }
    // A vertical gradient for the area fill (its own id per chart).
    var gid = "grad-" + (svg.getAttribute("data-chart") || "x");
    var defs = el("defs");
    var lg = el("linearGradient", { id: gid, x1: "0", y1: "0", x2: "0", y2: "1" });
    lg.appendChild(el("stop", { offset: "0%", "stop-color": "currentColor", "stop-opacity": "0.35" }));
    lg.appendChild(el("stop", { offset: "100%", "stop-color": "currentColor", "stop-opacity": "0.02" }));
    defs.appendChild(lg);
    svg.appendChild(defs);
    var line = "M" + x(0) + " " + y(values[0]);
    for (var i = 1; i < n; i++) line += " L" + x(i) + " " + y(values[i]);
    var area = line + " L" + W + " " + H + " L0 " + H + " Z";
    svg.appendChild(el("path", { d: area, fill: "url(#" + gid + ")", stroke: "none" }));
    svg.appendChild(el("path", { d: line, class: "line", stroke: "currentColor", "vector-effect": "non-scaling-stroke" }));
    return true;
  }
  function pct(used, total) { return total > 0 ? (used / total) * 100 : 0; }
  // Hover read-out: a vertical guide line follows the cursor and the chart's header
  // number shows the exact value at that point (like a real chart's tooltip). Built
  // from SVG attributes only (CSP-safe); the guide uses non-scaling-stroke so it stays
  // crisp under the stretched viewBox.
  function setupChartHover(svg) {
    var W = 300, H = 140;
    var key = svg.getAttribute("data-chart");
    var nowEl = document.querySelector('[data-chart-now="' + key + '"]');
    var restore = function () {
      var g = svg.querySelector(".hover-guide");
      if (g) svg.removeChild(g);
      svg.__hovering = false;
      var vals = svg.__vals;
      if (nowEl) nowEl.textContent = (vals && vals.length) ? (svg.__fmt ? svg.__fmt(vals[vals.length - 1]) : Math.round(vals[vals.length - 1]) + "%") : "—";
    };
    svg.addEventListener("mousemove", function (e) {
      var vals = svg.__vals;
      if (!vals || vals.length < 2) return;
      var rect = svg.getBoundingClientRect();
      if (rect.width <= 0) return;
      var frac = (e.clientX - rect.left) / rect.width;
      frac = frac < 0 ? 0 : (frac > 1 ? 1 : frac);
      var idx = Math.round(frac * (vals.length - 1));
      var gx = (idx / (vals.length - 1)) * W;
      var g = svg.querySelector(".hover-guide");
      if (!g) { g = el("line", { class: "hover-guide", "vector-effect": "non-scaling-stroke" }); svg.appendChild(g); }
      g.setAttribute("x1", gx); g.setAttribute("y1", 0); g.setAttribute("x2", gx); g.setAttribute("y2", H);
      svg.__hovering = true;
      if (nowEl) nowEl.textContent = svg.__fmt ? svg.__fmt(vals[idx]) : vals[idx].toFixed(1) + "%";
    });
    svg.addEventListener("mouseleave", restore);
  }
  // The host charts (Overview/Server) — everything with [data-chart] that is NOT inside a
  // per-service metrics grid (those are refreshed by their own block below, from their own URL).
  var charts = Array.prototype.filter.call(document.querySelectorAll("[data-chart]"), function (svg) {
    return !(svg.closest && svg.closest("[data-service-metrics]"));
  });
  if (charts.length) {
    charts.forEach(setupChartHover);
    var refreshCharts = function () {
      if (!dashFocused()) return;
      fetch("/partials/metrics.json", { credentials: "same-origin", redirect: "error", headers: { "X-Requested-With": "fetch" } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          var pts = (data && data.points) || [];
          var series = {
            cpu: pts.map(function (p) { return p.cpu; }),
            mem: pts.map(function (p) { return pct(p.memUsed, p.memTotal); }),
            disk: pts.map(function (p) { return pct(p.diskUsed, p.diskTotal); }),
          };
          charts.forEach(function (svg) {
            var key = svg.getAttribute("data-chart");
            var vals = series[key];
            var drew = drawArea(svg, vals);
            svg.__vals = drew ? vals : null; // for hover read-out
            var empty = document.querySelector('[data-chart-empty="' + key + '"]');
            if (empty) empty.style.display = drew ? "none" : "";
            var now = document.querySelector('[data-chart-now="' + key + '"]');
            // Don't clobber the read-out while the cursor is parked on the chart.
            if (now && !svg.__hovering) now.textContent = (drew && vals.length) ? Math.round(vals[vals.length - 1]) + "%" : "—";
          });
        })
        .catch(function () { /* transient */ });
    };
    onFocusedNow(refreshCharts);
    setInterval(refreshCharts, 5000);
  }

  // ---- per-service trend charts (service page) ----
  // CPU% + memory + edge error-rate over time, fetched from the service's own metrics endpoint.
  // Self-contained (its own URL + peak-scaling), so it never collides with the host charts above.
  var svcWrap = document.querySelector("[data-service-metrics]");
  if (svcWrap) {
    var svcUrl = svcWrap.getAttribute("data-metrics-url");
    var svcCharts = svcWrap.querySelectorAll("[data-chart]");
    svcCharts.forEach(setupChartHover);
    var fmtMiB = function (mib) { return mib >= 1024 ? (mib / 1024).toFixed(2) + " GiB" : Math.round(mib) + " MiB"; };
    var svcFmt = {
      "svc-cpu": function (v) { return Math.round(v) + "%"; },
      "svc-mem": function (v) { return fmtMiB(v); },
      "svc-err": function (v) { return Math.round(v) + (Math.round(v) === 1 ? " error" : " errors"); },
    };
    svcCharts.forEach(function (svg) {
      var f = svcFmt[svg.getAttribute("data-chart")];
      if (f) svg.__fmt = f;
    });
    var refreshSvc = function () {
      if (!dashFocused()) return;
      fetch(svcUrl, { credentials: "same-origin", redirect: "error", headers: { "X-Requested-With": "fetch" } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          if (!data) return;
          var pts = data.points || [], errs = data.errors || [];
          var series = {
            "svc-cpu": { vals: pts.map(function (p) { return p.cpu; }), max: 100 },
            "svc-mem": { vals: pts.map(function (p) { return p.memBytes / 1048576; }), max: 0 },
            "svc-err": { vals: errs.map(function (b) { return b.count; }), max: 0 },
          };
          svcCharts.forEach(function (svg) {
            var key = svg.getAttribute("data-chart");
            var s = series[key];
            if (!s) return;
            var mx = s.max;
            if (mx === 0) { mx = 1; for (var i = 0; i < s.vals.length; i++) if (s.vals[i] > mx) mx = s.vals[i]; }
            var drew = drawArea(svg, s.vals, mx);
            svg.__vals = drew ? s.vals : null;
            var empty = svcWrap.querySelector('[data-chart-empty="' + key + '"]');
            if (empty) empty.style.display = drew ? "none" : "";
            var now = svcWrap.querySelector('[data-chart-now="' + key + '"]');
            if (now && !svg.__hovering) {
              now.textContent = (drew && s.vals.length && svg.__fmt) ? svg.__fmt(s.vals[s.vals.length - 1]) : "—";
            }
          });
        })
        .catch(function () { /* transient */ });
    };
    onFocusedNow(refreshSvc);
    setInterval(refreshSvc, 5000);
  }

  // ---- per-route error-log filter (Errors tab) ----
  // Each `.err-filter` input hides the `.err-line` rows in its accordion's `.err-body` that don't
  // contain EVERY typed word. Delegated on document, so it also covers accordions opened later (and
  // re-applied after a live refresh). Reads textContent only (CSP/XSS-safe).
  function applyErrFilter(input) {
    var body = input.closest ? input.closest(".err-body") : null;
    if (!body) return;
    var terms = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    var lines = body.querySelectorAll(".err-line");
    for (var i = 0; i < lines.length; i++) {
      var txt = lines[i].textContent.toLowerCase();
      var ok = true;
      for (var j = 0; j < terms.length; j++) {
        if (txt.indexOf(terms[j]) < 0) { ok = false; break; }
      }
      lines[i].style.display = ok ? "" : "none";
    }
  }
  document.addEventListener("input", function (e) {
    if (e.target.classList && e.target.classList.contains("err-filter")) applyErrFilter(e.target);
  });

  // ---- log-entry modal (service log history): a line stays clipped to one row; click it to read
  // its FULL content in a modal. ----
  var logModal = document.getElementById("log-modal");
  if (logModal) {
    var lmMeta = document.getElementById("log-modal-meta");
    var lmText = document.getElementById("log-modal-text");
    var openLogModal = function (line) {
      var t = line.querySelector(".log-t"), c = line.querySelector(".log-copy"), x = line.querySelector(".log-text");
      var meta = t ? t.textContent.trim() : "";
      if (c) meta += "  ·  " + c.textContent.trim();
      lmMeta.textContent = meta;
      lmText.textContent = x ? x.textContent : line.textContent; // textContent is the FULL line (clip is visual only)
      lmText.className = "stream"; // carry the line's severity color into the modal
      ["lvl-error", "lvl-warn", "lvl-debug"].forEach(function (c) { if (line.classList.contains(c)) lmText.classList.add(c); });
      logModal.hidden = false;
    };
    var closeLogModal = function () { logModal.hidden = true; };
    document.addEventListener("click", function (e) {
      if (e.target.closest && e.target.closest("[data-modal-close]")) { closeLogModal(); return; }
      var line = e.target.closest ? e.target.closest(".log-line") : null;
      if (line) openLogModal(line);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !logModal.hidden) closeLogModal();
    });
  }

  // ---- error-request modal (Errors tab): click a row to see the full request details (like the log
  // modal). The inline "view app logs" link still navigates. ----
  var errModal = document.getElementById("err-modal");
  if (errModal) {
    var emBody = document.getElementById("err-modal-body");
    var emLogs = document.getElementById("err-modal-logs");
    var pad = function (s, n) { s = String(s); while (s.length < n) s += " "; return s; };
    var openErrModal = function (row) {
      var at = parseInt(row.getAttribute("data-at"), 10);
      var when = (at && !isNaN(at)) ? (TS_FMT ? TS_FMT.format(new Date(at * 1000)) : new Date(at * 1000).toLocaleString()) : "";
      var app = row.getAttribute("data-app") || "", svc = row.getAttribute("data-svc") || "";
      emBody.textContent = [
        pad("Time", 9) + when,
        pad("Method", 9) + (row.getAttribute("data-method") || ""),
        pad("Path", 9) + (row.getAttribute("data-path") || ""),
        pad("Status", 9) + (row.getAttribute("data-status") || ""),
        pad("Client", 9) + (row.getAttribute("data-ip") || ""),
        pad("Latency", 9) + (row.getAttribute("data-dur") || "0") + " ms",
        pad("Route", 9) + (row.getAttribute("data-route") || "") + "  →  " + app + "/" + svc,
      ].join("\n");
      if (row.getAttribute("data-logs") === "1" && app && svc && at) {
        emLogs.href = "/apps/" + encodeURIComponent(app) + "/services/" + encodeURIComponent(svc) + "/logs/history?at=" + at;
        emLogs.hidden = false;
      } else {
        emLogs.hidden = true;
      }
      errModal.hidden = false;
    };
    var closeErrModal = function () { errModal.hidden = true; };
    document.addEventListener("click", function (e) {
      if (e.target.closest && e.target.closest("[data-modal-close]")) { closeErrModal(); return; }
      if (e.target.closest && e.target.closest("#err-modal")) return; // clicks inside the box do nothing
      if (e.target.closest && e.target.closest("a")) return;          // let the inline app-logs link navigate
      var row = e.target.closest ? e.target.closest(".err-line") : null;
      if (row && row.hasAttribute("data-at")) openErrModal(row);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !errModal.hidden) closeErrModal();
    });
  }
})();
