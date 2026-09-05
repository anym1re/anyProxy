// The panel's interface. Everything on the screen comes from the API and
// every word from the catalogue; the page itself holds no data.
(() => {
  'use strict';

  const RANGES = [['ui-range-week', 7], ['ui-range-month', 30], ['ui-range-half', 180], ['ui-range-year', 365]];
  const REFRESH_MS = 30000;
  const PAGE = 200;

  // Browser storage can be absent or refuse; the interface works without it.
  function recall(store, key) { try { return window[store].getItem(key); } catch { return null; } }
  function remember(store, key, value) { try { window[store].setItem(key, value); } catch { /* nothing to keep it in */ } }
  function forget(store, key) { try { window[store].removeItem(key); } catch { /* already gone */ } }

  const state = {
    token: recall('sessionStorage', 'ap-token'),
    lang: recall('localStorage', 'ap-lang') || ((navigator.language || 'en').toLowerCase().startsWith('ru') ? 'ru' : 'en'),
    theme: recall('localStorage', 'ap-theme') || 'dark',
    range: Number(recall('localStorage', 'ap-range')) || 30,
    messages: {},
    me: null,
    timer: null,
    nodeFilter: 'all',
  };

  const $ = (selector, root) => (root || document).querySelector(selector);

  // ── building ────────────────────────────────────────────────────────────

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [name, value] of Object.entries(attrs)) {
        if (value == null || value === false) continue;
        if (name === 'class') el.className = value;
        // Through the object model, not the attribute: the page's policy
        // allows no inline attributes, and this is not one.
        else if (name === 'style') el.style.cssText = value;
        else if (name === 'on') for (const [event, fn] of Object.entries(value)) el.addEventListener(event, fn);
        else if (name === 'dataset') Object.assign(el.dataset, value);
        else if (typeof value === 'boolean') el[name] = value;
        else el.setAttribute(name, value);
      }
    }
    for (const child of children.flat(Infinity)) {
      if (child == null || child === false) continue;
      el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return el;
  }

  function s(tag, attrs, ...children) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [name, value] of Object.entries(attrs || {})) el.setAttribute(name, value);
    for (const child of children.flat(Infinity)) if (child != null) el.append(child);
    return el;
  }

  function t(key, args) {
    let text = state.messages[key];
    if (text === undefined) return key;
    if (args) text = text.replace(/\{\s*\$([A-Za-z0-9_-]+)\s*\}/g, (_, name) => (args[name] == null ? '' : String(args[name])));
    return text;
  }

  function applyStaticText() {
    for (const el of document.querySelectorAll('[data-t]')) el.textContent = t(el.dataset.t);
    document.title = t('ui-title');
  }

  // ── talking to the panel ────────────────────────────────────────────────

  class Refusal extends Error {
    constructor(status, code, message, retryAfter) {
      super(message);
      this.status = status;
      this.code = code;
      this.retryAfter = retryAfter;
    }
  }

  async function api(method, path, body) {
    const headers = { 'accept-language': state.lang };
    if (state.token) headers.authorization = `Bearer ${state.token}`;
    if (body !== undefined) headers['content-type'] = 'application/json';
    let response;
    try {
      response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store' });
    } catch {
      throw new Refusal(0, 'offline', t('ui-offline'), null);
    }
    if (response.status === 401 && path !== '/v1/session') {
      leave();
      throw new Refusal(401, 'unauthenticated', '', null);
    }
    if (!response.ok) {
      let payload = null;
      try { payload = await response.json(); } catch { /* no body */ }
      const code = ((payload && payload.error) || {}).code || String(response.status);
      throw new Refusal(response.status, code, refusalText(code), response.headers.get('retry-after'));
    }
    if (response.status === 204) return null;
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  }

  // The sentence for a refusal code, from the same catalogue the CLI reads.
  function refusalText(code) {
    const key = `api-${String(code).replace(/_/g, '-')}`;
    return state.messages[key] === undefined ? t('api-unknown', { code }) : t(key);
  }

  async function loadMessages() {
    const reply = await fetch(`/v1/i18n?lang=${encodeURIComponent(state.lang)}`, { cache: 'no-store' });
    const payload = await reply.json();
    state.messages = payload.messages || {};
    state.lang = payload.lang || state.lang;
    document.documentElement.lang = state.lang;
    applyStaticText();
  }

  // ── words and figures ───────────────────────────────────────────────────

  const HEALTH_CLASS = { up: 'ok', down: 'bad', open: 'ok', blocked: 'bad', unknown: 'warn' };
  const PRESSURE_CLASS = { calm: 'ok', strained: 'warn', critical: 'bad' };
  const STATE_CLASS = { active: 'ok', pending: 'warn', disabled: 'warn', suspended: 'warn', burned: 'bad', archived: 'bad', revoked: 'bad' };

  function locale() { return state.lang === 'ru' ? 'ru-RU' : 'en-GB'; }

  // Everything the panel says is in UTC, and so is everything shown: a
  // date that shifted with the operator's clock would not be the date the
  // panel acts on.
  function fmtDateTime(iso) {
    if (!iso) return t('ui-never');
    return new Intl.DateTimeFormat(locale(), { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(new Date(iso));
  }

  function fmtDate(iso) {
    if (!iso) return t('ui-no-expiry');
    return new Intl.DateTimeFormat(locale(), { dateStyle: 'medium', timeZone: 'UTC' }).format(new Date(iso));
  }

  function fmtDateShort(iso) {
    if (!iso) return t('ui-no-expiry');
    return new Intl.DateTimeFormat(locale(), { dateStyle: 'short', timeZone: 'UTC' }).format(new Date(iso));
  }

  function fmtDay(ymd) {
    const [year, month, day] = ymd.split('-').map(Number);
    return new Intl.DateTimeFormat(locale(), { day: 'numeric', month: 'short' }).format(new Date(Date.UTC(year, month - 1, day)));
  }

  function fmtNum(value) { return Number(value || 0).toLocaleString(locale()); }

  function fmtBytes(value) {
    const units = ['ui-unit-b', 'ui-unit-kb', 'ui-unit-mb', 'ui-unit-gb', 'ui-unit-tb'];
    let amount = Number(value) || 0;
    let unit = 0;
    while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1; }
    const digits = unit === 0 ? 0 : amount < 10 ? 2 : amount < 100 ? 1 : 0;
    return `${amount.toLocaleString(locale(), { maximumFractionDigits: digits })} ${t(units[unit])}`;
  }

  function fmtMb(mb) { return fmtBytes(Number(mb || 0) * 1024 * 1024); }

  function fmtQuota(bytes) { return bytes == null ? t('ui-no-limit') : fmtBytes(bytes); }

  function gbToBytes(text) {
    const value = Number(String(text || '').replace(',', '.'));
    return text === '' || !(value > 0) ? null : Math.round(value * 1024 * 1024 * 1024);
  }

  function dayToExpiry(text) { return text ? `${text}T23:59:59Z` : null; }

  function kindOf(node) { return t(node.kind === 'mtproto' && node.masked ? 'ui-kind-mtproto-masked' : `ui-kind-${node.kind}`); }

  function dot(cls) { return h('i', { class: `dot ${cls || ''}` }); }

  function word(value) { return h('span', { class: 'word' }, dot(HEALTH_CLASS[value]), t(`ui-word-${value}`)); }

  function pressure(value) { return h('span', { class: `word ${PRESSURE_CLASS[value] || ''}` }, dot(PRESSURE_CLASS[value]), t(`ui-pressure-${value}`)); }

  function stateChip(prefix, value) { return h('span', { class: `chipst ${STATE_CLASS[value] || ''}` }, t(`ui-${prefix}-state-${value}`)); }

  function whyAttention(node) {
    const reasons = [];
    if (node.health) {
      if (node.health.engine === 'down') reasons.push(`${t('ui-health-engine')}: ${t('ui-word-down')}`);
      if (node.health.site === 'down') reasons.push(`${t('ui-health-site')}: ${t('ui-word-down')}`);
      if (node.health.reach === 'blocked') reasons.push(`${t('ui-health-reach')}: ${t('ui-word-blocked')}`);
    }
    if (node.machine && node.machine.pressure !== 'calm') reasons.push(`${t('ui-col-pressure')}: ${t(`ui-pressure-${node.machine.pressure}`)}`);
    return reasons.join(' · ');
  }

  function ratio(used, limit) { return limit ? Math.min(1, Number(used || 0) / Number(limit)) : 0; }

  function bar(used, limit) {
    const share = ratio(used, limit);
    const cls = share >= 0.95 ? 'bad' : share >= 0.85 ? 'warn' : '';
    return h('span', { class: `bar ${cls}` }, h('i', { style: `width:${Math.round(share * 100)}%` }));
  }

  async function copy(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const area = h('textarea', { readonly: true, style: 'position:fixed;left:-1000px;top:0' }, text);
      document.body.append(area);
      area.select();
      try { document.execCommand('copy'); } catch { /* nothing else to try */ }
      area.remove();
    }
    toast(t('ui-copied'), 'ok');
  }

  function copyButton(text) { return h('button', { type: 'button', class: 'btn sm', on: { click: () => copy(text) } }, t('ui-copy')); }

  function codeLine(text) { return h('div', { class: 'code' }, h('code', null, text), copyButton(text)); }

  // ── toast and modal ─────────────────────────────────────────────────────

  function toast(text, kind) {
    const root = $('#toast-root');
    root.replaceChildren(h('div', { class: `toast ${kind || ''}`, role: 'status' }, text));
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => root.replaceChildren(), 3600);
  }

  function refused(error) {
    if (error instanceof Refusal && error.status === 401) return;
    toast(t('ui-refused', { message: error.message }), 'bad');
  }

  function modal({ title, body, actions, onClose }) {
    const root = $('#modal-root');
    const box = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' }, h('h2', null, title), body);
    const acts = h('div', { class: 'actions' });
    function close() {
      root.replaceChildren();
      document.removeEventListener('keydown', onKey);
      if (onClose) onClose();
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    for (const action of actions || []) {
      const button = h('button', { type: 'button', class: `btn ${action.kind || ''}` }, action.label);
      button.addEventListener('click', () => action.run(close, button));
      if (action.ready) action.ready(button);
      acts.append(button);
    }
    if (acts.childElementCount) box.append(acts);
    const back = h('div', { class: 'back', on: { click: (event) => { if (event.target === back) close(); } } }, box);
    root.replaceChildren(back);
    document.addEventListener('keydown', onKey);
    const first = box.querySelector('input:not([type=checkbox]), select, button');
    if (first) first.focus();
    return close;
  }

  function field(label, input, extra) {
    return h('label', { class: `field ${extra || ''}` }, h('span', null, label), input);
  }

  function errorLine() { return h('div', { class: 'err' }); }

  // Runs one request from a modal, showing what the panel answered.
  async function attempt(button, err, run) {
    button.disabled = true;
    err.textContent = '';
    try {
      await run();
    } catch (error) {
      err.textContent = error.message;
      refused(error);
    } finally {
      button.disabled = false;
    }
  }

  // ── shell ───────────────────────────────────────────────────────────────

  function applyTheme() {
    document.documentElement.dataset.theme = state.theme;
    for (const button of $('#theme').querySelectorAll('button')) button.classList.toggle('on', button.dataset.theme === state.theme);
  }

  function applyLangButtons() {
    for (const button of $('#lang').querySelectorAll('button')) button.classList.toggle('on', button.dataset.lang === state.lang);
  }

  function showRail() {
    const rail = $('#rail');
    rail.hidden = !state.me;
    if (!state.me) return;
    $('#me-login').textContent = state.me.login;
    $('#me-role').textContent = t(`ui-role-${state.me.role}`);
    for (const link of $('#nav').querySelectorAll('a')) {
      const needs = link.dataset.needs;
      link.hidden = (needs === 'nodes' && state.me.role === 'reseller') || (needs === 'audit' && state.me.role !== 'superadmin');
    }
  }

  function leave() {
    state.token = null;
    state.me = null;
    forget('sessionStorage', 'ap-token');
    showRail();
    route();
  }

  async function signOut() {
    try { await api('DELETE', '/v1/session'); } catch { /* the token is dropped either way */ }
    leave();
  }

  function topbar(name) {
    return h('div', { class: 'topbar' },
      h('h1', null, t(`ui-nav-${name}`)),
      h('div', { class: 'sp' }),
      h('button', { type: 'button', class: 'btn ghost sm', on: { click: () => route() } }, t('ui-refresh')),
    );
  }

  function card(cls, title, count, ...body) {
    const head = title === null ? null : h('div', { class: 'card-h' }, h('h3', null, title), count != null ? h('span', { class: 'n mono' }, count) : null, h('div', { class: 'sp' }));
    return h('section', { class: `card ${cls}` }, head, h('div', { class: 'card-b' }, body));
  }

  function table(columns, rows) {
    return h('div', { class: 'scroll' }, h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, columns.map((column) => h('th', { class: `${column.right ? 'r' : ''} ${column.opt ? 'opt' : ''}` }, column.label)))),
      h('tbody', null, rows),
    ));
  }

  function empty(text) { return h('div', { class: 'empty' }, text || t('ui-empty')); }

  // ── sign in ─────────────────────────────────────────────────────────────

  function loginView() {
    const login = h('input', { type: 'text', autocomplete: 'username', required: true, autofocus: true });
    const password = h('input', { type: 'password', autocomplete: 'current-password', required: true });
    const totp = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', required: true, pattern: '[0-9]{6}' });
    const err = errorLine();
    const submit = h('button', { type: 'submit', class: 'btn primary' }, t('ui-login-submit'));
    const form = h('form', { class: 'card-b', on: { submit: async (event) => {
      event.preventDefault();
      submit.disabled = true;
      err.textContent = '';
      try {
        const reply = await api('POST', '/v1/session', { login: login.value.trim(), password: password.value, totp: totp.value.trim() });
        state.token = reply.token;
        remember('sessionStorage', 'ap-token', reply.token);
        state.me = await api('GET', '/v1/session');
        showRail();
        location.hash = '#/dashboard';
        route();
      } catch (error) {
        if (error.status === 429) err.textContent = t('ui-login-wait', { seconds: error.retryAfter || '' });
        else if (error.status === 401) err.textContent = t('ui-login-failed');
        else err.textContent = error.message;
        submit.disabled = false;
      }
    } } },
      h('div', { class: 'brand' },
        h('span', { class: 'mono', style: 'color:var(--key)' }, '◆'),
        h('b', null, t('ui-title'))),
      h('h2', null, t('ui-login-title')),
      field(t('ui-login-login'), login),
      field(t('ui-login-password'), password),
      field(t('ui-login-totp'), totp),
      err,
      submit,
    );
    return h('div', { class: 'content', style: 'display:flex' }, h('section', { class: 'card login' }, form));
  }

  // ── dashboard ───────────────────────────────────────────────────────────

  function chart(series, days) {
    const byDay = new Map(series.map((point) => [point.day, point]));
    const now = new Date();
    const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
    const points = [];
    for (let back = days - 1; back >= 0; back -= 1) {
      const key = new Date(today - back * 86400000).toISOString().slice(0, 10);
      const point = byDay.get(key);
      points.push({ day: key, in: point ? Number(point.bytes_in) : 0, out: point ? Number(point.bytes_out) : 0 });
    }
    const W = 600; const H = 160; const L = 6; const R = 6; const T = 10; const B = 22;
    const max = Math.max(1, ...points.map((point) => Math.max(point.in, point.out)));
    const x = (index) => L + (index / Math.max(1, points.length - 1)) * (W - L - R);
    const y = (value) => T + (1 - value / max) * (H - T - B);
    const line = (key) => points.map((point, index) => `${index ? 'L' : 'M'}${x(index).toFixed(1)},${y(point[key]).toFixed(1)}`).join(' ');
    const floor = (H - B).toFixed(1);
    const area = (key) => `${line(key)} L${x(points.length - 1).toFixed(1)},${floor} L${x(0).toFixed(1)},${floor} Z`;
    const stop = (offset, color) => s('stop', { offset, 'stop-color': color });
    const labels = [0, Math.floor((points.length - 1) / 2), points.length - 1].map((index) =>
      s('text', { x: x(index).toFixed(1), y: H - 6, 'text-anchor': index === 0 ? 'start' : index === points.length - 1 ? 'end' : 'middle' }, fmtDay(points[index].day)));
    const grid = [0.25, 0.5, 0.75].map((share) => s('line', { x1: L, x2: W - R, y1: y(max * share).toFixed(1), y2: y(max * share).toFixed(1) }));
    const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img' },
      s('defs', null,
        s('linearGradient', { id: 'area-in', x1: 0, y1: 0, x2: 0, y2: 1 }, stop('0%', 'var(--area-1)'), stop('100%', 'var(--area-2)')),
        s('linearGradient', { id: 'area-out', x1: 0, y1: 0, x2: 0, y2: 1 }, stop('0%', 'var(--area-out-1)'), stop('100%', 'var(--area-out-2)'))),
      s('g', { class: 'grid' }, grid),
      s('path', { class: 'area-in', d: area('in') }),
      s('path', { class: 'area-out', d: area('out') }),
      s('path', { class: 'line-in', d: line('in') }),
      s('path', { class: 'line-out', d: line('out') }),
      s('g', { class: 'axis' }, labels),
    );
    const received = points.reduce((sum, point) => sum + point.in, 0);
    const sent = points.reduce((sum, point) => sum + point.out, 0);
    return { svg, received, sent };
  }

  async function dashboardView() {
    const seesNodes = state.me.role !== 'reseller';
    const readsAudit = state.me.role === 'superadmin';
    const [nodes, clients, publics, audit, series] = await Promise.all([
      seesNodes ? api('GET', '/v1/nodes') : Promise.resolve([]),
      api('GET', `/v1/clients?limit=${PAGE}`),
      seesNodes ? api('GET', '/v1/accesses/public').catch(() => []) : Promise.resolve([]),
      readsAudit ? api('GET', '/v1/audit?limit=12') : Promise.resolve([]),
      api('GET', `/v1/traffic?days=${state.range}`),
    ]);
    const live = nodes.filter((node) => node.state !== 'burned');
    const attention = live.filter((node) => node.wants_attention);
    const drawn = chart(series, state.range);

    const attentionCard = seesNodes ? card('c12', t('ui-dash-attention'), attention.length,
      attention.length
        ? h('div', { class: 'attn' }, attention.map((node) => h('a', { href: '#/nodes' }, dot('bad'), h('b', null, node.label), h('span', { class: 'm2' }, kindOf(node)), h('span', { class: 'why' }, whyAttention(node)))))
        : h('div', { class: 'calm' }, dot('ok'), t('ui-dash-all-calm'))) : null;

    const metric = (n, k, sub) => h('section', { class: 'card c3' }, h('div', { class: 'metric' }, h('div', { class: 'n' }, n), h('div', { class: 'k' }, k), h('div', { class: 's' }, sub)));
    const strip = [
      seesNodes ? metric(fmtNum(live.length), t('ui-dash-nodes'), `${fmtNum(live.filter((node) => node.state === 'active').length)} ${t('ui-dash-in-service')} · ${fmtNum(attention.length)} ${t('ui-dash-attention-count')}`) : null,
      metric(fmtNum(clients.length), t('ui-dash-clients'), `${fmtNum(clients.filter((client) => client.state === 'active').length)} ${t('ui-dash-active-count')}`),
      seesNodes ? metric(fmtNum(publics.length), t('ui-dash-public'), `${fmtNum(publics.filter((access) => access.state === 'active').length)} ${t('ui-dash-active-count')}`) : null,
      metric(fmtBytes(drawn.received + drawn.sent), t('ui-dash-traffic'), `${t('ui-dash-received')} ${fmtBytes(drawn.received)} · ${t('ui-dash-sent')} ${fmtBytes(drawn.sent)}`),
    ];

    const chips = h('div', { class: 'chips' }, RANGES.map(([key, days]) => h('button', { type: 'button', class: `chip ${days === state.range ? 'on' : ''}`, on: { click: () => { state.range = days; remember('localStorage', 'ap-range', String(days)); route(); } } }, t(key))));
    const trafficCard = h('section', { class: 'card c8' },
      h('div', { class: 'card-h' }, h('h3', null, t('ui-dash-traffic')), h('div', { class: 'sp' }), chips),
      h('div', { class: 'card-b' },
        h('div', { class: 'chart' }, drawn.svg),
        h('div', { class: 'legend' },
          h('span', { class: 'in' }, h('i'), `${t('ui-dash-received')} `, h('b', null, fmtBytes(drawn.received))),
          h('span', { class: 'out' }, h('i'), `${t('ui-dash-sent')} `, h('b', null, fmtBytes(drawn.sent))))));

    const processes = seesNodes ? card('c4', t('ui-dash-processes'), live.length,
      live.length ? h('div', { class: 'scroll' }, h('table', { class: 'tbl' }, h('tbody', null, live.map((node) => h('tr', null,
        h('td', { class: 'name' }, node.label),
        h('td', null, node.health ? word(node.health.engine) : h('span', { class: 'm3' }, t('ui-no-report'))),
        h('td', null, node.health ? word(node.health.site) : ''),
        h('td', null, node.health ? word(node.health.reach) : ''),
      ))))) : empty()) : null;

    const hosts = seesNodes ? card('c12', t('ui-dash-hosts'), live.length,
      live.length ? table([
        { label: t('ui-col-node') }, { label: t('ui-col-cpus'), right: true }, { label: t('ui-col-memory'), right: true },
        { label: t('ui-col-files'), right: true }, { label: t('ui-col-stall'), right: true }, { label: t('ui-col-pressure') },
      ], live.map((node) => {
        const m = node.machine;
        return h('tr', null,
          h('td', { class: 'name' }, node.label, h('div', { class: 'sub' }, kindOf(node))),
          h('td', { class: 'r mono' }, m ? fmtNum(m.cpus) : ''),
          h('td', { class: 'r mono' }, m ? [fmtMb(m.memory_used_mb), m.memory_limit_mb ? ` / ${fmtMb(m.memory_limit_mb)}` : '', m.memory_limit_mb ? bar(m.memory_used_mb, m.memory_limit_mb) : null] : ''),
          h('td', { class: 'r mono' }, m && m.open_files != null ? [fmtNum(m.open_files), m.file_limit ? ` / ${fmtNum(m.file_limit)}` : ''] : ''),
          h('td', { class: 'r mono' }, m ? `${Number(m.memory_stall).toFixed(1)}% · ${Number(m.cpu_stall).toFixed(1)}%` : ''),
          h('td', null, m ? pressure(m.pressure) : h('span', { class: 'm3' }, t('ui-no-report'))),
        );
      })) : empty()) : null;

    const events = readsAudit ? card('c12', t('ui-dash-events'), audit.length,
      audit.length ? table([{ label: t('ui-col-time') }, { label: t('ui-col-action') }, { label: t('ui-col-target') }],
        audit.map((entry) => h('tr', null, h('td', { class: 'mono m2' }, fmtDateTime(entry.at)), h('td', null, entry.action), h('td', { class: 'mono' }, entry.target || '')))) : empty()) : null;

    return h('div', { class: 'content' },
      attentionCard,
      h('div', { class: 'g' }, strip),
      h('div', { class: 'g' }, trafficCard, processes),
      hosts ? h('div', { class: 'g' }, hosts) : null,
      events ? h('div', { class: 'g' }, events) : null,
    );
  }

  // ── nodes ───────────────────────────────────────────────────────────────

  function enrolCommand(host, code, fingerprint) {
    return `anyproxy-agent enroll --panel ${host || '<panel-host>'}:8443 --code ${code} --fingerprint ${fingerprint}`;
  }

  function showEnrolment(node, issued) {
    const host = h('input', { type: 'text', placeholder: '<panel-host>', spellcheck: false });
    const command = h('code', null, enrolCommand('', issued.code, issued.panel_fingerprint));
    host.addEventListener('input', () => { command.textContent = enrolCommand(host.value.trim(), issued.code, issued.panel_fingerprint); });
    modal({
      title: `${t('ui-enrol-title')} · ${node.label}`,
      body: h('div', { style: 'display:flex;flex-direction:column;gap:12px' },
        h('p', { class: 'warn' }, `${t('ui-enrol-once')} · ${t('ui-enrol-expires', { date: fmtDateTime(issued.expires_at) })}`),
        h('div', { class: 'kv' },
          h('span', { class: 'k' }, t('ui-enrol-code')), h('span', { class: 'mono' }, issued.code),
          h('span', { class: 'k' }, t('ui-enrol-fingerprint')), h('span', { class: 'mono', style: 'overflow-wrap:anywhere' }, issued.panel_fingerprint)),
        field(t('ui-panel-host'), host),
        field(t('ui-enrol-command'), h('div', { class: 'code' }, command, h('button', { type: 'button', class: 'btn sm', on: { click: () => copy(command.textContent) } }, t('ui-copy')))),
      ),
      actions: [{ label: t('ui-close'), run: (close) => close() }],
      onClose: () => route(),
    });
  }

  function newNodeModal() {
    const label = h('input', { type: 'text', required: true, pattern: '[a-z0-9_-]{1,32}', spellcheck: false });
    const kind = h('select', null, ['mtproto', 'web', 'socks5', 'http'].map((value) => h('option', { value }, t(`ui-kind-${value}`))));
    const masked = h('input', { type: 'checkbox', checked: true });
    const domain = h('input', { type: 'text', placeholder: 'example.com', spellcheck: false });
    const maskedField = field(t('ui-new-node-masked'), masked, 'row');
    const domainField = field(t('ui-new-node-domain'), domain, 'wide');
    const err = errorLine();
    function refresh() {
      maskedField.hidden = kind.value !== 'mtproto';
      domainField.hidden = !(kind.value === 'web' || (kind.value === 'mtproto' && masked.checked));
    }
    kind.addEventListener('change', refresh);
    masked.addEventListener('change', refresh);
    refresh();
    modal({
      title: t('ui-new-node-title'),
      body: h('div', { class: 'form' }, field(t('ui-new-node-label'), label), field(t('ui-new-node-kind'), kind), maskedField, domainField, h('div', { class: 'wide' }, err)),
      actions: [
        { label: t('ui-cancel'), run: (close) => close() },
        { label: t('ui-new-node-submit'), kind: 'primary', run: (close, button) => attempt(button, err, async () => {
          const body = { label: label.value.trim(), kind: kind.value };
          if (kind.value === 'mtproto') body.masked = masked.checked;
          if (!domainField.hidden) body.domain = domain.value.trim();
          const node = await api('POST', '/v1/nodes', body);
          const issued = await api('POST', `/v1/nodes/${node.id}/enrollment`);
          close();
          showEnrolment(node, issued);
        }) },
      ],
    });
  }

  function deleteNodeModal(node) {
    const typed = h('input', { type: 'text', autocomplete: 'off', spellcheck: false });
    const err = errorLine();
    modal({
      title: t('ui-node-delete-title', { label: node.label }),
      body: h('div', { style: 'display:flex;flex-direction:column;gap:12px' }, h('p', null, t('ui-node-delete-text')), field(t('ui-node-delete-type'), typed), err),
      actions: [
        { label: t('ui-cancel'), run: (close) => close() },
        { label: t('ui-node-delete-confirm'), kind: 'danger', ready: (button) => { button.disabled = true; typed.addEventListener('input', () => { button.disabled = typed.value.trim() !== node.label; }); },
          run: (close, button) => attempt(button, err, async () => { await api('POST', `/v1/nodes/${node.id}/burn`); close(); route(); }) },
      ],
    });
  }

  function domainModal(node) {
    const domain = h('input', { type: 'text', value: node.domain || '', spellcheck: false });
    const err = errorLine();
    modal({
      title: `${t('ui-rename-title')} · ${node.label}`,
      body: h('div', { style: 'display:flex;flex-direction:column;gap:12px' }, field(t('ui-node-domain'), domain), err),
      actions: [
        { label: t('ui-cancel'), run: (close) => close() },
        { label: t('ui-save'), kind: 'primary', run: (close, button) => attempt(button, err, async () => { await api('POST', `/v1/nodes/${node.id}/names`, { domain: domain.value.trim() || null }); close(); route(); }) },
      ],
    });
  }

  function sponsorModal(node) {
    const tag = h('input', { type: 'text', value: node.ad_tag || '', pattern: '[0-9a-f]{32}', spellcheck: false, placeholder: '0'.repeat(32) });
    const err = errorLine();
    const actions = [{ label: t('ui-cancel'), run: (close) => close() }];
    if (node.ad_tag) actions.push({ label: t('ui-sponsor-clear'), kind: 'danger', run: (close, button) => attempt(button, err, async () => { await api('POST', `/v1/nodes/${node.id}/sponsorship`, { ad_tag: null }); close(); route(); }) });
    actions.push({ label: t('ui-save'), kind: 'primary', run: (close, button) => attempt(button, err, async () => { await api('POST', `/v1/nodes/${node.id}/sponsorship`, { ad_tag: tag.value.trim() }); close(); route(); }) });
    modal({ title: `${t('ui-sponsor-title')} · ${node.label}`, body: h('div', { style: 'display:flex;flex-direction:column;gap:12px' }, field(t('ui-node-ad-tag'), tag), err), actions });
  }

  function nodeCard(node, index) {
    const manages = state.me.role === 'superadmin';
    const m = node.machine;
    const burned = node.state === 'burned';
    const acts = manages && !burned ? h('div', { class: 'acts' },
      node.domain != null ? h('button', { type: 'button', class: 'btn sm', on: { click: () => domainModal(node) } }, t('ui-node-rename')) : null,
      node.kind === 'mtproto' ? h('button', { type: 'button', class: 'btn sm', on: { click: () => sponsorModal(node) } }, t('ui-node-sponsor')) : null,
      h('button', { type: 'button', class: 'btn sm', on: { click: async () => { try { showEnrolment(node, await api('POST', `/v1/nodes/${node.id}/enrollment`)); } catch (error) { refused(error); } } } }, t('ui-node-code')),
      h('button', { type: 'button', class: 'btn sm danger', on: { click: () => deleteNodeModal(node) } }, t('ui-node-delete')),
    ) : null;
    return h('section', { class: 'card c6 ncard', style: `--d:${index * 40}ms; ${burned ? 'opacity:.55' : ''}` }, h('div', { class: 'card-b' },
      h('div', { class: 'top' }, node.wants_attention ? dot('bad') : null, h('span', { class: 'lbl' }, node.label), h('span', { class: 'm2' }, kindOf(node)), h('div', { class: 'sp', style: 'flex:1' }), stateChip('node', node.state)),
      h('div', { class: 'line' },
        node.domain ? h('span', null, `${t('ui-node-domain')} `, h('span', { class: 'mono' }, node.domain)) : null,
        node.address ? h('span', null, `${t('ui-node-address')} `, h('span', { class: 'mono' }, node.address)) : null,
        node.ad_tag ? h('span', null, `${t('ui-node-ad-tag')} `, h('span', { class: 'mono' }, `${node.ad_tag.slice(0, 8)}…`)) : null),
      node.health
        ? h('div', { class: 'health' },
          h('span', null, `${t('ui-health-engine')} `, word(node.health.engine)),
          h('span', null, `${t('ui-health-site')} `, word(node.health.site)),
          h('span', null, `${t('ui-health-reach')} `, word(node.health.reach)),
          h('span', { class: node.health.cert_not_after ? 'm2' : 'm3' }, node.health.cert_not_after ? t('ui-cert-until', { date: fmtDate(node.health.cert_not_after) }) : (node.kind === 'web' ? t('ui-cert-none') : '')))
        : h('div', { class: 'health m3' }, t('ui-no-report')),
      m ? h('div', { class: 'hw' },
        h('b', null, fmtNum(m.cpus)), ` ${t('ui-col-cpus')} · `,
        h('b', null, fmtMb(m.memory_used_mb)), m.memory_limit_mb ? ` / ${fmtMb(m.memory_limit_mb)}` : '', ` · ${t('ui-col-files')} `,
        h('b', null, m.open_files != null ? fmtNum(m.open_files) : t('ui-none')), m.file_limit ? ` / ${fmtNum(m.file_limit)}` : '', ' · ', pressure(m.pressure)) : null,
      h('div', { class: 'line m3' },
        h('span', null, `${t('ui-node-agent')} `, h('span', { class: 'mono' }, node.agent_version || t('ui-none'))),
        h('span', null, `${t('ui-node-seen')} `, h('span', { class: 'mono' }, fmtDateTime(node.last_seen_at))),
        h('span', null, `${t('ui-node-created')} `, h('span', { class: 'mono' }, fmtDate(node.created_at)))),
      acts,
    ));
  }

  async function nodesView() {
    const nodes = await api('GET', '/v1/nodes');
    const kinds = [...new Set(nodes.map((node) => node.kind))];
    const filters = [['all', t('ui-all')], ['attention', t('ui-filter-attention')], ...kinds.map((kind) => [kind, t(`ui-kind-${kind}`)])];
    const shown = nodes.filter((node) => state.nodeFilter === 'all' || (state.nodeFilter === 'attention' ? node.wants_attention : node.kind === state.nodeFilter));
    const chips = h('div', { class: 'chips' }, filters.map(([value, label]) => h('button', { type: 'button', class: `chip ${state.nodeFilter === value ? 'on' : ''}`, on: { click: () => { state.nodeFilter = value; route(); } } }, label)));
    return h('div', { class: 'content' },
      h('div', { class: 'phead' }, h('div', { class: 'tools' }, chips), state.me.role === 'superadmin' ? h('button', { type: 'button', class: 'btn primary', on: { click: newNodeModal } }, t('ui-nodes-new')) : null),
      shown.length ? h('div', { class: 'g' }, shown.map(nodeCard)) : h('section', { class: 'card' }, h('div', { class: 'card-b' }, empty())),
    );
  }

  // ── users ───────────────────────────────────────────────────────────────

  function nodeName(nodes, id) {
    const node = nodes.find((candidate) => candidate.id === id);
    return node ? node.label : id.slice(0, 8);
  }

  async function clientModal(client) {
    let used = null;
    try { used = await api('GET', `/v1/clients/${client.id}/traffic`); } catch (error) { refused(error); }
    const err = errorLine();
    const setState = (value) => (close, button) => attempt(button, err, async () => { await api('POST', `/v1/clients/${client.id}/state`, { state: value }); close(); route(); });
    const actions = [{ label: t('ui-close'), run: (close) => close() }];
    if (client.state === 'active') actions.push({ label: t('ui-client-suspend'), run: setState('suspended') });
    if (client.state === 'suspended') actions.push({ label: t('ui-client-resume'), kind: 'primary', run: setState('active') });
    if (client.state !== 'archived') actions.push({ label: t('ui-client-archive'), kind: 'danger', run: setState('archived') });
    modal({
      title: client.label,
      body: h('div', { style: 'display:flex;flex-direction:column;gap:12px' }, h('div', { class: 'kv' },
        h('span', { class: 'k' }, t('ui-col-state')), stateChip('client', client.state),
        h('span', { class: 'k' }, t('ui-col-quota')), h('span', null, fmtQuota(client.quota_bytes)),
        h('span', { class: 'k' }, t('ui-used')), h('span', null, used ? fmtBytes(used.total) : t('ui-none')),
        h('span', { class: 'k' }, t('ui-col-expires')), h('span', null, fmtDate(client.expires_at)),
        h('span', { class: 'k' }, t('ui-node-created')), h('span', null, fmtDate(client.created_at))), err),
      actions,
    });
  }

  function newClientModal() {
    const label = h('input', { type: 'text', required: true, pattern: '[a-z0-9_-]{1,32}', spellcheck: false });
    const quota = h('input', { type: 'number', min: '0', step: '0.1' });
    const expires = h('input', { type: 'date' });
    const err = errorLine();
    modal({
      title: t('ui-new-client-title'),
      body: h('div', { class: 'form' }, field(t('ui-new-client-label'), label, 'wide'), field(t('ui-new-client-quota'), quota), field(t('ui-new-client-expires'), expires), h('div', { class: 'wide' }, err)),
      actions: [
        { label: t('ui-cancel'), run: (close) => close() },
        { label: t('ui-create'), kind: 'primary', run: (close, button) => attempt(button, err, async () => {
          await api('POST', '/v1/clients', { label: label.value.trim(), quota_bytes: gbToBytes(quota.value), expires_at: dayToExpiry(expires.value) });
          close();
          route();
        }) },
      ],
    });
  }

  function newAccessModal(clients, nodes, isPublic) {
    const client = h('select', null, clients.filter((candidate) => candidate.state === 'active').map((candidate) => h('option', { value: candidate.id }, candidate.label)));
    const name = h('input', { type: 'text', maxlength: '64' });
    const node = h('select', null, nodes.filter((candidate) => candidate.state !== 'burned').map((candidate) => h('option', { value: candidate.id }, `${candidate.label} · ${kindOf(candidate)}`)));
    const quota = h('input', { type: 'number', min: '0', step: '0.1' });
    const expires = h('input', { type: 'date' });
    const devices = h('input', { type: 'number', min: '1', max: '1000', step: '1' });
    const err = errorLine();
    modal({
      title: t(isPublic ? 'ui-users-new-public' : 'ui-new-access-title'),
      body: h('div', { class: 'form' },
        isPublic ? field(t('ui-new-access-name'), name, 'wide') : field(t('ui-new-access-client'), client, 'wide'),
        field(t('ui-new-access-node'), node, 'wide'),
        field(t('ui-new-access-quota'), quota), field(t('ui-new-access-expires'), expires), field(t('ui-new-access-devices'), devices),
        h('div', { class: 'wide' }, err)),
      actions: [
        { label: t('ui-cancel'), run: (close) => close() },
        { label: t('ui-create'), kind: 'primary', run: (close, button) => attempt(button, err, async () => {
          const body = { node_id: node.value, quota_bytes: gbToBytes(quota.value), expires_at: dayToExpiry(expires.value), max_devices: devices.value ? Number(devices.value) : null };
          if (isPublic) body.name = name.value.trim(); else body.client_id = client.value;
          await api('POST', '/v1/accesses', body);
          close();
          route();
        }) },
      ],
    });
  }

  function linkModal(access, node) {
    const host = h('input', { type: 'text', value: (node && node.address) || (node && node.domain) || '', spellcheck: false });
    const ack = h('input', { type: 'checkbox' });
    const err = errorLine();
    const result = h('div', { style: 'display:flex;flex-direction:column;gap:8px' });
    modal({
      title: `${t('ui-link-title')} · ${access.name || nodeName(node ? [node] : [], access.node_id)}`,
      body: h('div', { style: 'display:flex;flex-direction:column;gap:12px' }, field(t('ui-link-host'), host), field(t('ui-link-ack'), ack, 'row'), err, result),
      actions: [
        { label: t('ui-close'), run: (close) => close() },
        { label: t('ui-link-get'), kind: 'primary', run: (close, button) => attempt(button, err, async () => {
          const issued = await api('POST', `/v1/accesses/${access.id}/link`, { host: host.value.trim(), acknowledged: ack.checked });
          result.replaceChildren();
          if (issued.link) {
            result.append(codeLine(issued.link));
          } else {
            result.append(h('div', { class: 'kv' },
              h('span', { class: 'k' }, t('ui-link-host')), h('span', { class: 'mono' }, issued.host),
              h('span', { class: 'k' }, t('ui-link-port')), h('span', { class: 'mono' }, issued.port),
              h('span', { class: 'k' }, t('ui-link-user')), h('span', { class: 'mono' }, issued.user),
              h('span', { class: 'k' }, t('ui-link-password')), h('span', { class: 'mono' }, issued.password)));
            result.append(codeLine(`${issued.method}://${issued.user}:${issued.password}@${issued.host}:${issued.port}`));
          }
          button.disabled = true;
        }) },
      ],
    });
  }

  function revokeModal(access, label) {
    const err = errorLine();
    modal({
      title: `${t('ui-access-revoke')} · ${label}`,
      body: h('div', null, h('p', null, t('ui-access-revoke-text')), err),
      actions: [
        { label: t('ui-cancel'), run: (close) => close() },
        { label: t('ui-access-revoke'), kind: 'danger', run: (close, button) => attempt(button, err, async () => { await api('POST', `/v1/accesses/${access.id}/state`, { state: 'revoked' }); close(); route(); }) },
      ],
    });
  }

  function accessActions(access, label, node) {
    if (access.state === 'revoked') return null;
    const flip = async (value) => { try { await api('POST', `/v1/accesses/${access.id}/state`, { state: value }); route(); } catch (error) { refused(error); } };
    return [
      access.state === 'active' ? h('button', { type: 'button', class: 'btn sm', on: { click: () => linkModal(access, node) } }, t('ui-access-link')) : null,
      access.state === 'active'
        ? h('button', { type: 'button', class: 'btn sm', on: { click: () => flip('disabled') } }, t('ui-access-disable'))
        : h('button', { type: 'button', class: 'btn sm', on: { click: () => flip('active') } }, t('ui-access-enable')),
      h('button', { type: 'button', class: 'btn sm danger', on: { click: () => revokeModal(access, label) } }, t('ui-access-revoke')),
    ];
  }

  function accessCells(access, nodes) {
    const node = nodes.find((candidate) => candidate.id === access.node_id);
    return [
      h('td', null, nodeName(nodes, access.node_id), h('div', { class: 'sub' }, t(`ui-method-${access.method}`))),
      h('td', null, stateChip('access', access.state)),
      h('td', { class: 'r mono' }, fmtQuota(access.quota_bytes)),
      h('td', { class: 'r mono' }, fmtDateShort(access.expires_at)),
      h('td', { class: 'r mono opt' }, access.max_devices == null ? t('ui-none') : fmtNum(access.max_devices)),
      h('td', { class: 'mono m2 opt' }, fmtDateShort(access.created_at)),
      node,
    ];
  }

  async function usersView() {
    const seesAll = state.me.role !== 'reseller';
    const [clients, accesses, nodes, publics] = await Promise.all([
      api('GET', `/v1/clients?limit=${PAGE}`),
      api('GET', `/v1/accesses?limit=${PAGE}`),
      seesAll ? api('GET', '/v1/nodes').catch(() => []) : Promise.resolve([]),
      seesAll ? api('GET', '/v1/accesses/public').catch(() => []) : Promise.resolve([]),
    ]);
    const byClient = new Map(clients.map((client) => [client.id, []]));
    for (const access of accesses) {
      const own = byClient.get(access.client_id);
      if (own) own.push(access);
    }

    const rows = [];
    clients.forEach((client) => {
      const accesses = byClient.get(client.id) || [];
      const userCell = () => h('td', null,
        h('button', { type: 'button', class: 'btn ghost sm', style: 'padding-left:0', on: { click: () => clientModal(client) } }, h('b', null, client.label), ' ', stateChip('client', client.state)),
        h('div', { class: 'sub' }, `${fmtQuota(client.quota_bytes)} · ${fmtDateShort(client.expires_at)}`));
      if (!accesses.length) {
        rows.push(h('tr', null, userCell(), h('td', { class: 'm3', colspan: '7' }, t('ui-empty'))));
        return;
      }
      for (const access of accesses) {
        const cells = accessCells(access, nodes);
        const node = cells.pop();
        rows.push(h('tr', null, userCell(), cells, h('td', { class: 'acts' }, accessActions(access, client.label, node))));
      }
    });

    const columns = [
      { label: t('ui-col-user') }, { label: t('ui-col-node') }, { label: t('ui-col-state') },
      { label: t('ui-col-quota'), right: true }, { label: t('ui-col-expires'), right: true },
      { label: t('ui-col-devices'), right: true, opt: true }, { label: t('ui-col-issued'), opt: true }, { label: '' },
    ];
    const publicRows = publics.map((access) => {
      const cells = accessCells(access, nodes);
      const node = cells.pop();
      return h('tr', null, h('td', { class: 'name' }, access.name || access.id.slice(0, 8)), cells, h('td', { class: 'acts' }, accessActions(access, access.name || access.id.slice(0, 8), node)));
    });
    const publicColumns = [
      { label: t('ui-col-name') }, { label: t('ui-col-node') }, { label: t('ui-col-state') },
      { label: t('ui-col-quota'), right: true }, { label: t('ui-col-expires'), right: true },
      { label: t('ui-col-devices'), right: true, opt: true }, { label: t('ui-col-issued'), opt: true }, { label: '' },
    ];

    return h('div', { class: 'content' },
      h('div', { class: 'phead' }, h('div'), h('div', { class: 'tools' },
        h('button', { type: 'button', class: 'btn', on: { click: newClientModal } }, t('ui-users-new-client')),
        nodes.length ? h('button', { type: 'button', class: 'btn primary', on: { click: () => newAccessModal(clients, nodes, false) } }, t('ui-users-new-access')) : null,
        nodes.length ? h('button', { type: 'button', class: 'btn', on: { click: () => newAccessModal(clients, nodes, true) } }, t('ui-users-new-public')) : null)),
      card('c12', t('ui-nav-users'), clients.length, rows.length ? table(columns, rows) : empty()),
      seesAll ? card('c12', t('ui-users-public'), publics.length, publicRows.length ? table(publicColumns, publicRows) : empty()) : null,
    );
  }

  // ── log ─────────────────────────────────────────────────────────────────

  async function logView() {
    const entries = await api('GET', `/v1/audit?limit=${PAGE}`);
    const filter = h('input', { type: 'search', class: 'search', placeholder: t('ui-log-filter') });
    const body = h('tbody');
    function draw() {
      const needle = filter.value.trim().toLowerCase();
      body.replaceChildren(...entries
        .filter((entry) => !needle || `${entry.action} ${entry.target || ''} ${entry.actor_id || ''} ${JSON.stringify(entry.details || {})}`.toLowerCase().includes(needle))
        .map((entry) => h('tr', null,
          h('td', { class: 'mono m2' }, fmtDateTime(entry.at)),
          h('td', { class: 'mono' }, entry.actor_id ? entry.actor_id.slice(0, 8) : t('ui-none')),
          h('td', null, entry.action),
          h('td', { class: 'mono' }, entry.target || ''),
          h('td', { class: 'mono m3', style: 'white-space:normal;overflow-wrap:anywhere' }, entry.details && Object.keys(entry.details).length ? JSON.stringify(entry.details) : ''))));
      if (!body.childElementCount) body.append(h('tr', null, h('td', { colspan: '5', class: 'm3' }, t('ui-empty'))));
    }
    filter.addEventListener('input', draw);
    draw();
    return h('div', { class: 'content' },
      h('div', { class: 'phead' }, h('div'), h('div', { class: 'tools' }, filter)),
      h('section', { class: 'card' }, h('div', { class: 'card-b' }, h('div', { class: 'scroll' }, h('table', { class: 'tbl' },
        h('thead', null, h('tr', null, [t('ui-col-time'), t('ui-col-actor'), t('ui-col-action'), t('ui-col-target'), ''].map((label) => h('th', null, label)))), body)))),
    );
  }

  // ── routing ─────────────────────────────────────────────────────────────

  const views = { dashboard: dashboardView, nodes: nodesView, users: usersView, log: logView };

  function allowed(name) {
    if (name === 'nodes') return state.me.role !== 'reseller';
    if (name === 'log') return state.me.role === 'superadmin';
    return true;
  }

  async function show(main, name, quiet) {
    if (!quiet) main.replaceChildren(topbar(name), h('div', { class: 'content' }, empty(t('ui-loading'))));
    try {
      const content = await views[name]();
      main.replaceChildren(topbar(name), content);
    } catch (error) {
      if (!quiet) main.replaceChildren(topbar(name), h('div', { class: 'content' }, empty(error.message)));
      refused(error);
    }
  }

  async function route() {
    clearInterval(state.timer);
    const main = $('#main');
    if (!state.me) {
      main.replaceChildren(loginView());
      return;
    }
    let name = (location.hash.replace(/^#\/?/, '') || 'dashboard').split('/')[0];
    if (!views[name] || !allowed(name)) name = 'dashboard';
    for (const link of $('#nav').querySelectorAll('a')) link.classList.toggle('on', link.dataset.view === name);
    await show(main, name, false);
    if (name === 'dashboard' || name === 'nodes') {
      state.timer = setInterval(() => {
        if (document.visibilityState === 'visible' && !$('#modal-root').childElementCount) show(main, name, true);
      }, REFRESH_MS);
    }
  }

  async function boot() {
    applyTheme();
    applyLangButtons();
    try {
      await loadMessages();
    } catch {
      $('#main').replaceChildren(h('div', { class: 'content' }, h('div', { class: 'empty' }, 'anyProxy')));
      return;
    }
    $('#lang').addEventListener('click', async (event) => {
      const button = event.target.closest('button');
      if (!button || button.dataset.lang === state.lang) return;
      state.lang = button.dataset.lang;
      remember('localStorage', 'ap-lang', state.lang);
      applyLangButtons();
      await loadMessages();
      showRail();
      route();
    });
    $('#theme').addEventListener('click', (event) => {
      const button = event.target.closest('button');
      if (!button) return;
      state.theme = button.dataset.theme;
      remember('localStorage', 'ap-theme', state.theme);
      applyTheme();
    });
    $('#sign-out').addEventListener('click', signOut);
    window.addEventListener('hashchange', route);
    if (state.token) {
      try { state.me = await api('GET', '/v1/session'); } catch { state.me = null; }
    }
    showRail();
    route();
  }

  boot();
})();
