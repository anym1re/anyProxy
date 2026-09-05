// The panel's interface.
//
// No markup is written here. Every screen is the stand's own, carried in a
// <template> in the page; this fills it. A list keeps its first row as the
// shape to clone, so a row on screen is the row that was drawn.
(() => {
  'use strict';

  const REFRESH_MS = 30000;
  const PAGE = 200;
  // The stand's four ranges. The series the panel keeps is by day, so the
  // shortest is a week rather than the stand's single day.
  const RANGES = [['Н', 7], ['М', 30], ['6М', 180], ['Г', 365]];

  const recall = (store, key) => { try { return window[store].getItem(key); } catch { return null; } };
  const remember = (store, key, value) => { try { window[store].setItem(key, value); } catch { /* nothing to keep it in */ } };
  const forget = (store, key) => { try { window[store].removeItem(key); } catch { /* already gone */ } };

  const state = {
    token: recall('sessionStorage', 'ap-token'),
    lang: recall('localStorage', 'ap-lang') || 'ru',
    theme: recall('localStorage', 'ap-theme') || 'dark',
    range: Number(recall('localStorage', 'ap-range')) || 30,
    messages: {},
    me: null,
    version: '',
    setupNeeded: false,
    secondFactor: true,
    lastLogin: '',
    filter: 'all',
    timer: null,
    known: { nodes: [], clients: [] },
  };

  const $ = (selector, root) => (root || document).querySelector(selector);
  const $$ = (selector, root) => [...(root || document).querySelectorAll(selector)];

  // ── filling what the stand drew ─────────────────────────────────────────

  /** The screen as drawn, ready to be filled. */
  const screen = (name) => $(`#screen-${name}`).content.cloneNode(true).firstElementChild;

  /** Sets the text of one element inside a piece of drawn markup. */
  function put(root, selector, text) {
    const el = selector ? $(selector, root) : root;
    if (el) el.textContent = text == null ? '' : String(text);
    return el;
  }

  /**
   * Repeats a drawn row for every item.
   *
   * The first child is the shape: it was drawn with sample data, and every
   * row on screen is a copy of it with the sample replaced.
   */
  function repeat(container, items, fill) {
    if (!container) return;
    const shape = container.firstElementChild;
    if (!shape) return;
    const drawn = items.map((item, index) => {
      const row = shape.cloneNode(true);
      fill(row, item, index);
      return row;
    });
    container.replaceChildren(...drawn);
  }

  /** Puts one of the stand's status dots into the state it should show. */
  function dot(el, kind) {
    if (!el) return;
    el.classList.remove('w', 'b', 'n');
    if (kind && kind !== 'ok') el.classList.add(kind === 'warn' ? 'w' : kind === 'bad' ? 'b' : 'n');
  }

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs || {})) {
      if (value == null || value === false) continue;
      if (name === 'class') el.className = value;
      else if (name === 'style') el.style.cssText = value;
      else if (name === 'on') for (const [event, fn] of Object.entries(value)) el.addEventListener(event, fn);
      else if (typeof value === 'boolean') el[name] = value;
      else el.setAttribute(name, value);
    }
    for (const child of children.flat(Infinity)) {
      if (child == null || child === false) continue;
      el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return el;
  }

  // ── words ───────────────────────────────────────────────────────────────

  function t(key, args) {
    let text = state.messages[key];
    if (text === undefined) return key;
    if (args) text = text.replace(/\{\s*\$([A-Za-z0-9_-]+)\s*\}/g, (_, name) => (args[name] == null ? '' : String(args[name])));
    return text;
  }

  const applyStaticText = (root) => $$('[data-t]', root || document).forEach((el) => { el.textContent = t(el.dataset.t); });

  async function loadMessages() {
    const reply = await fetch(`/v1/i18n?lang=${encodeURIComponent(state.lang)}`, { cache: 'no-store' });
    const payload = await reply.json();
    state.messages = payload.messages || {};
    state.lang = payload.lang || state.lang;
    document.documentElement.lang = state.lang;
    applyStaticText();
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

  function refusalText(code) {
    const key = `api-${String(code).replace(/_/g, '-')}`;
    return state.messages[key] === undefined ? t('api-unknown', { code }) : t(key);
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

  // ── figures ─────────────────────────────────────────────────────────────

  const locale = () => (state.lang === 'ru' ? 'ru-RU' : 'en-GB');
  const num = (value) => Number(value || 0).toLocaleString(locale());

  const UNITS = ['ui-unit-b', 'ui-unit-kb', 'ui-unit-mb', 'ui-unit-gb', 'ui-unit-tb'];

  function scale(value) {
    let amount = Number(value) || 0;
    let unit = 0;
    while (amount >= 1024 && unit < UNITS.length - 1) { amount /= 1024; unit += 1; }
    const digits = unit === 0 ? 0 : amount < 10 ? 2 : amount < 100 ? 1 : 0;
    return [amount.toLocaleString(locale(), { maximumFractionDigits: digits }), t(UNITS[unit])];
  }

  const bytes = (value) => scale(value).join(' ');
  const mbytes = (mb) => bytes(Number(mb || 0) * 1024 * 1024);
  const quota = (value) => (value == null ? t('ui-no-limit') : bytes(value));

  const clock = (iso) => (iso ? new Intl.DateTimeFormat(locale(), { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }).format(new Date(iso)) : '—');
  const stamp = (iso) => (iso ? new Intl.DateTimeFormat(locale(), { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(new Date(iso)) : t('ui-never'));
  const date = (iso) => (iso ? new Intl.DateTimeFormat(locale(), { dateStyle: 'medium', timeZone: 'UTC' }).format(new Date(iso)) : t('ui-no-expiry'));
  const shortDate = (iso) => (iso ? new Intl.DateTimeFormat(locale(), { dateStyle: 'short', timeZone: 'UTC' }).format(new Date(iso)) : t('ui-no-expiry'));

  function day(ymd) {
    const [year, month, date_] = ymd.split('-').map(Number);
    return new Intl.DateTimeFormat(locale(), { day: 'numeric', month: 'long', timeZone: 'UTC' }).format(new Date(Date.UTC(year, month - 1, date_)));
  }

  function ago(iso) {
    if (!iso) return t('ui-never');
    const minutes = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
    const rel = new Intl.RelativeTimeFormat(locale(), { numeric: 'auto' });
    if (minutes < 60) return rel.format(-minutes, 'minute');
    if (minutes < 60 * 24) return rel.format(-Math.round(minutes / 60), 'hour');
    return rel.format(-Math.round(minutes / 1440), 'day');
  }

  /// Days, hours or minutes — whichever says it in one figure.
  function uptime(seconds) {
    const total = Number(seconds) || 0;
    if (total >= 86400) return t('ui-uptime-days', { count: Math.floor(total / 86400) });
    if (total >= 3600) return t('ui-uptime-hours', { count: Math.floor(total / 3600) });
    return t('ui-uptime-minutes', { count: Math.floor(total / 60) });
  }

  const gbToBytes = (text) => {
    const value = Number(String(text || '').replace(',', '.'));
    return text === '' || !(value > 0) ? null : Math.round(value * 1024 * 1024 * 1024);
  };
  const dayToExpiry = (text) => (text ? `${text}T23:59:59Z` : null);

  const kindOf = (node) => t(node.kind === 'mtproto' && node.masked ? 'ui-kind-mtproto-masked' : `ui-kind-${node.kind}`);

  // How a node stands: well, uneasy, bad, or silent.
  function standing(node) {
    if (!node.health && !node.last_seen_at) return 'none';
    if (!node.health) return 'warn';
    if (node.health.engine === 'down' || node.health.reach === 'blocked') return 'bad';
    if (node.machine && node.machine.pressure === 'critical') return 'bad';
    if (node.health.site === 'down' || node.health.site === 'unknown' || node.health.reach === 'unknown') return 'warn';
    if (node.machine && node.machine.pressure !== 'calm') return 'warn';
    return 'ok';
  }

  function trouble(node) {
    if (!node.health && !node.last_seen_at) return t('ui-trouble-silent');
    if (node.health) {
      if (node.health.engine === 'down') return t('ui-trouble-engine');
      if (node.health.reach === 'blocked') return t('ui-trouble-reach');
      if (node.health.site === 'down') return t('ui-trouble-site');
    }
    if (node.machine && node.machine.pressure === 'critical') return t('ui-trouble-critical');
    if (node.machine && node.machine.pressure === 'strained') return t('ui-trouble-strained');
    if (!node.health) return t('ui-trouble-silent');
    return t('ui-trouble-unknown');
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
    toast(t('ui-copied'));
  }

  function toast(text, kind) {
    const root = $('#toast-root');
    root.replaceChildren(h('div', { class: `toast ${kind || ''}`, role: 'status' }, text));
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => root.replaceChildren(), 3600);
  }

  const refused = (error) => { if (!(error instanceof Refusal && error.status === 401)) toast(t('ui-refused', { message: error.message }), 'bad'); };

  // ── dialogs, also as drawn ──────────────────────────────────────────────

  /**
   * Shows one of the drawn dialogs.
   *
   * `prepare` gets the dialog's own markup to fill and wire; the scrim, the
   * Esc key and the buttons are the stand's.
   */
  const DIALOG_SCREEN = { link: 'link', user: 'new-user', node: 'new-node', delete: 'delete' };

  function dialog(name, prepare) {
    const root = $('#modal-root');
    root.className = `scr-${DIALOG_SCREEN[name] || name}`;
    const wrap = $(`#dialog-${name}`).content.cloneNode(true).firstElementChild;
    const box = $('.dlg', wrap) || wrap;
    function close() {
      root.replaceChildren();
      document.removeEventListener('keydown', onKey);
    }
    function onKey(event) { if (event.key === 'Escape') close(); }
    root.replaceChildren(h('div', { class: 'scrim', on: { click: close } }), wrap);
    document.addEventListener('keydown', onKey);
    prepare(box, close);
    const first = $('input, select, button', box);
    if (first) first.focus();
    return close;
  }

  /** Turns a drawn field box into one that can be typed into. */
  function editable(box, value, onInput) {
    if (!box) return null;
    const field = h('input', { class: 'inp', type: 'text', value: value == null ? '' : value });
    if (onInput) field.addEventListener('input', () => onInput(field.value));
    box.replaceWith(field);
    return field;
  }

  // ── the shell ───────────────────────────────────────────────────────────

  function applyTheme() {
    document.documentElement.dataset.theme = state.theme;
    $$('#theme > *').forEach((el) => el.classList.toggle('on', el.dataset.theme === state.theme));
  }

  const applyLang = () => $$('#lang > *').forEach((el) => el.classList.toggle('on', el.dataset.lang === state.lang));

  function showRail() {
    $('.rail').hidden = !state.me;
    $('.barstrip').hidden = !state.me;
    if (!state.me) return;
    put(document, '#me-login', state.me.login);
    put(document, '#me-role', t(`ui-role-${state.me.role}`));
    put(document, '#me-version', state.version || '—');
    $$('#screen ~ *, .rail .nav a').forEach(() => {});
    $$('.rail .nav a').forEach((link) => {
      const view = link.dataset.view;
      link.hidden = (view === 'nodes' && state.me.role === 'reseller') || (view === 'log' && state.me.role !== 'superadmin');
    });
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

  // ── the way in ──────────────────────────────────────────────────────────

  function gate(name, prepare) {
    const drawn = $(`#gate-${name}`).content.cloneNode(true).firstElementChild;
    // Both gates were drawn twice, side by side, to show the two states; a
    // panel shows the one it is in.
    const cards = $$('.card', drawn);
    prepare(drawn, cards);
    return drawn;
  }

  function loginView() {
    return gate('login', (drawn, cards) => {
      // With a code where somebody signs in with one, without it where
      // nobody does.
      const card = state.secondFactor ? cards[0] : cards[1];
      cards.filter((other) => other !== card).forEach((other) => other.remove());
      const fields = $$('.fld .inp', card);
      const login = editable(fields[0], state.lastLogin);
      const password = editable(fields[1], '');
      password.type = 'password';
      const code = fields[2] ? editable(fields[2], '') : null;
      if (code) { code.inputMode = 'numeric'; code.maxLength = 6; }
      const err = h('div', { class: 'hint bad' });
      const button = $('.btn', card);
      button.before(err);
      const submit = async () => {
        button.disabled = true;
        err.textContent = '';
        try {
          const reply = await api('POST', '/v1/session', {
            login: login.value.trim(), password: password.value, totp: code ? code.value.trim() : '',
          });
          state.token = reply.token;
          remember('sessionStorage', 'ap-token', reply.token);
          state.me = await api('GET', '/v1/session');
          showRail();
          location.hash = '#/dashboard';
          route();
        } catch (error) {
          err.textContent = error.status === 401 ? t('ui-login-failed') : error.message;
          button.disabled = false;
        }
      };
      button.addEventListener('click', submit);
      for (const field of [login, password, code]) {
        if (field) field.addEventListener('keydown', (event) => { if (event.key === 'Enter') submit(); });
      }
    });
  }

  function setupView() {
    return gate('setup', (drawn, cards) => {
      const [form, secret] = cards;
      secret.remove();
      const fields = $$('.fld .inp', form);
      const login = editable(fields[0], '');
      const password = editable(fields[1], '');
      password.type = 'password';
      const check = $('.chk', form);
      let second = true;
      check.addEventListener('click', () => {
        second = !second;
        $('.bx', check).style.cssText = second ? '' : 'background: transparent; border-color: var(--ink-3);';
        $('.bx svg', check).style.opacity = second ? '1' : '0';
      });
      $('.bx svg', check).style.opacity = '1';
      $('.bx', check).style.cssText = 'background: var(--key); border-color: var(--key);';
      const err = h('div', { class: 'hint bad' });
      const button = $('.btn', form);
      button.before(err);
      button.addEventListener('click', async () => {
        button.disabled = true;
        err.textContent = '';
        try {
          const made = await api('POST', '/v1/setup', { login: login.value.trim(), password: password.value, second_factor: second });
          state.setupNeeded = false;
          state.secondFactor = second;
          state.lastLogin = made.login;
          if (made.secret) showSecret(made.secret);
          else route();
        } catch (error) {
          err.textContent = error.message;
          button.disabled = false;
        }
      });
    });
  }

  function showSecret(value) {
    const drawn = gate('setup', (root, cards) => {
      const [form, secret] = cards;
      form.remove();
      put(secret, '.secret', value);
      $('.secret', secret).append(h('span', { class: 'cp', on: { click: () => copy(value) } }, '⧉'));
      $('.btn', secret).addEventListener('click', () => route());
    });
    $('#screen').replaceChildren(drawn);
  }

  // ── the dashboard ───────────────────────────────────────────────────────

  function curve(points, width, top, floor) {
    const max = Math.max(1, ...points.map((point) => point.in + point.out));
    const x = (index) => (index / Math.max(1, points.length - 1)) * width;
    const y = (value) => top + (1 - value / max) * (floor - top);
    const line = points.map((point, index) => {
      const px = x(index).toFixed(1);
      const py = y(point.in + point.out).toFixed(1);
      if (!index) return `M ${px} ${py}`;
      const previous = points[index - 1];
      const mid = ((x(index - 1) + x(index)) / 2).toFixed(1);
      return `C ${mid} ${y(previous.in + previous.out).toFixed(1)} ${mid} ${py} ${px} ${py}`;
    }).join(' ');
    return { line, x, y };
  }

  function series(rows, days) {
    const byDay = new Map(rows.map((point) => [point.day, point]));
    const now = new Date();
    const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
    const points = [];
    for (let back = days - 1; back >= 0; back -= 1) {
      const key = new Date(today - back * 86400000).toISOString().slice(0, 10);
      const point = byDay.get(key);
      points.push({ day: key, in: point ? Number(point.bytes_in) : 0, out: point ? Number(point.bytes_out) : 0 });
    }
    const received = points.reduce((sum, point) => sum + point.in, 0);
    const sent = points.reduce((sum, point) => sum + point.out, 0);
    const peak = points.reduce((best, point, index) => (point.in + point.out > points[best].in + points[best].out ? index : best), 0);
    return { points, received, sent, peak, total: received + sent };
  }

  async function dashboard(root) {
    const seesNodes = state.me.role !== 'reseller';
    const readsAudit = state.me.role === 'superadmin';
    const [nodes, clients, accesses, now, before] = await Promise.all([
      seesNodes ? api('GET', '/v1/nodes') : Promise.resolve([]),
      api('GET', `/v1/clients?limit=${PAGE}`),
      api('GET', `/v1/accesses?limit=${PAGE}`),
      api('GET', `/v1/traffic?days=${state.range}`),
      api('GET', `/v1/traffic?days=${state.range * 2}`),
    ]);
    state.known = { nodes, clients };

    const live = nodes.filter((node) => node.state !== 'burned');
    const seen = live.filter((node) => node.last_seen_at);
    const wanting = live.filter((node) => node.wants_attention || standing(node) === 'none');
    const drawn = series(now, state.range);
    const older = series(before, state.range * 2);
    const earlier = older.total - drawn.total;
    const change = earlier > 0 ? Math.round(((drawn.total - earlier) / earlier) * 100) : null;

    put(root, '.phead h1', t('ui-nav-dashboard'));
    // Two figures, as drawn: when it was refreshed, and how often it is.
    $('.pmeta', root).replaceChildren(
      `${t('ui-dash-updated')} `, h('span', { class: 'mono' }, clock(new Date().toISOString())),
      h('br'), `${t('ui-dash-every-prefix')} `, h('span', { class: 'mono' }, t('ui-dash-every-value', { seconds: REFRESH_MS / 1000 })));

    const cards = $$('.g > .card', root);
    const [attention, traffic, fleet, strip, hosts, processes, events] = cards;

    // ── needs attention ──
    put(attention, '.ch h2', t('ui-dash-attention'));
    put(attention, '.ch .cnt', num(wanting.length));
    const all = put(attention, '.ch .lnk', t('ui-dash-all-nodes'));
    if (all) all.setAttribute('href', '#/nodes');
    if (wanting.length) {
      repeat($('.cb', attention), wanting.slice(0, 6), (row, node) => {
        dot($('.sd', row), standing(node));
        $('.nm', row).lastChild.textContent = node.label;
        put(row, '.what', trouble(node));
        put(row, '.since', ago(node.last_seen_at));
        const act = $('.act .btn', row);
        act.textContent = t('ui-dash-open-node');
        act.setAttribute('href', '#/nodes');
        // The stand marks the row that needs doing something about first.
        act.classList.toggle('key', standing(node) === 'bad');
      });
    } else {
      const row = $('.cb .prow', attention);
      dot($('.sd', row), 'ok');
      $('.nm', row).lastChild.textContent = t('ui-dash-all-calm');
      put(row, '.what', t('ui-dash-calm-note', { count: num(seen.length) }));
      put(row, '.since', '');
      $('.act', row).replaceChildren();
      $('.cb', attention).replaceChildren(row);
      attention.classList.remove('att');
    }

    // ── traffic ──
    put(traffic, '.ch h2', t('ui-dash-traffic'));
    put(traffic, '.ch .note', t('ui-dash-traffic-note'));
    const seg = $('.seg', traffic);
    seg.replaceChildren(...RANGES.map(([label, days]) => h('label', {
      class: days === state.range ? 'on' : '',
      role: 'button',
      tabindex: '0',
      on: { click: () => { state.range = days; remember('localStorage', 'ap-range', String(days)); route(); } },
    }, label)));
    const [total, unit] = scale(drawn.total);
    put(traffic, '.big .v', total);
    put(traffic, '.big .u', unit);
    const delta = $('.big .delta', traffic);
    if (change == null) {
      delta.remove();
    } else {
      // The stand carried a figure per range in its own <b>; one range is
      // drawn here, so the spares go with it.
      $$('b', delta).slice(1).forEach((spare) => spare.remove());
      put(delta, 'b', t(change < 0 ? 'ui-dash-down' : 'ui-dash-up', { percent: Math.abs(change) }));
    }

    const svg = $('.chart svg', traffic);
    const view = svg.getAttribute('viewBox').split(' ').map(Number);
    const { line, x, y } = curve(drawn.points, view[2], 8, 162);
    // The stand drew a curve per range; the panel draws the one it was asked
    // for, so the spare fills and lines go — the first of each stays.
    const fills = $$('.fill', svg);
    const lines = $$('.line', svg);
    fills.slice(1).forEach((path) => path.remove());
    lines.slice(1).forEach((path) => path.remove());
    const fill = fills[0];
    const stroke = lines[0];
    fill.setAttribute('d', `${line} L ${view[2]} ${view[3]} L 0 ${view[3]} Z`);
    stroke.setAttribute('d', line);
    // The line is drawn by a dash the length of the path; the stand's was
    // 1500 units long and ours is whatever the days make it, so it is
    // measured rather than assumed — otherwise the curve arrives in pieces.
    const length = Math.ceil(stroke.getTotalLength());
    stroke.style.strokeDasharray = length;
    stroke.style.strokeDashoffset = length;
    stroke.style.animationName = 'draw';
    const top = drawn.points[drawn.peak];
    const peakX = x(drawn.peak).toFixed(1);
    const peakY = y(top.in + top.out).toFixed(1);
    const vline = $('.vline', svg);
    vline.setAttribute('x1', peakX);
    vline.setAttribute('x2', peakX);
    vline.setAttribute('y1', peakY);
    const mark = $('.pk', svg);
    mark.setAttribute('cx', peakX);
    mark.setAttribute('cy', peakY);
    const tip = $('.tip', traffic);
    tip.style.left = `${Math.min(88, Math.max(12, (drawn.peak / Math.max(1, drawn.points.length - 1)) * 100))}%`;
    put(tip, '.d', day(top.day));
    put(tip, '.n', bytes(top.in + top.out));
    put(tip, '.s', `${t('ui-dash-received')} ${bytes(top.in)} · ${t('ui-dash-sent')} ${bytes(top.out)}`);
    const axis = $$('.xax > span', traffic);
    put(axis[0], null, day(drawn.points[0].day));
    put(axis[1], null, day(drawn.points[drawn.points.length - 1].day));
    const foot = $$('.tfoot > span', traffic);
    const figure = (span, label, value) => span.replaceChildren(`${label} `, h('b', null, value));
    figure(foot[0], t('ui-dash-received'), bytes(drawn.received));
    figure(foot[1], t('ui-dash-sent'), bytes(drawn.sent));
    figure(foot[2], t('ui-dash-peak'), bytes(top.in + top.out));
    figure(foot[3], t('ui-dash-average'), bytes(drawn.total / state.range));

    // ── the fleet ──
    if (!seesNodes) fleet.remove();
    else {
      put(fleet, '.ch h2', t('ui-dash-nodes'));
      put(fleet, '.ch .note', t('ui-dash-updated-at', { time: clock(new Date().toISOString()) }));
      const count = $('.fleet', fleet);
      count.replaceChildren(h('span', { class: 'v' }, num(seen.length)), h('span', { class: 'u' }, t('ui-dash-in-touch', { count: num(live.length) })));
      repeat($('.bars', fleet), live.slice(0, 24), (bar, node, index) => {
        dot(bar, standing(node));
        bar.style.setProperty('--sd', `${index * 40}ms`);
      });
      repeat($('.nlist', fleet), live.slice(0, 5), (row, node) => {
        dot($('.sd', row), standing(node));
        put(row, '.nm', node.label);
        $('.nm', row).classList.toggle('m3', standing(node) === 'none');
        const rt = $('.rt', row);
        rt.className = `rt ${standing(node) === 'ok' ? '' : standing(node) === 'bad' ? 'b' : 'w'}`;
        rt.textContent = standing(node) === 'ok' ? `${node.agent_version || '—'} · ${clock(node.last_seen_at)}` : trouble(node);
      });
      const banner = $('.banner', fleet);
      if (!wanting.length) banner.remove();
      else {
        put(banner, 'span', `${wanting[0].label}: ${trouble(wanting[0])}`);
        const link = $('a', banner);
        link.textContent = t('ui-dash-open-node');
        link.setAttribute('href', '#/nodes');
      }
    }

    // ── the strip of four ──
    const versions = [...new Set(live.map((node) => node.agent_version).filter(Boolean))];
    const cells = $$('.strip4 > div', strip);
    const cell = (index, label, ...value) => {
      put(cells[index], '.k', label);
      $('.v', cells[index]).replaceChildren(...value);
    };
    cell(0, t('ui-strip-panel'), h('span', { class: 'mono' }, state.version || '—'));
    cell(1, t('ui-strip-agents'), h('span', { class: 'mono' }, versions.length ? versions.join(' · ') : '—'));
    cell(2, t('ui-strip-channel'), h('span', { class: `sd ${seen.length === live.length ? '' : 'w'}` }), t('ui-dash-in-touch-of', { seen: num(seen.length), total: num(live.length) }));
    cell(3, t('ui-strip-accesses'), h('span', { class: 'sd' }), h('span', { class: 'mono' }, num(accesses.filter((access) => access.state === 'active').length)),
      h('span', { class: 'm3' }, ` · ${t('ui-strip-of-clients', { count: num(clients.length) })}`));

    // ── hosts ──
    if (!seesNodes) hosts.remove();
    else {
      put(hosts, '.ch h2', t('ui-dash-hosts'));
      put(hosts, '.ch .note', t('ui-dash-hosts-note'));
      const head = $$('.t-host .th > div', hosts);
      [t('ui-col-node'), t('ui-col-cpu'), t('ui-col-memory'), t('ui-col-network'), t('ui-col-connections'), t('ui-col-uptime')]
        .forEach((label, index) => { if (head[index]) put(head[index], null, label); });
      const reported = live.filter((node) => node.machine);
      const shown = (reported.length ? reported : live).slice(0, 8);
      const body = $('.t-host', hosts);
      const rows = [...body.children].filter((child) => child.classList.contains('tr'));
      const shape = rows[0];
      body.replaceChildren($('.th', body), ...shown.map((node) => {
        const row = shape.cloneNode(true);
        const machine = node.machine;
        dot($('.nmdot .sd', row), standing(node));
        $('.nmdot', row).lastChild.textContent = node.label;
        const cellAt = (index, text, part) => {
          const box = $$('.cell', row)[index];
          put(box, '.pct', text);
          $('.pct', box).classList.toggle('warn', part != null && part >= 0.85);
          const bar = $('.bar i', box);
          if (part == null) $('.bar', box).remove();
          else { bar.style.setProperty('--p', part.toFixed(2)); bar.classList.toggle('hot', part >= 0.85); }
        };
        const share = (used, limit) => (limit ? Math.min(1, Number(used) / Number(limit)) : null);
        const percent = (part) => (part == null ? '—' : `${Math.round(part * 100)} %`);
        if (machine) {
          const processor = machine.cpu_percent == null ? null : Math.min(1, machine.cpu_percent / 100);
          const memory = share(machine.memory_used_mb, machine.memory_limit_mb);
          cellAt(0, processor == null ? '—' : `${Math.round(machine.cpu_percent)} %`, processor);
          cellAt(1, percent(memory), memory);
        } else {
          // The stand draws a silent node as a short row of dashes rather
          // than as gauges with nothing in them.
          const cells = $$('.cell', row);
          cells[0].className = 'm3';
          cells[0].replaceChildren(t('ui-no-report'));
          cells[1].className = 'm3';
          cells[1].replaceChildren('—');
        }
        const rest = [...row.children].slice(3);
        const speed = (bytes) => (bytes == null ? '—' : `${(Number(bytes) * 8 / 1e6).toFixed(1)}`);
        if (machine && (machine.rx_bps != null || machine.tx_bps != null)) {
          rest[0].replaceChildren(speed(machine.rx_bps), h('span', { class: 'm3' }, ` / ${speed(machine.tx_bps)}`));
        } else {
          put(rest[0], null, '—');
        }
        put(rest[1], null, machine && machine.connections != null ? num(machine.connections) : '—');
        put(rest[2], null, machine && machine.uptime_seconds != null ? uptime(machine.uptime_seconds) : '—');
        return row;
      }));
    }

    // ── processes ──
    // What the agent says about the engine and about itself. The columns the
    // stand drew for cpu, memory and restarts are not reported yet, and stay
    // empty rather than filled with a guess.
    if (!seesNodes) processes.remove();
    else {
      // One row per process name, gathered across the nodes that report it.
      const gathered = new Map();
      for (const node of live) {
        for (const process of node.processes || []) {
          const row = gathered.get(process.name) || { name: process.name, hosts: 0, cpu: 0, memory: 0, restarts: 0 };
          row.hosts += 1;
          row.cpu += Number(process.cpu_percent || 0);
          row.memory += Number(process.memory_mb || 0);
          row.restarts += Number(process.restarts || 0);
          gathered.set(process.name, row);
        }
      }
      const rows = [...gathered.values()].map((row) => ({
        name: row.name,
        hosts: t('ui-proc-of-nodes', { count: num(row.hosts), total: num(live.length) }),
        cpu: `${(row.cpu / Math.max(1, row.hosts)).toFixed(1)} %`,
        memory: mbytes(row.memory),
        restarts: row.restarts,
        well: row.restarts === 0,
      }));
      const head = $$('.t-proc .th > div', processes);
      [t('ui-col-process'), t('ui-col-hosts'), t('ui-col-cpu'), t('ui-col-memory'), t('ui-col-restarts')]
        .forEach((label, index) => { if (head[index]) head[index].textContent = label; });
      const body = $('.t-proc', processes);
      const shape = [...body.children].find((child) => child.classList.contains('tr'));
      if (!rows.length) {
        body.replaceChildren($('.th', body), h('div', { class: 'tr m3' }, t('ui-no-report')));
      } else body.replaceChildren($('.th', body), ...rows.map((row) => {
        const drawn = shape.cloneNode(true);
        dot($('.nmdot .sd', drawn), row.well ? 'ok' : 'warn');
        $('.nmdot .mono', drawn).textContent = row.name;
        const rest = [...drawn.children].slice(1);
        put(rest[0], null, row.hosts);
        put(rest[1], null, row.cpu);
        put(rest[2], null, row.memory);
        put(rest[3], null, t('ui-proc-restarts', { count: num(row.restarts) }));
        rest[3].className = row.restarts ? 'r mono warn' : 'r mono m3';
        return drawn;
      }));
    }

    // ── events ──
    if (!readsAudit) events.remove();
    else {
      const audit = await api('GET', '/v1/audit?limit=6');
      put(events, '.ch h2', t('ui-dash-events'));
      const all = $('.ch .lnk', events);
      if (all) { all.textContent = t('ui-dash-all-log'); all.setAttribute('href', '#/log'); }
      repeat($('.cb', events), audit, (row, entry) => {
        put(row, '.t', clock(entry.at));
        dot($('.sd', row), entry.action.includes('burn') || entry.action.includes('revoke') ? 'bad' : 'ok');
        const words = [...row.children].find((child) => !child.className);
        if (words) words.textContent = `${entry.action}${entry.target ? ` · ${entry.target}` : ''}`;
        put(row, '.who', entry.actor_id ? entry.actor_id.slice(0, 8) : t('ui-none'));
      });
    }

  }

  // ── nodes, users, log: the stand's own markup, filled ───────────────────

  async function nodes(root) {
    const [list, accesses] = await Promise.all([
      api('GET', '/v1/nodes'),
      api('GET', `/v1/accesses?limit=${PAGE}`),
    ]);
    state.known.nodes = list;
    const live = list.filter((node) => node.state !== 'burned');
    const shown = live.filter((node) => state.filter === 'all'
      || (state.filter === 'attention' ? standing(node) !== 'ok' : node.kind === state.filter));
    const held = new Map();
    for (const access of accesses) held.set(access.node_id, (held.get(access.node_id) || 0) + 1);

    put(root, '.phead h1', t('ui-nav-nodes'));
    const well = live.filter((node) => standing(node) === 'ok').length;
    $('.phead .pmeta', root)?.replaceChildren(
      t('ui-nodes-well', { well: num(well), total: num(live.length) }), h('br'),
      t('ui-nodes-wanting', { count: num(live.length - well) }));

    // The filters the stand drew, made to work.
    const kinds = [...new Set(live.map((node) => node.kind))];
    const filters = [
      ['all', t('ui-all'), live.length],
      ['attention', t('ui-filter-attention'), live.filter((node) => standing(node) !== 'ok').length],
      ...kinds.map((kind) => [kind, t(`ui-kind-${kind}`), live.filter((node) => node.kind === kind).length]),
    ];
    const bar = $('.fbar', root);
    if (bar) {
      const shape = bar.firstElementChild;
      bar.replaceChildren(...filters.map(([value, label, count]) => {
        const chip = shape.cloneNode(true);
        const badge = $('.n', chip);
        chip.replaceChildren(label, badge || '');
        if (badge) badge.textContent = num(count);
        chip.classList.toggle('on', state.filter === value);
        chip.removeAttribute('for');
        chip.addEventListener('click', () => { state.filter = value; route(); });
        return chip;
      }));
      if (state.me.role === 'superadmin') {
        bar.append(h('button', { type: 'button', class: 'btn key', style: 'margin-left: auto',
          on: { click: newNode } }, t('ui-nodes-new')));
      }
    }

    // The stand drew a node in four conditions and a tile for adding one.
    // A node takes the card it was drawn in rather than the first one.
    const grid = $('.grid', root);
    const drawn = [...grid.children].filter((child) => child.classList.contains('card'));
    const add = $('.add', grid);
    const shapes = {
      ok: drawn[0],
      warn: drawn[1] || drawn[0],
      bad: drawn[drawn.length - 1],
      none: drawn[drawn.length - 1],
    };
    const cards = shown.map((node, index) => {
      const card = shapes[standing(node)].cloneNode(true);
      card.style.setProperty('--d', `${Math.min(index, 12) * 40}ms`);
      fillNodeCard(card, node, held.get(node.id) || 0);
      return card;
    });
    if (add && state.me.role === 'superadmin') {
      add.removeAttribute('href');
      add.addEventListener('click', (event) => { event.preventDefault(); newNode(); });
      cards.push(add);
    }
    grid.replaceChildren(...cards);
  }

  const DOT_WORD = { ok: 'up', warn: 'warn', bad: 'bad', none: 'none' };

  function fillNodeCard(card, node, accesses) {
    const machine = node.machine;
    const how = standing(node);
    const head = $('.chead', card);
    const mark = $('.sd', head);
    mark.className = `sd ${DOT_WORD[how]}`;
    put(head, '.nm', node.label);
    const badge = $('.badge', head);
    if (badge) {
      badge.textContent = t(`ui-node-state-${node.state}`);
      badge.className = `badge ${how === 'ok' ? 'hid' : ''}`;
    }
    const where = node.domain || node.address || '—';
    const line = $('.cline', card);
    if (how === 'ok') line.replaceChildren(h('span', { class: 'mono' }, where), ` · ${kindOf(node)}`);
    else line.replaceChildren(trouble(node), ' · ', h('span', { class: 'mono' }, where));
    put(card, '.hw', machine
      ? `${num(machine.cpus)} CPU · ${machine.memory_limit_mb ? mbytes(machine.memory_limit_mb) : '—'}`
      : '—');

    const stats = $$('.stat', card);
    const stat = (index, key, value, unit) => {
      if (!stats[index]) return;
      put(stats[index], '.k', key);
      $('.v', stats[index]).replaceChildren(value, unit ? h('span', null, ` ${unit}`) : '');
    };
    stat(0, t('ui-col-accesses'), num(accesses));
    stat(1, t('ui-col-connections'), machine && machine.connections != null ? num(machine.connections) : '—');
    stat(2, t('ui-col-uptime'), machine && machine.uptime_seconds != null ? uptime(machine.uptime_seconds) : '—');

    const health = $$('.health > div', card);
    const words = node.health
      ? [[t('ui-health-engine'), node.health.engine], [t('ui-health-site'), node.health.site], [t('ui-health-reach'), node.health.reach]]
      : [[t('ui-health-engine'), null], [t('ui-health-site'), null], [t('ui-health-reach'), null]];
    words.forEach(([key, value], index) => {
      if (!health[index]) return;
      put(health[index], '.k', key);
      const shownValue = value ? t(`ui-word-${value}`) : t('ui-no-report');
      const mark_ = h('i', { class: value === 'up' || value === 'open' ? '' : value ? 'bad' : 'n' });
      $('.v', health[index]).replaceChildren(mark_, shownValue);
    });

    // The stand's strip is half an hour of history, which the panel does not
    // keep yet; the bars stand for what the node is now, so the shape is the
    // drawn one and says nothing it does not know.
    const strip = $('.strip', card);
    if (strip) {
      repeat(strip, Array.from({ length: 20 }), (bar, _, index) => {
        dot(bar, how);
        bar.style.setProperty('--sd', `${index * 12}ms`);
      });
    }
    const label = $('.striplbl', card);
    if (label) {
      const spans = [...label.children];
      put(spans[0], null, node.last_seen_at ? ago(node.last_seen_at) : t('ui-never'));
      put(spans[1], null, t(`ui-node-state-${node.state}`));
    }

    const foot = $('.cfoot', card);
    if (foot) {
      put(foot, '.mono', `${node.agent_version || '—'} · ${node.last_seen_at ? clock(node.last_seen_at) : t('ui-never')}`);
      const cert = $('.cert', foot);
      if (cert) {
        cert.textContent = node.health && node.health.cert_not_after
          ? t('ui-cert-until', { date: date(node.health.cert_not_after) })
          : (node.kind === 'web' ? t('ui-cert-none') : '');
      }
      const acts = $('.a', foot);
      if (acts) {
        acts.replaceChildren(...(state.me.role === 'superadmin' && node.state !== 'burned' ? [
          node.domain != null ? h('a', { href: '#', on: { click: (event) => { event.preventDefault(); renameNode(node); } } }, t('ui-node-rename')) : null,
          h('a', { href: '#', on: { click: (event) => { event.preventDefault(); enrol(node); } } }, t('ui-node-code')),
          h('a', { href: '#', class: 'risk', on: { click: (event) => { event.preventDefault(); deleteNode(node); } } }, t('ui-node-delete')),
        ].filter(Boolean) : []));
      }
    }
  }

  async function users(root) {
    const seesAll = state.me.role !== 'reseller';
    const [clients, accesses, list, publics] = await Promise.all([
      api('GET', `/v1/clients?limit=${PAGE}`),
      api('GET', `/v1/accesses?limit=${PAGE}`),
      seesAll ? api('GET', '/v1/nodes').catch(() => []) : Promise.resolve([]),
      seesAll ? api('GET', '/v1/accesses/public').catch(() => []) : Promise.resolve([]),
    ]);
    state.known = { nodes: list, clients };

    put(root, '.phead h1', t('ui-nav-users'));
    $('.phead .pmeta', root)?.replaceChildren(
      t('ui-users-count', { count: num(clients.length) }), h('br'),
      t('ui-users-accesses', { count: num(accesses.length + publics.length) }));
    $('.phead', root).append(h('div', { class: 'df', style: 'margin-left: auto; gap: 8px' },
      h('button', { type: 'button', class: 'btn', on: { click: newClient } }, t('ui-users-new-client')),
      list.length ? h('button', { type: 'button', class: 'btn key', on: { click: () => newAccess(clients, list, false) } }, t('ui-users-new-access')) : null,
      list.length ? h('button', { type: 'button', class: 'btn', on: { click: () => newAccess(clients, list, true) } }, t('ui-users-new-public')) : null));

    const table = $('.tbl', root);
    const head = $$('.th > div', table);
    [t('ui-col-user'), t('ui-col-node'), t('ui-col-method'), t('ui-col-quota'), t('ui-col-expires'), t('ui-col-link')]
      .forEach((label, index) => { if (head[index]) head[index].textContent = label; });

    const byClient = new Map(clients.map((client) => [client.id, []]));
    for (const access of accesses) byClient.get(access.client_id)?.push(access);
    const rows = [];
    for (const client of clients) {
      const own = byClient.get(client.id) || [];
      if (!own.length) rows.push({ client, access: null, first: true });
      own.forEach((access, index) => rows.push({ client, access, first: index === 0 }));
    }
    for (const access of publics) rows.push({ client: null, access, first: true });

    const shape = $('.tr', table);
    const header = $('.th', table);
    table.replaceChildren(header, ...rows.map(({ client, access, first }) => {
      const row = shape.cloneNode(true);
      const node = access ? list.find((candidate) => candidate.id === access.node_id) : null;
      const who = $('.who', row);
      who.className = `who ${first ? '' : 'same'}`;
      who.replaceChildren(client
        ? h('button', { type: 'button', class: 'lnk', on: { click: () => clientCard(client) } }, first ? client.label : '')
        : h('span', null, access.name || '—'));
      const where = $('.node', row);
      where.replaceChildren(h('span', { class: `sd ${node && standing(node) === 'ok' ? '' : 'w'}` }), node ? node.label : '—');
      const cells = [...row.children];
      if (cells[2]) cells[2].textContent = access ? t(`ui-method-${access.method}`) : t('ui-empty');
      if (cells[3]) cells[3].textContent = access ? quota(access.quota_bytes) : '';
      if (cells[4]) cells[4].textContent = access ? shortDate(access.expires_at) : '';
      // The stand shows the link in this cell. A link is a secret, and the
      // panel hands one out only through the endpoint that writes to the
      // audit log — so the cell shows that a link exists and the button
      // beside it is what asks for it.
      const link = $('.lk', row);
      if (link) {
        const value = $('.v', link);
        const ask = $('.cp', link);
        if (!access || access.state === 'revoked') {
          link.replaceChildren(h('span', { class: 'v m3' }, access ? t('ui-access-state-revoked') : ''));
        } else {
          if (value) value.textContent = t('ui-link-hidden');
          if (ask) {
            ask.replaceChildren(h('button', { type: 'button', class: 'btn', on: { click: () => linkFor(access, node) } }, t('ui-access-link')));
          }
          link.append(h('button', {
            type: 'button',
            class: 'btn',
            on: { click: () => setAccess(access, access.state === 'active' ? 'disabled' : 'active') },
          }, t(access.state === 'active' ? 'ui-access-disable' : 'ui-access-enable')));
        }
      }
      return row;
    }));
  }

  async function log(root) {
    const entries = await api('GET', `/v1/audit?limit=${PAGE}`);
    put(root, '.phead h1', t('ui-nav-log'));
    $('.phead .pmeta', root)?.replaceChildren(t('ui-log-count', { count: num(entries.length) }));

    const table = $('.tbl', root);
    const head = $$('.th > div', table);
    [t('ui-col-time'), t('ui-col-actor'), t('ui-col-action'), t('ui-col-target'), t('ui-col-details'), '']
      .forEach((label, index) => { if (head[index]) head[index].textContent = label; });

    // The filter the stand drew above the table.
    const bar = $('.fbar', root);
    let needle = '';
    const shape = $('.tr', table);
    const header = $('.th', table);
    function draw() {
      const shown = entries.filter((entry) => !needle
        || `${entry.action} ${entry.target || ''} ${JSON.stringify(entry.details || {})}`.toLowerCase().includes(needle));
      table.replaceChildren(header, ...shown.map((entry) => {
        const row = shape.cloneNode(true);
        row.className = 'tr';
        row.removeAttribute('for');
        const cells = [...row.children];
        if (cells[0]) cells[0].textContent = clock(entry.at);
        if (cells[1]) cells[1].textContent = entry.actor_id ? entry.actor_id.slice(0, 8) : t('ui-none');
        if (cells[2]) { cells[2].textContent = entry.action; cells[2].className = 'ev'; }
        if (cells[3]) cells[3].textContent = entry.target || '—';
        if (cells[4]) cells[4].textContent = entry.details && Object.keys(entry.details).length ? JSON.stringify(entry.details) : '';
        if (cells[5]) cells[5].textContent = stamp(entry.at).split(',')[0];
        return row;
      }));
      if (!shown.length) table.append(h('div', { class: 'tr m3' }, t('ui-empty')));
    }
    if (bar) {
      const search = h('input', { class: 'inp', type: 'search', placeholder: t('ui-log-filter'), style: 'max-width: 280px' });
      search.addEventListener('input', () => { needle = search.value.trim().toLowerCase(); draw(); });
      bar.replaceChildren(search);
    }
    draw();
  }

  // ── the things a screen can do ──────────────────────────────────────────

  const reload = () => route();

  async function setAccess(access, value) {
    try { await api('POST', `/v1/accesses/${access.id}/state`, { state: value }); reload(); } catch (error) { refused(error); }
  }

  function linkFor(access, node) {
    dialog('link', (box, close) => {
      const fields = $$('.fld .inp', box);
      const host = editable(fields[0], (node && node.address) || (node && node.domain) || '');
      const pairs = $('.pair', box);
      if (pairs) pairs.replaceChildren();
      const shown = $('.link', box);
      shown.replaceChildren(h('span', { class: 'm3' }, '—'));
      let acknowledged = false;
      const check = $('.chk', box);
      if (check) {
        $('.bx svg', check).style.opacity = '0';
        check.addEventListener('click', () => {
          acknowledged = !acknowledged;
          $('.bx svg', check).style.opacity = acknowledged ? '1' : '0';
          $('.bx', check).style.cssText = acknowledged ? 'background: var(--key); border-color: var(--key);' : '';
        });
      }
      const buttons = $$('.df .btn', box);
      buttons[0].addEventListener('click', close);
      const get = buttons[1] || buttons[0];
      get.addEventListener('click', async () => {
        try {
          const issued = await api('POST', `/v1/accesses/${access.id}/link`, { host: host.value.trim(), acknowledged });
          const text = issued.link || `${issued.method}://${issued.user}:${issued.password}@${issued.host}:${issued.port}`;
          shown.replaceChildren(text, h('span', { class: 'cp', on: { click: () => copy(text) } }, '⧉'));
          if (pairs && !issued.link) {
            pairs.replaceChildren(...[[t('ui-link-host'), issued.host], [t('ui-link-port'), issued.port],
              [t('ui-link-user'), issued.user], [t('ui-link-password'), issued.password]]
              .flatMap(([key, value]) => [h('span', { class: 'k' }, key), h('span', { class: 'v' }, value)]));
          }
        } catch (error) { refused(error); }
      });
    });
  }

  function newClient() {
    dialog('user', (box, close) => {
      const cards = $$('.dlg', box.parentElement);
      const fields = $$('.fld .inp', box);
      const label = editable(fields[0], '');
      const quotaField = editable(fields[1], '');
      const expires = editable(fields[2], '');
      expires.type = 'date';
      const buttons = $$('.df .btn', box);
      buttons[0].addEventListener('click', close);
      buttons[1].addEventListener('click', async () => {
        try {
          await api('POST', '/v1/clients', {
            label: label.value.trim(), quota_bytes: gbToBytes(quotaField.value), expires_at: dayToExpiry(expires.value),
          });
          close();
          reload();
        } catch (error) { refused(error); }
      });
      cards.slice(1).forEach((card) => card.remove());
    });
  }

  function newAccess(clients, nodes_, isPublic) {
    dialog('user', (box, close) => {
      const wrap = box.parentElement;
      const cards = $$('.dlg', wrap);
      const card = cards[1] || cards[0];
      cards.filter((other) => other !== card).forEach((other) => other.remove());
      const fields = $$('.fld .inp', card);
      const who = fields[0];
      const client = h('select', { class: 'inp' }, clients.filter((candidate) => candidate.state === 'active')
        .map((candidate) => h('option', { value: candidate.id }, candidate.label)));
      const name = h('input', { class: 'inp', type: 'text', maxlength: '64' });
      who.replaceWith(isPublic ? name : client);
      const node = h('select', { class: 'inp' }, nodes_.filter((candidate) => candidate.state !== 'burned')
        .map((candidate) => h('option', { value: candidate.id }, `${candidate.label} · ${kindOf(candidate)}`)));
      fields[1].replaceWith(node);
      const quotaField = editable(fields[2], '');
      const devices = editable(fields[3], '');
      const expires = editable(fields[4], '');
      expires.type = 'date';
      const buttons = $$('.df .btn', card);
      buttons[0].addEventListener('click', close);
      buttons[1].addEventListener('click', async () => {
        const body = {
          node_id: node.value,
          quota_bytes: gbToBytes(quotaField.value),
          expires_at: dayToExpiry(expires.value),
          max_devices: devices.value ? Number(devices.value) : null,
        };
        if (isPublic) body.name = name.value.trim(); else body.client_id = client.value;
        try { await api('POST', '/v1/accesses', body); close(); reload(); } catch (error) { refused(error); }
      });
    });
  }

  function clientCard(client) {
    dialog('user', (box, close) => {
      const cards = $$('.dlg', box.parentElement);
      cards.slice(1).forEach((card) => card.remove());
      put(box, '.dh h2', client.label);
      put(box, '.dh .note', t(`ui-client-state-${client.state}`));
      $('.db', box).replaceChildren(h('div', { class: 'pair' },
        h('span', { class: 'k' }, t('ui-col-quota')), h('span', { class: 'v' }, quota(client.quota_bytes)),
        h('span', { class: 'k' }, t('ui-col-expires')), h('span', { class: 'v' }, date(client.expires_at)),
        h('span', { class: 'k' }, t('ui-node-created')), h('span', { class: 'v' }, date(client.created_at))));
      const buttons = $$('.df .btn', box);
      buttons[0].textContent = t('ui-close');
      buttons[0].addEventListener('click', close);
      buttons[1].textContent = t(client.state === 'active' ? 'ui-client-suspend' : 'ui-client-resume');
      buttons[1].classList.remove('key');
      buttons[1].addEventListener('click', async () => {
        try {
          await api('POST', `/v1/clients/${client.id}/state`, { state: client.state === 'active' ? 'suspended' : 'active' });
          close();
          reload();
        } catch (error) { refused(error); }
      });
    });
  }

  function newNode() {
    dialog('node', (box, close) => {
      const fields = $$('.fld .inp', box);
      const label = editable(fields[0], '');
      const kinds = $$('.tcard', box);
      let kind = 'mtproto';
      let masked = true;
      const domainBox = fields[1] ? editable(fields[1], '') : null;
      kinds.forEach((choice) => choice.addEventListener('click', () => {
        kinds.forEach((other) => other.classList.remove('on'));
        choice.classList.add('on');
        kind = (choice.textContent.match(/mtproto|web|socks5|http/i) || ['mtproto'])[0].toLowerCase();
      }));
      const check = $('.chk', box);
      if (check) check.addEventListener('click', () => { masked = !masked; $('.bx svg', check).style.opacity = masked ? '1' : '0'; });
      const buttons = $$('.df .btn', box);
      buttons[0].addEventListener('click', close);
      buttons[buttons.length - 1].addEventListener('click', async () => {
        const body = { label: label.value.trim(), kind };
        if (kind === 'mtproto') body.masked = masked;
        if (domainBox && domainBox.value.trim()) body.domain = domainBox.value.trim();
        try {
          const node = await api('POST', '/v1/nodes', body);
          close();
          enrol(node);
        } catch (error) { refused(error); }
      });
    });
  }

  async function enrol(node) {
    let issued;
    try { issued = await api('POST', `/v1/nodes/${node.id}/enrollment`); } catch (error) { refused(error); return; }
    const command = `anyproxy-agent enroll --panel <panel-host>:8443 --code ${issued.code} --fingerprint ${issued.panel_fingerprint}`;
    dialog('link', (box, close) => {
      put(box, '.dh h2', `${t('ui-enrol-title')} · ${node.label}`);
      put(box, '.dh .note', t('ui-enrol-expires', { date: stamp(issued.expires_at) }));
      const pairs = $('.pair', box);
      if (pairs) {
        pairs.replaceChildren(
          h('span', { class: 'k' }, t('ui-enrol-code')), h('span', { class: 'v' }, issued.code),
          h('span', { class: 'k' }, t('ui-enrol-fingerprint')), h('span', { class: 'v' }, issued.panel_fingerprint));
      }
      const fields = $$('.fld .inp', box);
      if (fields[0]) fields[0].remove();
      const shown = $('.link', box);
      shown.replaceChildren(command, h('span', { class: 'cp', on: { click: () => copy(command) } }, '⧉'));
      const check = $('.chk', box);
      if (check) check.remove();
      const buttons = $$('.df .btn', box);
      buttons.forEach((button, index) => { if (index) button.remove(); });
      buttons[0].textContent = t('ui-close');
      buttons[0].addEventListener('click', () => { close(); reload(); });
    });
  }

  function renameNode(node) {
    dialog('user', (box, close) => {
      $$('.dlg', box.parentElement).slice(1).forEach((card) => card.remove());
      put(box, '.dh h2', `${t('ui-rename-title')} · ${node.label}`);
      const fields = $$('.fld .inp', box);
      const domain = editable(fields[0], node.domain || '');
      $$('.fld', box).slice(1).forEach((field) => field.remove());
      $('.two', box)?.remove();
      const buttons = $$('.df .btn', box);
      buttons[0].addEventListener('click', close);
      buttons[1].textContent = t('ui-save');
      buttons[1].addEventListener('click', async () => {
        try { await api('POST', `/v1/nodes/${node.id}/names`, { domain: domain.value.trim() || null }); close(); reload(); } catch (error) { refused(error); }
      });
    });
  }

  function deleteNode(node) {
    dialog('delete', (box, close) => {
      put(box, '.dh h2', t('ui-node-delete-title', { label: node.label }));
      const confirm = $('.confirm .inp, .lock .inp, .fld .inp', box) || $('.inp', box);
      const typed = editable(confirm, '');
      const buttons = $$('.df .btn', box);
      const go = buttons[buttons.length - 1];
      go.disabled = true;
      typed.addEventListener('input', () => { go.disabled = typed.value.trim() !== node.label; });
      buttons[0].addEventListener('click', close);
      go.addEventListener('click', async () => {
        try { await api('POST', `/v1/nodes/${node.id}/burn`); close(); reload(); } catch (error) { refused(error); }
      });
    });
  }

  // ── the command bar ─────────────────────────────────────────────────────

  function palette() {
    const items = [
      ...[['dashboard', t('ui-nav-dashboard')], ['nodes', t('ui-nav-nodes')], ['users', t('ui-nav-users')], ['log', t('ui-nav-log')]]
        .filter(([name]) => allowed(name))
        .map(([name, label]) => ({ label, hint: t('ui-palette-screen'), go: () => { location.hash = `#/${name}`; } })),
      ...state.known.nodes.map((node) => ({ label: node.label, hint: kindOf(node), go: () => { location.hash = '#/nodes'; } })),
      ...state.known.clients.map((client) => ({ label: client.label, hint: t('ui-nav-users'), go: () => { location.hash = '#/users'; } })),
    ];
    let shown = items.slice(0, 12);
    let picked = 0;
    const line = h('input', { class: 'inp', type: 'text', placeholder: t('ui-command-hint') });
    const list = h('div', { class: 'res' });
    const box = h('div', { class: 'dlg' },
      h('div', { class: 'dh' }, h('h2', null, t('ui-command-title')), h('span', { class: 'sp' }), h('span', { class: 'esc' }, h('span', { class: 'kbd' }, 'Esc'))),
      h('div', { class: 'db' }, line, list));
    const root = $('#modal-root');
    function close() { root.replaceChildren(); document.removeEventListener('keydown', onKey); }
    function onKey(event) { if (event.key === 'Escape') close(); }
    function draw() {
      const needle = line.value.trim().toLowerCase();
      shown = (needle ? items.filter((item) => item.label.toLowerCase().includes(needle)) : items).slice(0, 12);
      picked = Math.min(picked, Math.max(0, shown.length - 1));
      list.replaceChildren(...shown.map((item, index) => h('div', {
        class: `row ${index === picked ? 'on' : ''}`,
        on: { click: () => { close(); item.go(); } },
      }, h('span', { class: 'lbl' }, item.label), h('span', { class: 'hint' }, item.hint))));
    }
    line.addEventListener('input', () => { picked = 0; draw(); });
    line.addEventListener('keydown', (event) => {
      if (event.key === 'ArrowDown') { picked = Math.min(picked + 1, shown.length - 1); draw(); event.preventDefault(); }
      if (event.key === 'ArrowUp') { picked = Math.max(picked - 1, 0); draw(); event.preventDefault(); }
      if (event.key === 'Enter' && shown[picked]) { const go = shown[picked].go; close(); go(); }
    });
    root.replaceChildren(h('div', { class: 'scrim', on: { click: close } }), h('div', { class: 'dlgwrap' }, box));
    document.addEventListener('keydown', onKey);
    draw();
    line.focus();
  }

  // ── routing ─────────────────────────────────────────────────────────────

  const views = { dashboard, nodes, users, log };

  function allowed(name) {
    if (name === 'nodes') return state.me && state.me.role !== 'reseller';
    if (name === 'log') return state.me && state.me.role === 'superadmin';
    return true;
  }

  async function show(name, quiet) {
    const root = screen(name);
    $('#screen').className = `scr-${name}`;
    try {
      await views[name](root);
      applyStaticText(root);
      $('#screen').replaceChildren(root);
    } catch (error) {
      if (!quiet) $('#screen').replaceChildren(h('div', { class: 'content' }, h('div', { class: 'm3' }, error.message)));
      refused(error);
    }
  }

  async function route() {
    clearInterval(state.timer);
    if (!state.me) {
      $('#screen').className = state.setupNeeded ? 'scr-first-run' : 'scr-login';
      $('#screen').replaceChildren(state.setupNeeded ? setupView() : loginView());
      return;
    }
    let name = (location.hash.replace(/^#\/?/, '') || 'dashboard').split('/')[0];
    if (!views[name] || !allowed(name)) name = 'dashboard';
    $$('.rail .nav a').forEach((link) => link.classList.toggle('on', link.dataset.view === name));
    await show(name, false);
    if (name === 'dashboard' || name === 'nodes') {
      state.timer = setInterval(() => {
        if (document.visibilityState === 'visible' && !$('#modal-root').childElementCount) show(name, true);
      }, REFRESH_MS);
    }
  }

  async function boot() {
    applyTheme();
    applyLang();
    try { await loadMessages(); } catch { /* the page still stands without them */ }
    $('#lang').addEventListener('click', async (event) => {
      const button = event.target.closest('[data-lang]');
      if (!button || button.dataset.lang === state.lang) return;
      state.lang = button.dataset.lang;
      remember('localStorage', 'ap-lang', state.lang);
      applyLang();
      await loadMessages();
      showRail();
      route();
    });
    $('#theme').addEventListener('click', (event) => {
      const button = event.target.closest('[data-theme]');
      if (!button) return;
      state.theme = button.dataset.theme;
      remember('localStorage', 'ap-theme', state.theme);
      applyTheme();
    });
    $('#sign-out').addEventListener('click', signOut);
    $('#cmdbar').addEventListener('click', palette);
    document.addEventListener('keydown', (event) => {
      if (!state.me) return;
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); palette(); return; }
      if (event.target.closest('input, select, textarea') || $('#modal-root').childElementCount) return;
      const screens = ['dashboard', 'nodes', 'users', 'log'];
      const index = Number(event.key) - 1;
      if (index >= 0 && index < screens.length && allowed(screens[index])) location.hash = `#/${screens[index]}`;
      // The tile on the nodes screen carries this key; it works from the
      // screen, which is where the tile is.
      if (event.key.toLowerCase() === 'n' && (event.ctrlKey || event.metaKey)
        && state.me.role === 'superadmin' && location.hash.startsWith('#/nodes')) {
        event.preventDefault();
        newNode();
      }
    });
    window.addEventListener('hashchange', route);
    if (state.token) {
      try { state.me = await api('GET', '/v1/session'); } catch { state.me = null; }
    }
    try {
      const panel = await api('GET', '/v1/setup');
      state.setupNeeded = panel.needed === true;
      state.secondFactor = panel.second_factor !== false;
      state.version = panel.version || '';
    } catch { state.setupNeeded = false; }
    showRail();
    route();
  }

  boot();
})();
