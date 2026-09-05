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
  // The stand drew one series per range and gave each its own class; the
  // panel keeps the one the range asks for, dressing and all.
  const SERIES = ['d', 'w', 'm', 'y'];

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
    channel: '',
    uptime: null,
    // Which page of the journal is on screen, and what it is filtered to.
    journal: { group: 'all', day: false, node: null, offset: 0, size: 12 },
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
  // A screen is more than one element — what was drawn, and the bar of
  // figures under it — so the whole of the template comes across.
  const screen = (name) => $(`#screen-${name}`).content.cloneNode(true);

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

  /// Fills the bar along the foot of a screen: one figure per drawn slot,
  /// each keeping the shape it was drawn in.
  function statusbar(root, figures) {
    const bar = $('.statusbar', root);
    if (!bar) return;
    const slots = $$('.sb', bar);
    figures.forEach((figure, index) => {
      const slot = slots[index];
      if (!slot || !figure) return;
      const [value, label] = figure;
      const mono = $('.mono', slot) || h('span', { class: 'mono' });
      mono.textContent = value;
      // Drawn either as a figure and then a word, or a word and then a
      // figure. Which it is shows in what comes first in the drawing.
      const ahead = slot.firstChild && slot.firstChild.nodeType === 3
        && slot.firstChild.textContent.trim();
      slot.replaceChildren(...(ahead ? [`${label} `, mono] : [mono, ` ${label}`]));
    });
    slots.slice(figures.length).forEach((spare) => spare.remove());
  }

  /// The noun for a count, from the forms the catalogue keeps apart.
  ///
  /// Russian has three: one node, two nodes, five nodes. English has two and
  /// says so by giving the same word twice. Fluent would choose for us, but
  /// the browser has none, so the choosing is here and the forms are plain
  /// text in the catalogue.
  function counted(key, count) {
    const forms = String(t(key)).split('|');
    if (forms.length < 2) return forms[0] || '';
    if (state.lang !== 'ru') return forms[Math.abs(count) === 1 ? 0 : 1];
    const ten = Math.abs(count) % 10;
    const hundred = Math.abs(count) % 100;
    if (ten === 1 && hundred !== 11) return forms[0];
    if (ten >= 2 && ten <= 4 && (hundred < 12 || hundred > 14)) return forms[1];
    return forms[2] || forms[1];
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

  const clock = (iso, seconds) => (iso ? new Intl.DateTimeFormat(locale(), {
    hour: '2-digit', minute: '2-digit', second: seconds ? '2-digit' : undefined, timeZone: 'UTC',
  }).format(new Date(iso)) : '—');
  // Every time in this interface is written in UTC, so that is what it says.
  const timezone = () => 'UTC';
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

  /// The address an agent dials, as an operator would type it.
  ///
  /// The panel gives a bare `:port` when its channel listens on no particular
  /// address; the host is then the one this page was opened on, which is the
  /// right answer for a panel and a channel on one machine (0065).
  function channelAddress() {
    const given = state.channel || '';
    if (!given) return '—';
    return given.startsWith(':') ? `${location.hostname}${given}` : given;
  }

  function setTheme(name) {
    state.theme = name;
    remember('localStorage', 'ap-theme', name);
    applyTheme();
  }

  async function setLang(code) {
    state.lang = code;
    remember('localStorage', 'ap-lang', code);
    await loadMessages();
    showRail();
    route();
  }

  function showRail() {
    $('.rail').hidden = !state.me;
    $('.barstrip').hidden = !state.me;
    if (!state.me) return;
    put(document, '#channel-address', channelAddress());
    put(document, '#panel-address', location.host);
    // Who is signed in and which build is answering. The rail was drawn with
    // no room for either, so the row they belong to says them on hover.
    const row = $('#panel-address').closest('.frow');
    if (row) {
      row.title = [state.me.login, t(`ui-role-${state.me.role}`), state.version].filter(Boolean).join(' · ');
    }
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
    const shown = SERIES[Math.max(0, RANGES.findIndex(([, days]) => days === state.range))] || SERIES[0];
    /// Keeps the drawn figure for this range, fills it, and drops the rest.
    const only = (box, value) => {
      if (!box) return null;
      const all = $$('b', box);
      const kept = all.find((one) => one.classList.contains(shown)) || all[0];
      all.forEach((one) => { if (one !== kept) one.remove(); });
      if (kept) kept.textContent = value;
      return kept;
    };
    /// The same choice among elements that are the series themselves.
    const pick = (all) => all.find((one) => one.classList.contains(shown)) || all[0];

    const [total, unit] = scale(drawn.total);
    only($('.big .v', traffic), total);
    only($('.big .u', traffic), unit);
    const delta = $('.big .delta', traffic);
    if (change == null) {
      delta.remove();
    } else {
      only(delta, t(change < 0 ? 'ui-dash-down' : 'ui-dash-up', { percent: Math.abs(change) }));
    }

    const svg = $('.chart svg', traffic);
    const view = svg.getAttribute('viewBox').split(' ').map(Number);
    const { line, x, y } = curve(drawn.points, view[2], 8, 162);
    // The stand drew a curve per range; the panel draws the one it was asked
    // for, and the spares go.
    const fills = $$('.fill', svg);
    const lines = $$('.line', svg);
    const fill = pick(fills);
    const stroke = pick(lines);
    fills.forEach((path) => { if (path !== fill) path.remove(); });
    lines.forEach((path) => { if (path !== stroke) path.remove(); });
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
    const vlines = $$('.vline', svg);
    const vline = pick(vlines);
    vlines.forEach((one) => { if (one !== vline) one.remove(); });
    vline.setAttribute('x1', peakX);
    vline.setAttribute('x2', peakX);
    vline.setAttribute('y1', peakY);
    const marks = $$('.pk', svg);
    const mark = pick(marks);
    marks.forEach((one) => { if (one !== mark) one.remove(); });
    mark.setAttribute('cx', peakX);
    mark.setAttribute('cy', peakY);
    const tips = $$('.tip', traffic);
    const tip = pick(tips);
    tips.forEach((one) => { if (one !== tip) one.remove(); });
    tip.style.left = `${Math.min(88, Math.max(12, (drawn.peak / Math.max(1, drawn.points.length - 1)) * 100))}%`;
    put(tip, '.d', day(top.day));
    put(tip, '.n', bytes(top.in + top.out));
    put(tip, '.s', `${t('ui-dash-received')} ${bytes(top.in)} · ${t('ui-dash-sent')} ${bytes(top.out)}`);
    const axis = $$('.xax > span', traffic);
    only(axis[0], day(drawn.points[0].day));
    only(axis[1], day(drawn.points[drawn.points.length - 1].day));
    const foot = $$('.tfoot > span', traffic);
    const figure = (span, label, value) => {
      const kept = only(span, value);
      // Everything but the figure goes, the word included: the word may have
      // been wrapped for translation and is no longer a bare piece of text.
      [...span.childNodes].filter((node) => node !== kept).forEach((node) => node.remove());
      if (kept) span.insertBefore(document.createTextNode(`${label} `), kept);
    };
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

    // ── the foot, as drawn: what there is, and what is answering ──
    const connections = live.reduce((sum, node) => sum
      + (node.machine && node.machine.connections != null ? Number(node.machine.connections) : 0), 0);
    statusbar(root, [
      [num(live.length), counted('ui-count-nodes', live.length)],
      [num(accesses.length), counted('ui-count-accesses', accesses.length)],
      [num(connections), counted('ui-count-connections', connections)],
      [state.version ? `v${state.version}` : '—', t('ui-rail-panel')],
      [state.uptime == null ? '—' : uptime(state.uptime), t('ui-status-running')],
    ]);

    // ── events ──
    if (!readsAudit) events.remove();
    else {
      const audit = (await api('GET', '/v1/audit?limit=6')).entries || [];
      put(events, '.ch h2', t('ui-dash-events'));
      const all = $('.ch .lnk', events);
      if (all) { all.textContent = t('ui-dash-all-log'); all.setAttribute('href', '#/log'); }
      repeat($('.cb', events), audit, (row, entry) => {
        put(row, '.t', clock(entry.at));
        dot($('.sd', row), entry.action.includes('burn') || entry.action.includes('revoke') ? 'bad' : 'ok');
        const words = [...row.children].find((child) => !child.className);
        if (words) words.textContent = `${eventWords(entry.action)}${entry.target ? ` · ${entry.target}` : ''}`;
        put(row, '.who', entry.actor_id ? entry.actor_id.slice(0, 8) : t('ui-none'));
      });
    }

  }

  // ── nodes, users, log: the stand's own markup, filled ───────────────────

  async function nodes(root) {
    const [list, accesses, traffic] = await Promise.all([
      api('GET', '/v1/nodes'),
      api('GET', `/v1/accesses?limit=${PAGE}`),
      api('GET', `/v1/traffic?days=${state.range}`),
    ]);
    state.known.nodes = list;
    const live = list.filter((node) => node.state !== 'burned');
    const shown = live.filter((node) => state.filter === 'all'
      || (state.filter === 'attention' ? standing(node) !== 'ok' : node.kind === state.filter));
    // The order the note on the bar promises: whatever wants doing something
    // about comes first, and the rest keep to their names.
    const RANK = { bad: 0, none: 1, warn: 2, ok: 3 };
    shown.sort((one, other) => (RANK[standing(one)] - RANK[standing(other)])
      || one.label.localeCompare(other.label));
    const held = new Map();
    for (const access of accesses) held.set(access.node_id, (held.get(access.node_id) || 0) + 1);

    put(root, '.phead h1', t('ui-nav-nodes'));
    const well = live.filter((node) => standing(node) === 'ok').length;
    const meta = $('.phead .pmeta', root);
    if (meta) {
      // Two lines, as drawn: how the fleet is answering, and what it carried
      // over the range, in the figure the drawing keeps set apart.
      const carried = $('.mono', meta) || h('span', { class: 'mono' });
      carried.textContent = bytes(series(traffic, state.range).total);
      meta.replaceChildren(
        t('ui-nodes-well', { well: num(well), total: num(live.length) }),
        ' · ', t('ui-nodes-wanting', { count: num(live.length - well) }), h('br'),
        `${t('ui-nodes-carried', { days: num(state.range) })} `, carried);
    }

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
      const divider = $('.fsep', bar);
      const note = $('.right', bar);
      const chipFor = ([value, label, count]) => {
        const chip = shape.cloneNode(true);
        const badge = $('.n', chip);
        chip.replaceChildren(label, badge || '');
        if (badge) badge.textContent = num(count);
        chip.classList.toggle('on', state.filter === value);
        chip.removeAttribute('for');
        chip.addEventListener('click', () => { state.filter = value; route(); });
        return chip;
      };
      // As drawn: the kinds, a divider, then the filter that is not a kind,
      // and on the right the order the cards are in.
      const kindChips = filters.filter(([value]) => value !== 'attention').map(chipFor);
      const attention = filters.filter(([value]) => value === 'attention').map(chipFor);
      if (note) note.textContent = t('ui-nodes-order');
      bar.replaceChildren(...kindChips, ...(divider ? [divider] : []), ...attention,
        ...(note ? [note] : []));
    }

    const masked = live.filter((node) => node.kind === 'hidden').length;
    statusbar(root, [
      [num(live.length), counted('ui-count-nodes', live.length)],
      [num(masked), t('ui-status-masked')],
      [num(live.length - well), t('ui-status-wanting')],
      [num(accesses.length), counted('ui-count-accesses', accesses.length)],
      [`${Math.round(REFRESH_MS / 1000)} ${t('ui-unit-seconds')}`, t('ui-status-checked-every')],
      [clock(new Date().toISOString()), t('ui-status-refreshed')],
    ]);

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
    // Two lines, as drawn: how many of each thing there is, and what they
    // carried over the range, in the figure the drawing sets apart.
    const meta = $('.phead .pmeta', root);
    if (meta) {
      const total = [...accesses, ...publics]
        .reduce((sum, access) => sum + Number(access.carried_bytes || 0), 0);
      const carried = $('.mono', meta) || h('span', { class: 'mono' });
      carried.textContent = bytes(total);
      meta.replaceChildren(
        `${num(clients.length)} ${counted('ui-count-clients', clients.length)} · `,
        `${num(publics.length)} ${counted('ui-count-links', publics.length)}`, h('br'),
        `${t('ui-nodes-carried', { days: num(30) })} `, carried);
    }

    // The stand draws two tables here: what the users hold, and the links
    // that belong to nobody.
    const table = $('.t-acc', root);
    const links = $('.t-link', root);
    const head = $$('.th > div', table);
    [t('ui-col-user'), t('ui-col-node'), t('ui-col-granted'), t('ui-col-carried'),
      t('ui-col-last-active'), t('ui-col-connection')]
      .forEach((label, index) => { if (head[index]) head[index].textContent = label; });
    if (links) {
      const linkHead = $$('.th > div', links);
      [t('ui-col-link-name'), t('ui-col-node'), t('ui-col-issued'), t('ui-col-carried'), t('ui-col-connection')]
        .forEach((label, index) => { if (linkHead[index]) linkHead[index].textContent = label; });
    }
    const heading = $('.shead h2', root);
    if (heading) heading.textContent = t('ui-users-public');
    const idle = clients.filter((client) => !accesses.some((one) => one.client_id === client.id)).length;
    statusbar(root, [
      [num(clients.length), counted('ui-count-clients', clients.length)],
      [num(accesses.length), counted('ui-count-accesses', accesses.length)],
      [num(publics.length), counted('ui-count-links', publics.length)],
      [num(idle), counted('ui-count-without', idle)],
    ]);

    const byClient = new Map(clients.map((client) => [client.id, []]));
    for (const access of accesses) byClient.get(access.client_id)?.push(access);
    const rows = [];
    for (const client of clients) {
      const own = byClient.get(client.id) || [];
      if (!own.length) rows.push({ client, access: null, first: true });
      own.forEach((access, index) => rows.push({ client, access, first: index === 0 }));
    }


    const shape = $('.tr', table);
    const header = $('.th', table);
    table.replaceChildren(header, ...rows.map(({ client, access, first }) => {
      const row = shape.cloneNode(true);
      const node = access ? list.find((candidate) => candidate.id === access.node_id) : null;
      const who = $('.who', row);
      who.className = `who ${first ? '' : 'same'}`;
      who.replaceChildren(client
        ? h('button', {
          type: 'button',
          class: 'lnk',
          on: { click: () => clientCard(client, byClient.get(client.id) || [], list) },
        }, first ? client.label : '')
        : h('span', null, access.name || '—'));
      const where = $('.node', row);
      where.replaceChildren(h('span', { class: `sd ${node && standing(node) === 'ok' ? '' : 'w'}` }), node ? node.label : '—');
      const cells = [...row.children];
      // As drawn: when it was granted, what it carried over the range, and
      // when it was last busy. A row with nothing behind it says so and is
      // muted, which is how the stand drew that case too.
      if (cells[2]) {
        cells[2].textContent = access ? shortDate(access.created_at) : t('ui-empty');
        cells[2].className = access ? 'm2' : 'm3';
      }
      const carried = access ? Number(access.carried_bytes || 0) : null;
      if (cells[3]) {
        cells[3].textContent = carried == null ? t('ui-empty') : (carried ? bytes(carried) : '0');
        cells[3].className = carried ? 'r mono' : 'r mono m3';
      }
      if (cells[4]) {
        const sick = node && standing(node) !== 'ok';
        if (!access) {
          cells[4].textContent = t('ui-empty');
          cells[4].className = 'r m3';
        } else if (sick) {
          cells[4].textContent = trouble(node);
          cells[4].className = 'r warnline';
        } else if (access.last_active_on) {
          cells[4].textContent = shortDate(`${access.last_active_on}T00:00:00Z`);
          cells[4].className = 'r mono m2';
        } else {
          cells[4].textContent = t('ui-never-connected');
          cells[4].className = 'r m3';
        }
      }
      // The stand shows the link in this cell. A link is a secret, and the
      // panel hands one out only through the endpoint that writes to the
      // audit log — so the cell shows that a link exists and the button
      // beside it is what asks for it.
      const link = $('.lk', row);
      if (link) {
        const value = $('.v', link);
        const ask = $('.cp', link);
        if (!access) {
          // The stand drew this row with one button in it: the way to give
          // this person something to connect with.
          link.replaceChildren(h('button', {
            type: 'button',
            class: 'btn sm key',
            on: { click: () => newAccess(clients, list, false, client) },
          }, t('ui-users-new-access')));
        } else if (access.state === 'revoked') {
          link.replaceChildren(h('span', { class: 'v m3' }, t('ui-access-state-revoked')));
        } else {
          // The stand drew the link itself and a small button beside it. A
          // link is a secret and is handed out only through the endpoint that
          // writes to the journal, so the text says the link exists and the
          // drawn button is what asks for it.
          if (value) value.textContent = t('ui-link-hidden');
          if (ask) {
            ask.setAttribute('role', 'button');
            ask.setAttribute('tabindex', '0');
            ask.title = t('ui-access-link');
            ask.onclick = () => linkFor(access, node);
          }
        }
      }
      return row;
    }));

    // The links that belong to nobody, in their own table.
    if (links) {
      const shapeLink = $('.tr', links);
      const headRow = $('.th', links);
      links.replaceChildren(headRow, ...publics.map((access) => {
        const row = shapeLink.cloneNode(true);
        const node = list.find((candidate) => candidate.id === access.node_id);
        const cells = [...row.children];
        cells[0].replaceChildren(access.name || access.id.slice(0, 8));
        $('.node', row).replaceChildren(
          h('span', { class: `sd ${node && standing(node) === 'ok' ? '' : 'w'}` }), node ? node.label : '—');
        if (cells[2]) cells[2].textContent = shortDate(access.created_at);
        const carried = Number(access.carried_bytes || 0);
        if (cells[3]) {
          cells[3].textContent = carried ? bytes(carried) : '0';
          cells[3].className = carried ? 'r mono' : 'r mono m3';
        }
        const link = $('.lk', row);
        if (link) {
          const value = $('.v', link);
          if (value) value.textContent = t('ui-link-hidden');
          const ask = $('.cp', link);
          if (ask) {
            ask.setAttribute('role', 'button');
            ask.setAttribute('tabindex', '0');
            ask.title = t('ui-access-link');
            ask.onclick = () => linkFor(access, node);
          }
        }
        return row;
      }));
      if (!publics.length) links.replaceChildren(headRow, h('div', { class: 'tr m3' }, t('ui-empty')));
    }
  }

  // ── the journal ─────────────────────────────────────────────────────────

  /// The groups the filter bar was drawn with, and what falls in each.
  const JOURNAL = [
    ['all', 'ui-log-all', []],
    ['nodes', 'ui-nav-nodes', ['node.']],
    ['accesses', 'ui-log-accesses', ['access.', 'client.']],
    ['sessions', 'ui-log-sessions', ['session.']],
    ['removals', 'ui-log-removals', ['node.burned', 'access.state', 'client.state']],
    ['faults', 'ui-log-faults', ['fault.']],
  ];

  /// Whether a record falls in a group. An empty group takes everything.
  const inGroup = (action, starts) => !starts.length || starts.some((one) => action.startsWith(one));

  /// What an entry is, in words. An action the catalogue has no phrase for is
  /// shown as it is recorded rather than as a guess at what it means.
  function eventWords(action) {
    const key = `ui-event-${action.replace(/\./g, '-')}`;
    const said = t(key);
    return said === key ? action : said;
  }

  /// How an entry should read: what went wrong is red, what was taken away is
  /// amber, what was made is green, and the rest is plain.
  function eventTone(action) {
    if (action.includes('fail') || action.includes('refus')) return 'bad';
    if (action.endsWith('.burned') || action.endsWith('.state')) return 'warn';
    if (action.endsWith('.created') || action.endsWith('.opened')) return 'ok';
    return '';
  }

  async function log(root) {
    const page = state.journal;
    const group = JOURNAL.find(([name]) => name === page.group) || JOURNAL[0];
    const query = [`limit=${page.size}`, `offset=${page.offset}`];
    if (page.day) query.push('days=1');
    // The filter goes with the request: narrowing what has already arrived
    // would leave the count beside the bar describing something else.
    if (group[2].length) query.push(`prefix=${encodeURIComponent(group[2].join(','))}`);
    const [answer, summary] = await Promise.all([
      api('GET', `/v1/audit?${query.join('&')}`),
      api('GET', `/v1/audit/summary?days=${page.day ? 1 : 3650}`),
    ]);
    const all = answer.entries || [];
    const counts = summary.by_action || {};
    // The bar counts what the journal holds; the table shows what is asked
    // for. Filtering by group happens here because the grouping is the
    // screen's, not the database's (0067).
    const entries = page.node
      ? all.filter((entry) => (entry.target || '').includes(page.node))
      : all;

    put(root, '.phead h1', t('ui-nav-log'));
    const faults = Object.entries(counts)
      .filter(([action]) => inGroup(action, JOURNAL[5][2]))
      .reduce((sum, [, many]) => sum + Number(many), 0);
    const meta = $('.phead .pmeta', root);
    if (meta) {
      const many = h('span', { class: 'mono' }, num(summary.total || 0));
      const bad = h('span', { class: 'mono' }, num(faults));
      const zone = h('span', { class: 'mono' }, timezone());
      meta.replaceChildren(`${t('ui-log-in-day')} `, many, ` · ${t('ui-log-faults-of')} `, bad,
        h('br'), `${t('ui-log-timezone')} `, zone);
    }

    // ── the bar, as drawn: the groups, a divider, the window and the node ──
    const bar = $('.fbar', root);
    if (bar) {
      const shape = $('.chip', bar);
      const divider = $('.fsep', bar);
      const live = $('.live', bar);
      const chip = (label, count, on, go) => {
        const made = shape.cloneNode(true);
        const badge = $('.n', made);
        made.replaceChildren(label, count == null ? '' : (badge || h('span', { class: 'n' })));
        const shownBadge = $('.n', made);
        if (shownBadge && count != null) shownBadge.textContent = num(count);
        made.classList.toggle('on', on);
        made.removeAttribute('for');
        made.addEventListener('click', go);
        return made;
      };
      const groups = JOURNAL.map(([name, key, starts]) => chip(
        t(key),
        Object.entries(counts).filter(([action]) => inGroup(action, starts))
          .reduce((sum, [, many]) => sum + Number(many), 0),
        page.group === name,
        () => { state.journal = { ...page, group: name, offset: 0 }; route(); },
      ));
      const window_ = chip(page.day ? t('ui-log-day') : t('ui-log-all-time'), null, page.day,
        () => { state.journal = { ...page, day: !page.day, offset: 0 }; route(); });
      const names = [null, ...state.known.nodes.map((node) => node.label)];
      const nodeChip = chip(
        page.node ? `${t('ui-col-node')}: ${page.node}` : t('ui-log-any-node'), null, !!page.node,
        () => {
          const at = names.indexOf(page.node || null);
          state.journal = { ...page, node: names[(at + 1) % names.length], offset: 0 };
          route();
        },
      );
      bar.replaceChildren(...groups, ...(divider ? [divider] : []), window_, nodeChip,
        ...(live ? [live] : []));
      if (live) {
        const word = [...live.childNodes].find((node) => node.nodeType === 3);
        if (word) word.textContent = t('ui-log-live');
      }
    }

    // ── the table, in the drawn columns ───────────────────────────────────
    const table = $('.tbl', root);
    const head = $$('.th > div', table);
    [t('ui-col-time'), t('ui-col-node'), t('ui-col-event'), t('ui-col-object'),
      t('ui-col-detail'), t('ui-col-source')]
      .forEach((label, index) => {
        if (!head[index]) return;
        const arrow = $('svg', head[index]);
        head[index].replaceChildren(label, arrow || '');
      });
    const shape = [...table.children].find((child) => child.classList.contains('tr'));
    const opened = [...table.children].find((child) => child.classList.contains('exp'));
    const header = $('.th', table);
    const rows = [];
    for (const entry of entries) {
      const row = shape.cloneNode(true);
      // The stand marks the newest record as just-arrived and lets the rest
      // come in behind it, one after another. Keeping those classes keeps the
      // motion that was drawn.
      const at = rows.length;
      row.className = at === 0 ? 'tr fresh' : 'tr streamed';
      row.style.setProperty('--d', `${Math.min(at, 12) * 40}ms`);
      row.removeAttribute('for');
      const cells = [...row.children];
      const facts = entry.details && typeof entry.details === 'object' ? entry.details : {};
      if (cells[0]) cells[0].textContent = clock(entry.at, true);
      if (cells[1]) cells[1].textContent = facts.node || facts.label || (entry.action.startsWith('node.') ? entry.target : '') || '—';
      if (cells[2]) {
        cells[2].textContent = eventWords(entry.action);
        cells[2].className = `ev ${eventTone(entry.action)}`.trim();
      }
      if (cells[3]) cells[3].textContent = entry.target || '—';
      if (cells[4]) {
        const said = Object.entries(facts)
          .filter(([, value]) => value != null && value !== '')
          .map(([key, value]) => `${key}: ${value}`).join(' · ');
        cells[4].textContent = said || '—';
      }
      if (cells[5]) cells[5].textContent = entry.actor_id ? t('ui-log-by-operator') : t('ui-log-by-panel');
      rows.push(row);
      if (opened) {
        row.style.cursor = 'pointer';
        row.addEventListener('click', () => {
          const already = row.nextElementSibling;
          if (already && already.classList.contains('exp')) { already.remove(); return; }
          $$('.exp', table).forEach((one) => one.remove());
          row.after(expanded(opened, entry, facts));
        });
      }
    }
    table.replaceChildren(header, ...rows);
    if (!rows.length) table.append(h('div', { class: 'tr m3' }, t('ui-empty')));

    // ── the footer, as drawn ──────────────────────────────────────────────
    const pager = $('.pgbar', root);
    if (pager) {
      const buttons = $$('.pg', pager);
      const [earlier, later, save] = [buttons[0], buttons[1], buttons[2]];
      const first = answer.total ? page.offset + 1 : 0;
      const last = Math.min(page.offset + all.length, answer.total || 0);
      const step = (by) => { state.journal = { ...page, offset: Math.max(0, page.offset + by) }; route(); };
      if (earlier) {
        earlier.disabled = page.offset + all.length >= (answer.total || 0);
        earlier.onclick = () => step(page.size);
      }
      if (later) {
        later.disabled = page.offset === 0;
        later.onclick = () => step(-page.size);
      }
      const said = $$('span', pager).find((span) => !span.classList.contains('push') && $('.mono', span));
      if (said) {
        said.replaceChildren(`${t('ui-log-records')} `, h('span', { class: 'mono' }, `${num(first)}–${num(last)}`),
          ` ${t('ui-log-of')} `, h('span', { class: 'mono' }, num(answer.total || 0)));
      }
      const note = $('.push', pager);
      if (note) note.textContent = t('ui-log-export-note');
      if (save) {
        const arrow = $('svg', save);
        save.replaceChildren(arrow || '', ` ${t('ui-log-export')}`);
        save.onclick = () => exportJournal(entries);
      }
    }

    statusbar(root, [
      [num(summary.total || 0), t('ui-log-in-day-foot')],
      [num(faults), counted('ui-count-faults', faults)],
      [num(Object.entries(counts).filter(([action]) => action.startsWith('session.')
        || action.endsWith('.created')).reduce((sum, [, many]) => sum + Number(many), 0)),
      t('ui-log-operator-actions')],
      [page.node || t('ui-log-any-node'), t('ui-log-scope')],
      [num(entries.length), counted('ui-count-records', entries.length)],
    ]);
  }

  /// The drawn block that opens under a row, filled with what the entry holds.
  function expanded(shape, entry, facts) {
    const box = shape.cloneNode(true);
    box.className = 'exp';
    put(box, '.et', `${eventWords(entry.action)} — ${entry.target || t('ui-none')}`);
    const summary = $('.ex', box);
    if (summary) summary.textContent = t('ui-log-recorded-at', { at: stamp(entry.at) });
    const pairs = (list, into) => {
      if (!into) return;
      const shapeRow = into.firstElementChild;
      into.replaceChildren(...list.map(([key, value, muted]) => {
        const row = shapeRow ? shapeRow.cloneNode(true) : h('div', null, h('dt'), h('dd'));
        put(row, 'dt', key);
        const said = $('dd', row);
        if (said) {
          said.textContent = value;
          said.className = muted ? 'm3' : (said.classList.contains('mono') ? 'mono' : '');
        }
        return row;
      }));
    };
    const [left, right] = $$('.dl', box);
    pairs(Object.entries(facts).map(([key, value]) => [key, String(value), false]).concat(
      [[t('ui-col-action'), entry.action, false]],
    ), left);
    pairs([
      [t('ui-col-time'), stamp(entry.at), false],
      [t('ui-col-source'), entry.actor_id ? t('ui-log-by-operator') : t('ui-log-by-panel'), false],
      [t('ui-col-object'), entry.target || t('ui-none'), !entry.target],
      ['id', entry.id, false],
    ], right);
    const note = $('.pnote', box);
    if (note) note.textContent = t('ui-log-keeps-note');
    const acts = $$('.act', box);
    acts.forEach((act) => act.remove());
    return box;
  }

  /// Hands the operator the rows on screen as a comma-separated file.
  function exportJournal(entries) {
    const cell = (value) => `"${String(value == null ? '' : value).replace(/"/g, '""')}"`;
    const lines = [['at', 'action', 'target', 'actor', 'details'].join(',')];
    for (const entry of entries) {
      lines.push([entry.at, entry.action, entry.target || '', entry.actor_id || '',
        JSON.stringify(entry.details || {})].map(cell).join(','));
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = h('a', { href: url, download: `anyproxy-journal-${new Date().toISOString().slice(0, 10)}.csv` });
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
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

  function newAccess(clients, nodes_, isPublic, forClient) {
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
      // Opened from a person's own row, it opens on that person.
      if (forClient) client.value = forClient.id;
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

  function clientCard(client, held, nodes_) {
    dialog('user', (box, close) => {
      const cards = $$('.dlg', box.parentElement);
      cards.slice(1).forEach((card) => card.remove());
      put(box, '.dh h2', client.label);
      put(box, '.dh .note', t(`ui-client-state-${client.state}`));
      const nodeOf = (access) => (nodes_ || []).find((one) => one.id === access.node_id);
      $('.db', box).replaceChildren(
        h('div', { class: 'pair' },
          h('span', { class: 'k' }, t('ui-col-quota')), h('span', { class: 'v' }, quota(client.quota_bytes)),
          h('span', { class: 'k' }, t('ui-col-expires')), h('span', { class: 'v' }, date(client.expires_at)),
          h('span', { class: 'k' }, t('ui-node-created')), h('span', { class: 'v' }, date(client.created_at))),
        // What this person holds, and the way to take one back. The users
        // screen was drawn without such a control; this is where the access
        // being turned off can be named.
        ...(held && held.length ? [h('div', { class: 'lst' }, ...held.map((access) => {
          const node = nodeOf(access);
          return h('div', { class: 'lk' },
            h('span', { class: 'v' }, `${node ? node.label : t('ui-none')} · ${t(`ui-method-${access.method}`)}`),
            h('button', {
              type: 'button',
              class: 'btn',
              on: {
                click: async () => {
                  await setAccess(access, access.state === 'active' ? 'disabled' : 'active');
                  close();
                },
              },
            }, t(access.state === 'active' ? 'ui-access-disable' : 'ui-access-enable')));
        }))] : []));
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
    const command = `anyproxy-agent enroll --panel ${channelAddress()} --code ${issued.code} --fingerprint ${issued.panel_fingerprint}`;
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
      // The stand drew no way out and no language switch on the rail, and a
      // panel needs both: the command bar it did draw is where they live.
      { label: t('ui-users-new-client'), hint: t('ui-palette-command'), go: newClient },
      ...(state.known.nodes.length ? [
        { label: t('ui-users-new-access'),
          hint: t('ui-palette-command'),
          go: () => newAccess(state.known.clients, state.known.nodes, false) },
        { label: t('ui-users-new-public'),
          hint: t('ui-palette-command'),
          go: () => newAccess(state.known.clients, state.known.nodes, true) },
      ] : []),
      ...(state.me.role === 'superadmin'
        ? [{ label: t('ui-nodes-new'), hint: t('ui-palette-command'), go: newNode }] : []),
      { label: t('ui-sign-out'), hint: t('ui-palette-command'), go: signOut },
      ...['ru', 'en'].filter((code) => code !== state.lang).map((code) => ({
        label: t('ui-palette-language', { name: code.toUpperCase() }),
        hint: t('ui-palette-command'),
        go: () => setLang(code),
      })),
      ...['dark', 'light'].filter((name) => name !== state.theme).map((name) => ({
        label: t(`ui-palette-theme-${name}`),
        hint: t('ui-palette-command'),
        go: () => setTheme(name),
      })),
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

  /// Dresses the whole page as the named screen was drawn.
  ///
  /// The rail and the strip were drawn differently on each of the stand's
  /// screens, so the scope goes on the root, above them, and not on the box
  /// the screen is rendered into.
  function wear(name) {
    document.querySelector('.root').className = `root scr-${name}`;
  }

  /// Which screen was asked for last. A screen that takes a while to gather
  /// its figures must not land on top of one the operator has since moved to.
  let asked = 0;

  async function show(name, quiet) {
    const target = $('#screen');
    const ticket = (asked += 1);
    // The screen it is about to be is worn straight away, and with it a word:
    // the one before it, wearing the wrong sheet, is what a wait used to look
    // like.
    if (!quiet) {
      wear(name);
      target.replaceChildren(h('div', { class: 'content' }, h('div', { class: 'm3' }, t('ui-loading'))));
    }
    const root = screen(name);
    try {
      await views[name](root);
      if (ticket !== asked) return;
      applyStaticText(root);
      wear(name);
      target.replaceChildren(root);
    } catch (error) {
      if (ticket !== asked) return;
      if (!quiet) target.replaceChildren(h('div', { class: 'content' }, h('div', { class: 'm3' }, error.message)));
      refused(error);
    }
  }

  async function route() {
    clearInterval(state.timer);
    if (!state.me) {
      wear(state.setupNeeded ? 'first-run' : 'login');
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
    try { await loadMessages(); } catch { /* the page still stands without them */ }
    $('#theme').addEventListener('click', (event) => {
      const button = event.target.closest('[data-theme]');
      if (button) setTheme(button.dataset.theme);
    });
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
      state.channel = panel.channel_address || '';
      state.uptime = panel.uptime_seconds == null ? null : Number(panel.uptime_seconds);
    } catch { state.setupNeeded = false; }
    showRail();
    route();
  }

  boot();
})();
