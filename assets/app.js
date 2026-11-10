'use strict';

(() => {
  // ── Config ──────────────────────────────────────────────────────────────────
  const CLIENT_ID = '5102067687-f0ilsv1bcnkfoj0a21h8fgsmp0g3kbgb.apps.googleusercontent.com';
  const SCOPES = [
    'https://www.googleapis.com/auth/documents',
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/userinfo.profile',
  ].join(' ');
  const ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'trickle.krishaypanchal.me'];
  const FLUSH_EVERY = 6;          // characters buffered before each Docs write
  const MAX_RETRIES = 5;          // for rate limits (429) and transient 5xx
  const TOKEN_KEY = 'tk_token';
  const EXPIRY_KEY = 'tk_token_exp';
  const STATE_KEY = 'tk_oauth_state';

  const $ = id => document.getElementById(id);

  // Refuse to run inside a frame (clickjacking). GitHub Pages cannot send
  // X-Frame-Options / frame-ancestors, so this has to be done in script.
  if (window.top !== window.self) {
    document.body.textContent = 'Trickle cannot run inside a frame. Open it directly.';
    return;
  }

  // ── Session (OAuth token) ───────────────────────────────────────────────────
  class AuthError extends Error {}

  const session = {
    token: '',
    load() {
      const exp = Number(sessionStorage.getItem(EXPIRY_KEY)) || 0;
      const token = sessionStorage.getItem(TOKEN_KEY) || '';
      if (token && Date.now() < exp) this.token = token;
      else this.clear();
    },
    save(token, expiresInSec) {
      this.token = token;
      sessionStorage.setItem(TOKEN_KEY, token);
      // Expire a minute early so a run never starts on a token about to die.
      sessionStorage.setItem(EXPIRY_KEY, String(Date.now() + (expiresInSec - 60) * 1000));
    },
    clear() {
      this.token = '';
      sessionStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(EXPIRY_KEY);
    },
  };

  function randomState() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  }

  function signIn() {
    const state = randomState();
    sessionStorage.setItem(STATE_KEY, state);
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: location.origin + location.pathname,
      response_type: 'token',
      scope: SCOPES,
      include_granted_scopes: 'true',
      state,
    });
    location.assign('https://accounts.google.com/o/oauth2/v2/auth?' + params);
  }

  /**
   * Reads the OAuth response from the URL fragment, if there is one.
   * A token is accepted only when its `state` matches the value this tab
   * generated in signIn(), so a crafted link cannot plant someone else's token.
   * Returns an error message to show, or '' when there is nothing to report.
   */
  function consumeOAuthRedirect() {
    if (!location.hash) return '';
    const params = new URLSearchParams(location.hash.slice(1));
    if (!params.has('access_token') && !params.has('error')) return '';

    // Never leave a token in the address bar or history.
    history.replaceState(null, '', location.pathname + location.search);

    const expected = sessionStorage.getItem(STATE_KEY);
    sessionStorage.removeItem(STATE_KEY);
    if (!expected || params.get('state') !== expected) {
      return 'Sign-in could not be verified. Please try again.';
    }
    if (params.has('error')) {
      return params.get('error') === 'access_denied'
        ? 'Sign-in was cancelled.'
        : 'Google sign-in failed. Please try again.';
    }
    const expiresIn = parseInt(params.get('expires_in'), 10);
    session.save(params.get('access_token'), Number.isFinite(expiresIn) ? expiresIn : 3600);
    return '';
  }

  function signOut() {
    const token = session.token;
    stopRun();
    session.clear();
    if (token) {
      // Revoke at Google so the token is dead, not merely forgotten locally.
      fetch('https://oauth2.googleapis.com/revoke', {
        method: 'POST',
        mode: 'no-cors',
        keepalive: true,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }),
      }).catch(() => {});
    }
    clearDoc();
    resetAll();
    $('srcText').value = '';
    $('docUrlInput').value = '';
    showAuth('');
  }

  // ── Google API ──────────────────────────────────────────────────────────────
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

  /** Authenticated JSON request. Throws on any non-2xx; retries 429 and 5xx. */
  async function api(url, body) {
    for (let attempt = 0; ; attempt++) {
      if (!session.token) throw new AuthError('Signed out');
      const res = await fetch(url, {
        method: body ? 'POST' : 'GET',
        headers: {
          Authorization: 'Bearer ' + session.token,
          ...(body ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        referrerPolicy: 'no-referrer',
      });
      if (res.ok) return res.json();
      if (res.status === 401) {
        session.clear();
        throw new AuthError('Your Google session expired. Please sign in again.');
      }
      if ((res.status === 429 || res.status >= 500) && attempt < MAX_RETRIES) {
        await sleep(1000 * 2 ** attempt + Math.random() * 500);
        continue;
      }
      let message = 'Google API error (' + res.status + ')';
      try {
        const data = await res.json();
        if (data && data.error && typeof data.error.message === 'string') message = data.error.message;
      } catch { /* non-JSON error body */ }
      throw new Error(message);
    }
  }

  const docUrl = (id, suffix = '') =>
    'https://docs.googleapis.com/v1/documents/' + encodeURIComponent(id) + suffix;

  const fetchDocBody = id => api(docUrl(id, '?fields=body.content'));

  const insertText = (id, text, index) =>
    api(docUrl(id, ':batchUpdate'), { requests: [{ insertText: { text, location: { index } } }] });

  const deleteRange = (id, startIndex, endIndex) =>
    api(docUrl(id, ':batchUpdate'), { requests: [{ deleteContentRange: { range: { startIndex, endIndex } } }] });

  // ── DOM helpers ─────────────────────────────────────────────────────────────
  // All dynamic content is built with createElement/textContent — never innerHTML —
  // so document names, API messages, etc. can never be interpreted as markup.
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function setStatus(text, state) {
    $('statusText').textContent = text;
    $('pip').className = 'pip' + (state ? ' ' + state : '');
  }

  function showAuth(errorMessage) {
    $('main-ui').hidden = true;
    $('auth-section').hidden = false;
    $('authError').textContent = errorMessage || '';
    $('authError').hidden = !errorMessage;
  }

  /** Handles an error from any API-backed action; returns the message shown. */
  function handleApiError(err) {
    if (err instanceof AuthError) {
      stopRun();
      showAuth(err.message);
    }
    return err && err.message ? err.message : 'Something went wrong.';
  }

  function isGoogleAvatar(url) {
    try {
      const u = new URL(url);
      return u.protocol === 'https:' && u.hostname.endsWith('.googleusercontent.com');
    } catch {
      return false;
    }
  }

  async function showSignedIn() {
    try {
      const user = await api('https://www.googleapis.com/oauth2/v2/userinfo');
      const avatar = $('userAvatar');
      const name = typeof user.name === 'string' ? user.name : '';
      avatar.replaceChildren();
      if (typeof user.picture === 'string' && isGoogleAvatar(user.picture)) {
        const img = el('img');
        img.alt = '';
        img.referrerPolicy = 'no-referrer';
        img.src = user.picture;
        avatar.appendChild(img);
      } else {
        avatar.textContent = (name || 'U').charAt(0).toUpperCase();
      }
      $('userName').textContent = name || 'Signed in';
      $('auth-section').hidden = true;
      $('main-ui').hidden = false;
    } catch (err) {
      session.clear();
      showAuth(err instanceof AuthError ? '' : 'Could not reach Google. Please try signing in again.');
    }
  }

  // ── Doc picker ──────────────────────────────────────────────────────────────
  const doc = { id: '', name: '' };

  async function loadDocs() {
    const items = $('docListItems');
    $('docList').hidden = false;
    items.replaceChildren(el('div', 'list-note', 'Loading your docs…'));
    try {
      const params = new URLSearchParams({
        q: "mimeType='application/vnd.google-apps.document' and trashed=false",
        pageSize: '25',
        orderBy: 'modifiedTime desc',
        fields: 'files(id,name,modifiedTime)',
      });
      const data = await api('https://www.googleapis.com/drive/v3/files?' + params);
      const files = Array.isArray(data.files) ? data.files : [];
      $('docListHdr').textContent = 'Your Google Docs (' + files.length + ' recent)';
      if (!files.length) {
        items.replaceChildren(el('div', 'list-note', 'No docs found.'));
        return;
      }
      items.replaceChildren(...files.map(file => {
        const row = el('div', 'doc-item' + (file.id === doc.id ? ' selected' : ''));
        const info = el('div', 'doc-info');
        info.append(
          el('div', 'doc-name', String(file.name)),
          el('div', 'doc-meta', 'Modified ' + new Date(file.modifiedTime).toLocaleDateString()),
        );
        row.append(el('span', 'doc-icon', '📄'), info, el('span', 'doc-check', '✓'));
        row.addEventListener('click', () => pickDoc(String(file.id), String(file.name), row));
        return row;
      }));
    } catch (err) {
      items.replaceChildren(el('div', 'list-note error', handleApiError(err)));
    }
  }

  function handleDocUrl() {
    const match = $('docUrlInput').value.match(/\/document\/d\/([a-zA-Z0-9_-]+)/);
    if (match) pickDoc(match[1], 'Doc from URL');
  }

  function pickDoc(id, name, row) {
    if (run) return; // never retarget a run that is in flight
    doc.id = id;
    doc.name = name;
    document.querySelectorAll('.doc-item').forEach(item => item.classList.remove('selected'));
    if (row) row.classList.add('selected');
    $('selectedName').textContent = '📄 ' + name;
    $('selectedBar').hidden = false;
    $('docList').hidden = true;
    $('docStructureBox').hidden = true;
    setStatus('Doc selected: ' + name, '');
  }

  function clearDoc() {
    if (run) return;
    doc.id = '';
    doc.name = '';
    $('selectedBar').hidden = true;
    $('docStructureBox').hidden = true;
    setStatus('Ready', '');
  }

  // ── Doc structure inspector ─────────────────────────────────────────────────
  async function inspectDoc() {
    if (!doc.id) { setStatus('Select a doc first', 'warn'); return; }
    const box = $('docStructureBox');
    box.hidden = false;
    box.replaceChildren(el('span', 'struct-note', 'Fetching structure…'));
    try {
      const data = await fetchDocBody(doc.id);
      const rows = [];
      for (const block of (data.body && data.body.content) || []) {
        if (!block.paragraph || !Number.isInteger(block.endIndex)) continue;
        const start = Number.isInteger(block.startIndex) ? block.startIndex : 0;
        const end = block.endIndex;
        let preview = '';
        for (const part of block.paragraph.elements || []) {
          preview += (part.textRun && part.textRun.content) || '';
        }
        preview = preview.replace(/\n/g, '↵').slice(0, 64);
        const style = (block.paragraph.paragraphStyle && block.paragraph.paragraphStyle.namedStyleType) || '';

        const row = el('button', 'struct-row');
        row.type = 'button';
        row.title = 'Insert after this paragraph';
        row.append(el('span', 'struct-range', start + '–' + end), ' ');
        if (style) row.append(el('span', 'struct-style', '[' + style + ']'));
        row.append(el('span', '', preview), el('span', 'struct-use', '← use this'));
        // A paragraph's endIndex is one past its trailing newline; inserting at
        // end - 1 keeps the text inside the document body (the final newline of
        // a doc cannot be written past).
        row.addEventListener('click', () => setInsertIndex(end - 1));
        rows.push(row);
      }
      if (rows.length) {
        box.replaceChildren(el('div', 'struct-hint', 'Click a row to insert at the end of that paragraph'), ...rows);
      } else {
        box.replaceChildren(el('span', 'struct-note', 'No paragraphs found.'));
      }
    } catch (err) {
      box.replaceChildren(el('span', 'struct-note error', handleApiError(err)));
    }
  }

  function setInsertIndex(index) {
    $('insertIdxInput').value = index;
    $('docStructureBox').hidden = true;
    setStatus('Insertion index set to ' + index, '');
  }

  // ── Typing engine ───────────────────────────────────────────────────────────
  const NEARBY = {
    a: 'sqwz', b: 'vghn', c: 'xdfv', d: 'serfcx', e: 'wrsdf', f: 'drtgv', g: 'ftyhbv',
    h: 'gyujbn', i: 'ujko', j: 'huikm', k: 'ijolm', l: 'kop', m: 'njk', n: 'bhjm', o: 'iklp', p: 'ol',
    q: 'wa', r: 'etdf', s: 'awedxz', t: 'ryfg', u: 'yihj', v: 'cfgb', w: 'qase', x: 'zsdc', y: 'tghu', z: 'asx',
  };

  function nearbyKey(c) {
    const options = NEARBY[c.toLowerCase()];
    if (!options) return c;
    const key = options[Math.floor(Math.random() * options.length)];
    return c === c.toUpperCase() ? key.toUpperCase() : key;
  }

  const rangeValue = id => parseInt($(id).value, 10) || 0;
  const baseDelay = () => Math.max(15, 285 - rangeValue('speedRange') * 23);
  const errorChance = () => rangeValue('errorRange') / 100 * 0.12;
  const hesitationChance = () => rangeValue('hesitationRange') / 100 * 0.16;

  /** The active run, or null. Each run owns its state, so a stale loop can never touch a new one. */
  let run = null;

  function renderPreview(text) {
    $('outputText').textContent = text;
    const box = $('outputBox');
    box.scrollTop = box.scrollHeight;
  }

  function setPauseButton(paused) {
    // SVG elements have no .hidden property, so toggle the attribute.
    $('pauseIcon').toggleAttribute('hidden', paused);
    $('resumeIcon').toggleAttribute('hidden', !paused);
    $('pauseLabel').textContent = paused ? 'Resume' : 'Pause';
  }

  function setRunningUi(running) {
    $('startBtn').disabled = running;
    $('pauseBtn').disabled = !running;
    $('docUrlInput').disabled = running;
    $('insertIdxInput').disabled = running;
    setPauseButton(false);
  }

  function stopRun() {
    if (!run) return;
    run.cancelled = true;
    if (run.resume) run.resume();
    run = null;
    setRunningUi(false);
  }

  async function resolveInsertIndex(docId) {
    const data = await fetchDocBody(docId);
    let end = 1;
    for (const block of (data.body && data.body.content) || []) {
      if (Number.isInteger(block.endIndex)) end = block.endIndex;
    }
    const lastWritable = Math.max(1, end - 1);
    const raw = $('insertIdxInput').value.trim();
    if (!raw) return lastWritable;
    const manual = Number(raw);
    if (!Number.isInteger(manual) || manual < 1 || manual > lastWritable) {
      throw new Error('Insertion index must be a whole number between 1 and ' + lastWritable + '.');
    }
    return manual;
  }

  async function startTyping() {
    if (run) return;
    const source = $('srcText').value.replace(/\r\n?/g, '\n');
    if (!source.trim()) { setStatus('Paste some text first', 'warn'); return; }
    if (!doc.id) { setStatus('Pick a Google Doc first', 'warn'); return; }

    const self = run = { cancelled: false, paused: false, resume: null };
    const docId = doc.id;
    const docName = doc.name;
    // Iterate by code point so emoji and other astral characters are never split
    // across two writes; Docs indexes are UTF-16 code units, hence .length below.
    const chars = Array.from(source);
    let typed = '';      // what the preview shows
    let pending = '';    // typed but not yet written to the doc
    let written = 0;     // UTF-16 units written to the doc so far
    let base = 0;        // doc index where this run started inserting

    const alive = () => !self.cancelled;
    const waitIfPaused = async () => {
      while (self.paused && alive()) await new Promise(resolve => { self.resume = resolve; });
    };
    const type = text => { typed += text; pending += text; renderPreview(typed); };
    const flush = async () => {
      if (!pending) return;
      const text = pending;
      await insertText(docId, text, base + written);
      pending = '';
      written += text.length;
    };
    /** Removes the last character from the doc and the preview (must be flushed first). */
    const backspace = async () => {
      const end = base + written;
      await deleteRange(docId, end - 1, end);
      written -= 1;
      typed = typed.slice(0, -1);
      renderPreview(typed);
    };

    renderPreview('');
    $('prog').style.width = '0%';
    $('copyBtn').disabled = true;
    $('typeCursor').hidden = false;
    setRunningUi(true);
    setStatus('Getting doc position…', 'active');

    try {
      base = await resolveInsertIndex(docId);
      if (!alive()) return;
      setStatus('Trickling into ' + docName + '…', 'active');

      for (let i = 0; i < chars.length; i++) {
        await waitIfPaused();
        if (!alive()) return;

        const c = chars[i];
        const speed = baseDelay();
        let wait = Math.max(12, speed + (Math.random() - 0.5) * speed * 0.7);
        if (c === ' ' || c === '\n') wait *= 1.15 + Math.random() * 0.3;
        if (c === '.' || c === '!' || c === '?') wait *= 2.2 + Math.random() * 1.5;
        if (c === ',') wait *= 1.6 + Math.random();
        if (c === '\n') wait *= 2.5 + Math.random();

        if (Math.random() < hesitationChance() && c !== ' ') {
          await sleep(wait * 3.5 + Math.random() * 320);
        }

        if (Math.random() < errorChance() && /^[a-zA-Z]$/.test(c)) {
          // Hit a neighbouring key, notice, backspace, retype. The typo is flushed
          // first so the backspace only ever deletes text this run inserted.
          type(nearbyKey(c));
          await flush();
          await sleep(wait);
          if (!alive()) return;

          // Occasionally over-correct and take the previous character out too.
          const prev = i > 0 ? chars[i - 1] : '';
          const overshoot = Math.random() < 0.2 && prev.length === 1 && prev !== '\n';
          await backspace();
          await sleep(wait * 0.6);
          if (overshoot) {
            await backspace();
            await sleep(wait * 0.6);
            type(prev);
            await sleep(wait);
          }
        }
        type(c);

        if (pending.length >= FLUSH_EVERY) await flush();
        $('prog').style.width = ((i + 1) / chars.length * 100).toFixed(1) + '%';
        await sleep(wait);
      }

      await flush();
      if (!alive()) return;
      $('typeCursor').hidden = true;
      $('copyBtn').disabled = false;
      setStatus('Done — trickled into "' + docName + '"', 'done');
    } catch (err) {
      if (alive()) setStatus('Stopped: ' + handleApiError(err), 'error');
    } finally {
      if (run === self) {
        run = null;
        setRunningUi(false);
      }
    }
  }

  function togglePause() {
    if (!run) return;
    run.paused = !run.paused;
    setPauseButton(run.paused);
    if (run.paused) {
      setStatus('Paused', 'warn');
    } else {
      setStatus('Trickling…', 'active');
      if (run.resume) { run.resume(); run.resume = null; }
    }
  }

  function resetAll() {
    stopRun();
    renderPreview('');
    $('typeCursor').hidden = false;
    $('prog').style.width = '0%';
    $('copyBtn').disabled = true;
    setStatus('Reset — ready', '');
  }

  function flashLabel(node, text, original) {
    node.textContent = text;
    setTimeout(() => { node.textContent = original; }, 2000);
  }

  function copyOutput() {
    navigator.clipboard.writeText($('outputText').textContent)
      .then(() => flashLabel($('copyLabel'), 'Copied!', 'Copy output'))
      .catch(() => setStatus('Could not copy to clipboard', 'warn'));
  }

  function copyServeCommand() {
    navigator.clipboard.writeText($('serveCmd').textContent)
      .then(() => flashLabel($('copyCmdBtn'), 'Copied!', 'Copy'))
      .catch(() => {});
  }

  // ── Boot ────────────────────────────────────────────────────────────────────
  function bindEvents() {
    $('copyCmdBtn').addEventListener('click', copyServeCommand);
    $('signInBtn').addEventListener('click', signIn);
    $('signOutBtn').addEventListener('click', signOut);
    $('docUrlInput').addEventListener('input', handleDocUrl);
    $('browseBtn').addEventListener('click', loadDocs);
    $('clearDocBtn').addEventListener('click', clearDoc);
    $('inspectBtn').addEventListener('click', inspectDoc);
    $('resetIdxBtn').addEventListener('click', () => { $('insertIdxInput').value = ''; });
    $('startBtn').addEventListener('click', startTyping);
    $('pauseBtn').addEventListener('click', togglePause);
    $('resetBtn').addEventListener('click', resetAll);
    $('copyBtn').addEventListener('click', copyOutput);
    document.querySelectorAll('input[type=range][data-output]').forEach(range => {
      range.addEventListener('input', () => { $(range.dataset.output).textContent = range.value; });
    });
  }

  function boot() {
    bindEvents();

    // OAuth only works from an origin registered with the Google client; anywhere
    // else (file://, an unknown host) show setup instructions and touch no tokens.
    if (!ALLOWED_HOSTS.includes(location.hostname)) {
      $('gate').hidden = false;
      return;
    }

    const authError = consumeOAuthRedirect();
    if (!session.token) session.load();

    if (session.token) showSignedIn();
    else showAuth(authError);
  }

  boot();
})();
