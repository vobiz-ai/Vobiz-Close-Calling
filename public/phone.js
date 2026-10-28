/* Vobiz Calling for Close: the softphone tab.
 *
 * Same panel as the Zendesk and ClickUp calling apps: numbered steps, a status
 * badge plus a status sentence, an incoming-call banner, a keypad, call
 * controls, a matched-record card and a "call finished" popup.
 *
 * The browser is the A leg for outbound calls: it sends the INVITE itself and
 * the backend's /vobiz/answer dials the customer. Inbound calls ring this tab
 * through <Dial><User>.
 *
 * JsSIP settings that audio depends on, learned the hard way:
 *  - user_agent has NO spaces (a space makes the gateway drop <Dial><User>);
 *  - session_timers off;
 *  - STUN in pcConfig on every call() and answer();
 *  - ICE gathering capped at about 2.5 s.
 */
(function () {
  'use strict';

  var REGISTRAR_HOST = 'registrar.vobiz.ai';
  var PC_CONFIG = { iceServers: [{ urls: ['stun:stun.l.google.com:19302'] }] };
  var TOKEN_KEY = 'vz_cl_session';
  var THEME_KEY = 'vz_cl_theme';

  var token = null;
  try { token = sessionStorage.getItem(TOKEN_KEY); } catch (e) { token = null; }
  var session = null;      // what /api/session returned
  var ua = null;
  var registered = false;
  var rtc = null;          // current JsSIP RTCSession
  var sipJwt = null;       // the current access token, when signed in with one
  var jwtTimer = null;     // renews the access token before it expires
  var call = null;         // { direction, number, ref, callUuid, startedAt, answeredAt, lookup }
  var pendingDial = null;  // a click-to-call waiting for confirmation
  var timerHandle = null;
  var ring = null;
  var streamAbort = null;
  var doneCall = null;     // the call the "call finished" popup is about

  var $ = function (id) { return document.getElementById(id); };
  function show(id, on) { $(id).hidden = !on; }
  function text(id, t) { $(id).textContent = t == null ? '' : String(t); }

  // ─── status: a badge holds a state, the sentence goes in its own row ────────

  var KIND = { info: 'is-busy', ok: 'is-ok', warn: 'is-pending', error: 'is-error' };

  function notice(msg, kind) {
    var el = $('status-message');
    el.textContent = msg || '';
    el.className = 'status-message ' + (KIND[kind] || KIND.info);
    el.hidden = !msg;
  }

  function setStatus(state, label) {
    var el = $('status');
    el.className = 'status-badge is-' + state;
    el.textContent = label;
  }

  function newRef() {
    var a = new Uint8Array(12);
    crypto.getRandomValues(a);
    return Array.prototype.map.call(a, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }

  function clock(secs) {
    secs = Math.max(0, Math.round(secs || 0));
    var m = Math.floor(secs / 60);
    var s = secs % 60;
    return (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s;
  }

  // ─── API ───────────────────────────────────────────────────────────────────

  function api(path, opts) {
    opts = opts || {};
    var headers = { Accept: 'application/json' };
    if (token) headers.Authorization = 'Bearer ' + token;
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    return fetch('/api' + path, {
      method: opts.method || (opts.body !== undefined ? 'POST' : 'GET'),
      headers: headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (r.status === 401 && data.code === 'signed_out') { signedOut('Your session ended. Connect Close again.'); }
        if (!r.ok) { var err = new Error(data.error || ('HTTP ' + r.status)); err.status = r.status; err.data = data; throw err; }
        return data;
      });
    });
  }

  function setToken(t) {
    token = t;
    try { if (t) sessionStorage.setItem(TOKEN_KEY, t); else sessionStorage.removeItem(TOKEN_KEY); } catch (e) { /* private mode */ }
  }

  // ─── render ────────────────────────────────────────────────────────────────

  function lock(id, locked) { $(id).classList.toggle('is-locked', !!locked); }
  function done(id, isDone) { $(id).classList.toggle('is-done', !!isDone); }

  function render() {
    var connected = !!session;
    var signedIn = connected && !!session.mode;

    // Step 1: Close.
    show('hs-out', !connected);
    show('hs-who', connected);
    if (connected) text('hs-who', 'Connected to ' + session.workspace.name + ' as ' + session.user.name + (session.user.auth === 'apikey' ? ' (API key)' : '') + ' · calls are logged under your name.');
    done('step-hs', connected);

    // Step 2: Vobiz.
    lock('step-signin', !connected);
    done('step-signin', signedIn);
    show('signin-forms', !signedIn);
    show('btn-signout', signedIn);
    if (!signedIn) text('login-status', connected ? 'Not signed in.' : 'Connect Close first.');
    else text('login-status', 'Logged in as ' + session.authId + ' — calling from ' + (session.from || 'no number'));

    // Steps 3, 4 and inbound.
    lock('step-caller', !signedIn);
    lock('step-call', !signedIn);
    lock('step-inbound', !signedIn);
    done('step-caller', signedIn && !!session.from);
    show('btn-settings', connected);
    if (signedIn) renderNumbers();
    updateDialState();
  }

  function renderNumbers() {
    var sel = $('sel-callerid');
    sel.innerHTML = '';
    (session.numbers || []).forEach(function (n) {
      var o = document.createElement('option');
      o.value = n; o.textContent = n;
      if (n === session.from) o.selected = true;
      sel.appendChild(o);
    });
    var app = session.numberApps && session.numberApps[session.from];
    if (app && app === session.appId) text('inbound-hint', 'Inbound calls to ' + session.from + ' already ring this softphone.');
    else if (app) text('inbound-hint', session.from + ' is on another Vobiz application (' + app + '). Enabling moves it here.');
    else text('inbound-hint', 'Inbound calls to ' + session.from + ' are not routed anywhere yet.');
    done('step-inbound', !!app && app === session.appId);
  }

  /** The Call button is enabled only when calling can actually work; the hint says why not. */
  function updateDialState() {
    var why = '';
    if (!session) why = 'Connect Close to start.';
    else if (!session.mode) why = 'Sign in to Vobiz to place calls.';
    else if (!registered) why = 'Waiting for the phone to register with Vobiz.';
    else if (session.mode === 'account' && !session.from) why = 'Choose a caller ID first.';
    $('btn-call').disabled = !!why || !!rtc;
    text('dial-hint', rtc ? '' : why);
  }

  function signedOut(msg) {
    stopUA();
    stopStream();
    setToken(null);
    session = null;
    showView('phone');
    render();
    setStatus('off', 'Offline');
    if (msg) notice(msg, 'warn');
  }

  function showView(name) {
    show('view-phone', name === 'phone');
    show('call-history', name === 'phone');
    document.querySelector('.faq').hidden = name !== 'phone';
    show('view-settings', name === 'settings');
  }

  // ─── boot ──────────────────────────────────────────────────────────────────

  function boot() {
    var hash = new URLSearchParams(location.hash.slice(1));
    if (hash.get('link') || hash.get('error')) history.replaceState(null, '', location.pathname);
    var ERRORS = {
      denied: 'Close access was not granted.',
      connect: 'Could not connect Close. Try again.',
    };
    if (hash.get('error')) notice(ERRORS[hash.get('error')] || ERRORS.connect, 'warn');
    loadOptions();

    var claim = hash.get('link')
      ? api('/identity/claim', { body: { code: hash.get('link') } }).then(function (r) { setToken(r.token); return r.session; })
      : (token ? api('/session') : Promise.resolve(null));

    claim.then(function (s) {
      session = s;
      render();
      if (!s) { setStatus('off', 'Offline'); return; }
      startStream();
      loadHistory();
      if (s.mode === 'account') return api('/agent').then(startUA);
      setStatus('off', 'Offline');
    }).catch(function (err) {
      if (err.status !== 401) notice(err.message, 'error');
      render();
    });
  }

  /** OAuth, an agent's own API key, or both: whatever this deployment offers. */
  function loadOptions() {
    fetch('/close/oauth/options').then(function (r) { return r.json(); }).then(function (r) {
      show('btn-connect', !!r.oauth);
      show('form-apikey', !!r.apiKey);
      show('apikey-or', !!r.oauth && !!r.apiKey);
    }).catch(function () { show('form-apikey', true); });
  }

  $('form-apikey').onsubmit = function (e) {
    e.preventDefault();
    var key = $('in-apikey').value.trim();
    $('in-apikey').value = '';
    notice('Checking the key with Close…', 'warn');
    api('/identity/apikey', { body: { apiKey: key } }).then(function (r) {
      setToken(r.token);
      session = r.session;
      notice('');
      render();
      startStream();
      loadHistory();
    }).catch(function (err) { notice(err.message, 'error'); });
  };

  // ─── sign-in ───────────────────────────────────────────────────────────────

  $('form-account').onsubmit = function (e) {
    e.preventDefault();
    notice('Signing in…', 'warn');
    setStatus('pending', 'Signing in');
    var authToken = $('in-authtoken').value;
    $('in-authtoken').value = '';
    api('/login', { body: { authId: $('in-authid').value.trim(), authToken: authToken } })
      .then(function (s) {
        session = s;
        if (s.bound === false) notice('Signed in, but your endpoint could not be linked to the calling application. Outbound calls may fail.', 'warn');
        else notice('');
        render();
        return api('/agent');
      })
      .then(startUA)
      .catch(function (err) { setStatus('error', 'Not signed in'); notice(err.message, 'error'); });
  };

  $('btn-signout').onclick = function () {
    if (rtc && !window.confirm('Signing out ends your current call. Sign out?')) return;
    api('/logout', { body: {} }).catch(function () {}).then(function () { signedOut('Signed out.'); });
  };

  // ─── event stream (fetch, so the token stays in a header) ────────────────

  function startStream() {
    stopStream();
    var ctrl = new AbortController();
    streamAbort = ctrl;
    var backoff = 1000;
    (function connect() {
      if (ctrl.signal.aborted || !token) return;
      fetch('/api/events', { headers: { Authorization: 'Bearer ' + token, Accept: 'text/event-stream' }, signal: ctrl.signal })
        .then(function (r) {
          if (r.status === 401) { signedOut('Your session ended. Connect Close again.'); return; }
          if (!r.ok || !r.body) throw new Error('stream ' + r.status);
          backoff = 1000;
          var reader = r.body.getReader();
          var dec = new TextDecoder();
          var buf = '';
          function pump() {
            return reader.read().then(function (chunk) {
              if (chunk.done) throw new Error('closed');
              buf += dec.decode(chunk.value, { stream: true });
              var parts = buf.split('\n\n');
              buf = parts.pop();
              parts.forEach(function (block) {
                var data = block.split('\n').filter(function (l) { return l.indexOf('data: ') === 0; }).map(function (l) { return l.slice(6); }).join('\n');
                if (data) { try { onEvent(JSON.parse(data)); } catch (e) { /* ignore */ } }
              });
              return pump();
            });
          }
          return pump();
        })
        .catch(function () {
          if (ctrl.signal.aborted) return;
          setTimeout(connect, backoff);
          backoff = Math.min(backoff * 2, 30000);
        });
    })();
  }

  function stopStream() {
    if (streamAbort) { streamAbort.abort(); streamAbort = null; }
  }

  function onEvent(ev) {
    switch (ev.type) {
      case 'incoming':
        if (call && call.direction === 'inbound' && !call.callUuid) call.callUuid = ev.callUuid;
        return;
      case 'logged': return markLogged(ev);
      case 'log-error':
        notice(ev.message, 'warn');
        if (doneCall && !$('call-done').hidden) setDoneCrm('error', 'Not logged yet. It will be retried.');
        return;
      case 'transfer-incoming': return notice('Transfer from ' + ev.fromAgent + ': ' + ev.from, 'info');
      case 'signed-out':
        stopUA();
        if (ev.reason === 'elsewhere') {
          setStatus('error', 'Signed in elsewhere');
          notice('You signed in in another tab or browser. This tab no longer receives calls.', 'warn');
        } else signedOut(ev.reason === 'disconnected' ? 'Close was disconnected.' : '');
        return;
      default: return;
    }
  }

  // ─── SIP ───────────────────────────────────────────────────────────────────

  /**
   * Register as the agent's SIP identity. With an access token (agent.auth
   * "jwt") there is no password: the token rides in X-Vobiz-Jwt on REGISTER
   * and on every outbound INVITE, and is renewed a minute before it expires.
   */
  function startUA(agent) {
    stopUA();
    if (typeof JsSIP === 'undefined') { setStatus('error', 'SIP missing'); notice('The SIP library did not load. Reload the page.', 'error'); return; }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) { setStatus('error', 'No microphone'); notice('This page needs microphone access over HTTPS.', 'error'); return; }
    setStatus('pending', 'Connecting');
    if (agent.auth !== 'jwt') { createUA(agent, null); return; }
    api('/sip-token', { body: {} }).then(function (t) {
      if (!session || session.mode !== 'account') return;
      createUA(agent, t);
    }).catch(function (err) {
      if (err.status === 401) return;
      setStatus('error', 'Not registered');
      notice('Could not get a calling token: ' + err.message, 'error');
    });
  }

  function createUA(agent, jwt) {
    if (ua) { stopUA(); setStatus('pending', 'Connecting'); }
    var sipUser = agent.sipUser;
    try {
      ua = new JsSIP.UA({
        sockets: [new JsSIP.WebSocketInterface(agent.registrarUrl)],
        uri: sipUser.indexOf('sip:') === 0 ? sipUser : 'sip:' + sipUser,
        password: jwt ? undefined : agent.sipPassword,
        display_name: agent.displayName,
        register: true,
        user_agent: 'VobizXCalling/1.0.0',
        session_timers: false,
      });
    } catch (err) {
      setStatus('error', 'SIP error');
      notice('Could not start the phone: ' + err.message, 'error');
      return;
    }
    ua.on('registered', function () { registered = true; setStatus('ok', 'Ready'); updateDialState(); });
    ua.on('registrationFailed', function (e) { registered = false; setStatus('error', 'Not registered'); notice('Registration failed: ' + ((e && e.cause) || 'unknown'), 'error'); updateDialState(); });
    ua.on('unregistered', function () { registered = false; setStatus('pending', 'Reconnecting'); updateDialState(); });
    ua.on('disconnected', function () { registered = false; setStatus('error', 'Disconnected'); updateDialState(); });
    ua.on('newRTCSession', function (data) { if (data.originator === 'remote') onIncoming(data.session); });
    if (jwt) useJwt(jwt);
    ua.start();
    // Ask for the microphone now, so the first call does not stall on a prompt.
    navigator.mediaDevices.getUserMedia({ audio: true }).then(function (s) { s.getTracks().forEach(function (t) { t.stop(); }); })
      .catch(function () { notice('Allow the microphone for this site, or callers will not hear you.', 'error'); });
  }

  /** Put a token on REGISTER and schedule its renewal. */
  function useJwt(t) {
    sipJwt = t.token;
    ua.registrator().setExtraHeaders(['X-Vobiz-Jwt: ' + t.token]);
    clearTimeout(jwtTimer);
    var wait = Math.max(30, Number(t.exp) - Math.floor(Date.now() / 1000) - 60) * 1000;
    jwtTimer = setTimeout(renewJwt, wait);
  }

  function renewJwt() {
    var current = ua;
    api('/sip-token', { body: {} }).then(function (t) {
      if (!current || ua !== current) return;
      useJwt(t);
      current.register();
    }).catch(function (err) {
      if (err.status === 401 || ua !== current) return;
      // The old token is still good for up to a minute: try again soon.
      jwtTimer = setTimeout(renewJwt, 15000);
    });
  }

  function stopUA() {
    registered = false;
    clearTimeout(jwtTimer);
    jwtTimer = null;
    sipJwt = null;
    if (rtc) { try { rtc.terminate(); } catch (e) { /* ignore */ } }
    if (ua) { var old = ua; ua = null; try { old.removeAllListeners(); old.stop(); } catch (e) { /* ignore */ } }
    setStatus('off', 'Offline');
    updateDialState();
  }

  function capIce(s) {
    var t = null;
    s.on('icecandidate', function (e) { if (!t) t = setTimeout(function () { e.ready(); }, 2500); });
  }

  function attachAudio(s) {
    var audio = $('remote-audio');
    function bind() {
      var pc = s.connection;
      if (!pc) return;
      pc.addEventListener('track', function (e) { if (e.streams && e.streams[0]) audio.srcObject = e.streams[0]; });
    }
    if (s.connection) bind(); else s.on('peerconnection', bind);
  }

  // ─── outbound ──────────────────────────────────────────────────────────────

  function placeCall(number, ref) {
    number = String(number || '').replace(/[^\d+]/g, '');
    if (!number) { notice('Type a number to call.', 'warn'); return; }
    if (!ua || !registered) { notice('The phone is not ready yet. Wait for the green Ready badge.', 'warn'); return; }
    if (rtc) { notice('You are already on a call.', 'warn'); return; }
    ref = ref || newRef();
    var headers = ['X-VH-Ref: ' + ref];
    if (/^\+?\d{10,15}$/.test(session.from || '')) headers.push('X-VH-Caller-ID: ' + session.from);
    if (sipJwt) headers.push('X-Vobiz-Jwt: ' + sipJwt);
    call = { direction: 'outbound', number: number, ref: ref, startedAt: Date.now() };
    $('in-dial').value = number;
    showCall('Calling ' + number);
    lookup(number);
    var s;
    try {
      s = ua.call('sip:' + number + '@' + REGISTRAR_HOST, {
        extraHeaders: headers,
        mediaConstraints: { audio: true, video: false },
        pcConfig: PC_CONFIG,
      });
    } catch (err) {
      endCall('Could not start the call: ' + err.message);
      return;
    }
    rtc = s;
    updateDialState();
    capIce(s);
    attachAudio(s);
    s.on('progress', function () { text('call-state', 'Ringing ' + number); setStatus('busy', 'Ringing'); });
    s.on('confirmed', function () { call.answeredAt = Date.now(); text('call-state', 'On a call with ' + number); setStatus('busy', 'On a call'); startTimer(); });
    // JsSIP fires "ended" only for established calls; everything else is
    // "failed". Report both, so the backend can log a call that never reached
    // /vobiz/answer.
    s.on('failed', function (e) { report(call, (e && e.cause) || 'Failed'); endCall('Call failed: ' + ((e && e.cause) || 'unknown')); });
    s.on('ended', function () { report(call, 'Ended'); endCall('Call ended'); });
  }

  function report(c, cause) {
    if (!c || c.direction !== 'outbound') return;
    api('/call-log', { body: { ref: c.ref, number: c.number, cause: cause, startedAt: c.startedAt } }).catch(function () {});
  }

  $('form-dial').onsubmit = function (e) { e.preventDefault(); placeCall($('in-dial').value); };

  // ─── click-to-call from Close ──────────────────────────────────────────────
  // With "Call using tel: links" chosen in Close and this page registered as
  // the browser's tel: handler, a click opens /dial, which hands the number to
  // this tab over a BroadcastChannel (same origin only). /dial can also carry a
  // Close contact or lead id (an Integration Link); the tab then offers that
  // record's numbers. Any website can open these links, so the number is
  // always shown and never dialled unasked.

  var DIAL_CHANNEL = 'vobiz-close-dial';
  var CLOSE_ID = /^(cont|lead)_[A-Za-z0-9]{8,80}$/;
  var dialChannel = null;
  try { dialChannel = new BroadcastChannel(DIAL_CHANNEL); } catch (e) { dialChannel = null; }
  if (dialChannel) {
    dialChannel.onmessage = function (e) {
      var d = e.data || {};
      if (d.type !== 'dial' || typeof d.id !== 'string') return;
      var number = typeof d.number === 'string' ? d.number.replace(/[^\d+]/g, '').slice(0, 20) : '';
      var record = typeof d.record === 'string' && CLOSE_ID.test(d.record) ? d.record : '';
      if (number.replace(/\D/g, '').length < 6) number = '';
      if (!number && !record) return;
      // Only a tab that can actually take the call answers, so the first ready tab wins.
      if (!session || !session.mode || !registered) { dialChannel.postMessage({ type: 'busy', id: d.id, reason: 'not-ready' }); return; }
      dialChannel.postMessage({ type: 'ack', id: d.id });
      onClickToCall({ number: number, record: record });
      try { window.focus(); } catch (err) { /* ignore */ }
    };
  }

  function onClickToCall(ev) {
    if (rtc) { notice('Finish your current call before calling ' + (ev.number || 'from Close') + '.', 'warn'); return; }
    var sel = $('sel-confirm-number');
    show('sel-confirm-number', false);
    if (ev.number) {
      pendingDial = ev;
      text('confirm-text', 'Call ' + ev.number + '?');
      show('confirm', true);
      $('btn-confirm-call').focus();
      return;
    }
    var q = ev.record.indexOf('cont_') === 0 ? 'contact=' : 'lead=';
    api('/record-phones?' + q + encodeURIComponent(ev.record)).then(function (r) {
      if (!r.phones.length) { notice('That Close record has no phone number.', 'warn'); return; }
      sel.innerHTML = '';
      r.phones.forEach(function (p) {
        var o = document.createElement('option'); o.value = p.number; o.textContent = p.number + (p.name ? ' · ' + p.name : ''); sel.appendChild(o);
      });
      pendingDial = { number: r.phones[0].number, pick: true };
      text('confirm-text', r.phones.length > 1 ? 'Which number?' : 'Call ' + r.phones[0].number + (r.phones[0].name ? ' (' + r.phones[0].name + ')' : '') + '?');
      show('sel-confirm-number', r.phones.length > 1);
      show('confirm', true);
      $('btn-confirm-call').focus();
    }).catch(function (err) { notice(err.message, 'error'); });
  }
  $('btn-confirm-call').onclick = function () {
    var d = pendingDial; pendingDial = null; show('confirm', false);
    if (d) placeCall(d.pick && !$('sel-confirm-number').hidden ? $('sel-confirm-number').value : d.number);
  };
  $('btn-confirm-dismiss').onclick = function () { pendingDial = null; show('confirm', false); };

  $('btn-tel').onclick = function () {
    if (!navigator.registerProtocolHandler) { text('tel-hint', 'This browser cannot handle phone links. Copy numbers into the dial box instead.'); return; }
    try {
      navigator.registerProtocolHandler('tel', location.origin + '/dial?to=%s');
      text('tel-hint', 'Your browser asks you to allow it (look at the address bar). Once allowed, clicking a number in Close brings it here. Keep this tab open.');
    } catch (err) {
      text('tel-hint', 'The browser refused: ' + err.message);
    }
  };

  // ─── inbound ───────────────────────────────────────────────────────────────

  function onIncoming(s) {
    if (rtc) { try { s.terminate({ status_code: 486, reason_phrase: 'Busy Here' }); } catch (e) { /* ignore */ } return; }
    var id = s.remote_identity || {};
    var shown = String(id.display_name || '').replace(/[^\d+]/g, '');
    var number = (shown.length >= 6 ? shown : '') || (id.uri && id.uri.user) || 'Unknown caller';
    rtc = s;
    call = { direction: 'inbound', number: number, startedAt: Date.now() };
    text('in-name', number);
    text('in-number', '');
    $('in-convs').innerHTML = '';
    show('incoming', true);
    setStatus('busy', 'Ringing');
    notice('Incoming call from ' + number, 'info');
    updateDialState();
    startRing();
    lookup(number);
    if (document.hidden && window.Notification && Notification.permission === 'granted') {
      try { new Notification('Incoming call', { body: number }); } catch (e) { /* ignore */ }
    }
    capIce(s);
    attachAudio(s);
    s.on('confirmed', function () { call.answeredAt = Date.now(); text('call-state', 'On a call with ' + displayName(call)); setStatus('busy', 'On a call'); startTimer(); });
    s.on('failed', function (e) {
      // Answered by a colleague, or the caller hung up first.
      var why = (e && e.cause) || '';
      endCall(why === 'Canceled' ? 'Answered elsewhere, or the caller hung up' : 'Missed');
    });
    s.on('ended', function () { endCall('Call ended'); });
  }

  function answer() {
    if (!rtc || !call || call.direction !== 'inbound' || call.answering) return;
    call.answering = true;
    stopRing();
    show('incoming', false);
    notice('');
    showCall('Connecting ' + call.number);
    try {
      rtc.answer({ mediaConstraints: { audio: true, video: false }, pcConfig: PC_CONFIG });
    } catch (err) {
      endCall('Could not answer: ' + err.message);
      return;
    }
    // Opening a tab needs a user action, which this is.
    if (session.settings.autoOpen && call.lookup && call.lookup.url) window.open(call.lookup.url, '_blank', 'noopener');
  }

  function decline() {
    if (!rtc || !call || call.direction !== 'inbound' || call.answering) return;
    try { rtc.terminate({ status_code: 486, reason_phrase: 'Busy Here' }); } catch (e) { /* ignore */ }
    endCall('Declined');
  }

  $('btn-answer').onclick = answer;
  $('btn-decline').onclick = decline;

  // Enter to accept, Escape to decline, as in the Zendesk and ClickUp panels.
  document.addEventListener('keydown', function (e) {
    if ($('incoming').hidden) {
      if (e.key === 'Escape' && !$('call-done').hidden) show('call-done', false);
      return;
    }
    if (e.key === 'Enter') { e.preventDefault(); answer(); }
    else if (e.key === 'Escape') { e.preventDefault(); decline(); }
  });

  function startRing() {
    stopRing();
    try {
      var ctx = new (window.AudioContext || window.webkitAudioContext)();
      var beep = function () {
        var o = ctx.createOscillator(); var g = ctx.createGain();
        o.frequency.value = 440; g.gain.value = 0.08;
        o.connect(g); g.connect(ctx.destination);
        o.start(); o.stop(ctx.currentTime + 0.8);
      };
      beep();
      ring = { ctx: ctx, timer: setInterval(beep, 2500) };
    } catch (e) { ring = null; }
  }
  function stopRing() {
    if (!ring) return;
    clearInterval(ring.timer);
    try { ring.ctx.close(); } catch (e) { /* ignore */ }
    ring = null;
  }

  // ─── in-call ───────────────────────────────────────────────────────────────

  function displayName(c) { return (c && c.lookup && c.lookup.name) || (c && c.number) || ''; }

  function showCall(state) {
    show('btn-call', false);
    show('btn-hangup', true);
    show('call-status', true);
    show('call-controls', true);
    show('controls-hint', true);
    show('transfer-box', false);
    text('call-state', state);
    text('call-timer', '00:00');
    setStatus('busy', 'Calling');
    ['btn-mute', 'btn-hold'].forEach(function (id) { $(id).setAttribute('aria-pressed', 'false'); });
    $('btn-mute').querySelector('span').textContent = 'Mute';
    $('btn-hold').querySelector('span').textContent = 'Hold';
    $('btn-transfer').setAttribute('aria-expanded', 'false');
    $('btn-transfer').disabled = !(call && call.direction === 'inbound' && session.mode === 'account');
    $('btn-transfer').title = $('btn-transfer').disabled ? 'Transfer works on inbound calls' : 'Transfer to another agent';
    if (call && !call.lookup) {
      show('customer-card', true);
      text('cust-name', 'Searching Close…');
      text('cust-number', call.number);
      text('cust-note', '');
      $('cust-convs').innerHTML = '';
      show('cust-link', false);
    }
  }

  function endCall(msg) {
    stopRing();
    stopTimer();
    var c = call;
    rtc = null;
    call = null;
    show('incoming', false);
    show('btn-call', true);
    show('btn-hangup', false);
    show('call-status', false);
    show('call-controls', false);
    show('controls-hint', false);
    show('transfer-box', false);
    show('customer-card', false);
    $('remote-audio').srcObject = null;
    setStatus(registered ? 'ok' : 'off', registered ? 'Ready' : 'Offline');
    updateDialState();
    if (!c) return;
    var secs = c.answeredAt ? Math.round((Date.now() - c.answeredAt) / 1000) : 0;
    var outcome = c.answeredAt ? clock(secs) : msg;
    if (!c.answeredAt) notice(msg, msg === 'Call ended' ? 'info' : 'warn');
    else notice((c.direction === 'inbound' ? 'Inbound' : 'Outbound') + ' call with ' + displayName(c) + ' · ' + outcome, 'info');
    // The list itself refreshes when the backend says the call is logged.
    // ClickUp pattern: a completion popup for answered inbound calls.
    if (c.direction === 'inbound' && c.answeredAt) showCallDone(c, secs);
  }

  function startTimer() {
    stopTimer();
    timerHandle = setInterval(function () {
      if (call && call.answeredAt) text('call-timer', clock((Date.now() - call.answeredAt) / 1000));
    }, 1000);
  }
  function stopTimer() { if (timerHandle) { clearInterval(timerHandle); timerHandle = null; } }

  $('btn-hangup').onclick = function () { if (rtc) { try { rtc.terminate(); } catch (e) { endCall('Call ended'); } } };

  $('btn-mute').onclick = function () {
    if (!rtc) return;
    var on = this.getAttribute('aria-pressed') !== 'true';
    if (on) rtc.mute({ audio: true }); else rtc.unmute({ audio: true });
    this.setAttribute('aria-pressed', String(on));
    this.querySelector('span').textContent = on ? 'Unmute' : 'Mute';
  };

  $('btn-hold').onclick = function () {
    if (!rtc) return;
    var on = this.getAttribute('aria-pressed') !== 'true';
    var ok = on ? rtc.hold() : rtc.unhold();
    if (ok === false) { notice('Hold is not available right now.', 'warn'); return; }
    this.setAttribute('aria-pressed', String(on));
    this.querySelector('span').textContent = on ? 'Resume' : 'Hold';
    text('call-state', on ? 'On hold · ' + displayName(call) : 'On a call with ' + displayName(call));
  };

  $('btn-transfer').onclick = function () {
    var btn = this;
    if (!$('transfer-box').hidden) { show('transfer-box', false); btn.setAttribute('aria-expanded', 'false'); return; }
    api('/agents').then(function (r) {
      var sel = $('sel-transfer');
      sel.innerHTML = '';
      if (!r.agents.length) { notice('No other agent is signed in to take a transfer.', 'warn'); return; }
      r.agents.forEach(function (a) { var o = document.createElement('option'); o.value = a.userId; o.textContent = a.name; sel.appendChild(o); });
      show('transfer-box', true);
      btn.setAttribute('aria-expanded', 'true');
    }).catch(function (err) { notice(err.message, 'error'); });
  };
  $('btn-transfer-go').onclick = function () {
    var userId = $('sel-transfer').value;
    if (!userId) return;
    api('/transfer', { body: { userId: userId } })
      .then(function () { notice('Transferring the caller. Your line drops when they answer.', 'info'); show('transfer-box', false); })
      .catch(function (err) { notice(err.message, 'error'); });
  };

  // ─── keypad: digits before a call, tones during one ────────────────────────

  var dtmfCtx = null;
  var DTMF_FREQS = {
    '1': [697, 1209], '2': [697, 1336], '3': [697, 1477],
    '4': [770, 1209], '5': [770, 1336], '6': [770, 1477],
    '7': [852, 1209], '8': [852, 1336], '9': [852, 1477],
    '*': [941, 1209], '0': [941, 1336], '#': [941, 1477],
  };

  function playTone(key) {
    var f = DTMF_FREQS[key];
    if (!f) return;
    try {
      if (!dtmfCtx) dtmfCtx = new (window.AudioContext || window.webkitAudioContext)();
      if (dtmfCtx.state === 'suspended') dtmfCtx.resume();
      var g = dtmfCtx.createGain();
      g.gain.value = 0.04;
      g.connect(dtmfCtx.destination);
      f.forEach(function (hz) {
        var o = dtmfCtx.createOscillator();
        o.frequency.value = hz;
        o.connect(g);
        o.start();
        o.stop(dtmfCtx.currentTime + 0.12);
      });
      g.gain.exponentialRampToValueAtTime(0.0001, dtmfCtx.currentTime + 0.12);
    } catch (e) { /* ignore */ }
  }

  document.querySelectorAll('#main-keypad .keypad-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var k = btn.dataset.key;
      playTone(k);
      if (rtc && call && call.answeredAt) {
        try { rtc.sendDTMF(k); } catch (err) { /* ignore */ }
        return;
      }
      var input = $('in-dial');
      input.value += k;
      input.focus();
    });
  });

  // ─── caller lookup (screen pop) ────────────────────────────────────────────

  function lookup(number) {
    var c = call;
    api('/lookup?number=' + encodeURIComponent(number)).then(function (r) {
      if (!c || c !== call) return;
      var first = r.people[0];
      c.lookup = { name: first ? first.name : '', url: first && first.url };
      var sub = first ? [first.jobTitle, first.company !== first.name ? first.company : '', first.status].filter(Boolean).join(' · ') : '';
      // Incoming banner.
      text('in-name', first ? first.name : 'Unknown caller');
      text('in-number', r.number + (sub ? ' · ' + sub : ''));
      drawRecent($('in-convs'), r.recent);
      // Contact card.
      show('customer-card', true);
      text('cust-name', first ? first.name : 'No Close contact has this number');
      text('cust-number', r.number + (sub ? ' · ' + sub : ''));
      text('cust-note', first
        ? (r.people.length > 1 ? r.people.length + ' contacts have this number; the call is logged on the first.' : '')
        : 'A lead is created when the call is logged, unless Settings turn that off.');
      drawRecent($('cust-convs'), r.recent);
      if (c.lookup.url) { $('cust-link').href = c.lookup.url; show('cust-link', true); } else show('cust-link', false);
      if (c.answeredAt || c.direction === 'outbound') text('call-state', (c.answeredAt ? 'On a call with ' : 'Calling ') + displayName(c));
    }).catch(function (err) {
      if (!c || c !== call) return;
      text('cust-name', err.data && err.data.code === 'close_reconnect' ? 'Reconnect Close to look callers up' : 'Could not search Close');
      text('cust-note', 'The call is still logged when it ends.');
    });
  }

  function callLabel(x) {
    var when = x.startedAt ? new Date(x.startedAt).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '';
    var outcome = x.outcome === 'answered' ? clock(x.talkSeconds) : String(x.outcome || '').replace('-', ' ');
    return (x.direction === 'inbound' ? 'Inbound' : 'Outbound') + ' · ' + outcome + (when ? ' · ' + when : '');
  }

  /** The caller's last calls through this softphone, for the ringing card. */
  function drawRecent(ul, recent) {
    ul.innerHTML = '';
    (recent || []).forEach(function (x) {
      var li = document.createElement('li');
      var s = document.createElement('span'); s.textContent = callLabel(x); li.appendChild(s);
      ul.appendChild(li);
    });
  }

  // ─── call finished popup ───────────────────────────────────────────────────

  function setDoneCrm(state, msg) {
    $('call-done-crm').dataset.state = state;
    text('call-done-crm-text', msg);
  }

  function showCallDone(c, secs) {
    doneCall = c;
    text('call-done-badge', 'Inbound call completed');
    text('call-done-caller', displayName(c) === c.number ? c.number : displayName(c) + ' · ' + c.number);
    text('call-done-duration', clock(secs));
    text('call-done-time', new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    setDoneCrm('pending', 'Logging to Close…');
    show('call-done-link', false);
    show('call-done', true);
    $('call-done-dismiss').focus();
  }
  $('call-done-dismiss').onclick = function () { show('call-done', false); doneCall = null; };
  $('call-done').addEventListener('click', function (e) { if (e.target === this) { show('call-done', false); doneCall = null; } });

  // ─── calls this session ────────────────────────────────────────────────────

  // Read from the backend, so recording links are always freshly signed.

  function markLogged(ev) {
    if (doneCall && !$('call-done').hidden) {
      if (ev.skipped) setDoneCrm('error', 'Not logged: unknown number, and creating leads is off');
      else setDoneCrm('ok', 'Logged to Close (' + ev.outcome + ')');
      if (ev.leadUrl) { $('call-done-link').href = ev.leadUrl; show('call-done-link', true); }
    }
    loadHistory();
  }

  function loadHistory() {
    if (!session) return;
    api('/calls').then(function (r) { drawActivity(r.calls || []); }).catch(function () { /* keep the old list */ });
  }

  function linkTo(href, label, title) {
    var a = document.createElement('a');
    a.className = 'history-open'; a.href = href; a.target = '_blank'; a.rel = 'noopener'; a.textContent = label; a.title = title;
    return a;
  }

  function drawActivity(calls) {
    var ul = $('activity');
    ul.innerHTML = '';
    if (!calls.length) {
      var e = document.createElement('li'); e.className = 'history-empty'; e.textContent = 'No calls yet.'; ul.appendChild(e);
      return;
    }
    calls.forEach(function (x) {
      var li = document.createElement('li');
      var info = document.createElement('div'); info.className = 'history-info';
      var who = document.createElement('span'); who.className = 'history-who'; who.textContent = x.contactName || x.remote;
      var meta = document.createElement('span'); meta.className = 'history-meta'; meta.textContent = callLabel(x);
      info.appendChild(who); info.appendChild(meta);
      li.appendChild(info);
      if (x.recordingUrl) li.appendChild(linkTo(x.recordingUrl, 'Play', 'Play the recording (a fresh, expiring link)'));
      if (x.leadUrl) li.appendChild(linkTo(x.leadUrl, 'Open', 'Open the lead in Close'));
      ul.appendChild(li);
    });
  }

  $('btn-refresh-history').onclick = loadHistory;

  // ─── caller ID and inbound ─────────────────────────────────────────────────

  $('sel-callerid').onchange = function () {
    var n = this.value;
    api('/select-number', { body: { number: n } }).then(function () { session.from = n; render(); }).catch(function (err) { notice(err.message, 'error'); });
  };

  $('btn-inbound').onclick = function () {
    var n = session.from;
    var current = session.numberApps && session.numberApps[n];
    if (current && current === session.appId) { notice('Inbound calls to ' + n + ' already ring this softphone.', 'ok'); return; }
    var msg = current
      ? 'Move ' + n + ' off Vobiz application ' + current + ' so its inbound calls ring here? Whatever that application did with calls stops.'
      : 'Route inbound calls to ' + n + ' to this softphone?';
    if (!window.confirm(msg)) return;
    api('/setup-inbound', { body: { number: n } }).then(function (r) {
      session.numberApps[n] = r.appId;
      renderNumbers();
      notice('Inbound calls to ' + n + ' now ring every signed-in agent.', 'ok');
    }).catch(function (err) { notice(err.message, 'error'); });
  };

  // ─── settings (per Close organization; admins change them) ───────────────────

  var SETTING_INPUTS = ['set-country', 'set-create', 'set-missed', 'set-autoopen', 'set-ttl', 'btn-save-settings'];

  $('btn-settings').onclick = function () {
    showView('settings');
    text('settings-who', 'Close organization ' + session.workspace.name + ' · ' + session.user.name + (session.user.admin ? ' (admin)' : ''));
    api('/settings').then(function (r) {
      $('set-country').value = r.settings.defaultCountry;
      $('set-create').checked = !!r.settings.createUnknown;
      $('set-missed').checked = !!r.settings.missedTask;
      $('set-autoopen').checked = !!r.settings.autoOpen;
      $('set-ttl').value = String(r.settings.recordingTtlSeconds);
      SETTING_INPUTS.forEach(function (id) { $(id).disabled = !r.admin; });
      text('settings-note', r.admin ? '' : 'Only a Close organization admin can change these.');
      show('btn-disconnect-company', r.admin);
    }).catch(function (err) { notice(err.message, 'error'); });
  };
  $('btn-settings-close').onclick = function () { showView('phone'); render(); };

  $('form-settings').onsubmit = function (e) {
    e.preventDefault();
    api('/settings', { body: {
      defaultCountry: $('set-country').value,
      createUnknown: $('set-create').checked,
      missedTask: $('set-missed').checked,
      autoOpen: $('set-autoopen').checked,
      recordingTtlSeconds: Number($('set-ttl').value),
    } }).then(function (r) {
      session.settings.autoOpen = r.settings.autoOpen;
      session.settings.defaultCountry = r.settings.defaultCountry;
      notice('Settings saved.', 'ok');
    }).catch(function (err) { notice(err.message, 'error'); });
  };

  function disconnect(scope) {
    var msg = scope === 'workspace'
      ? 'Disconnect this Close organization? Every agent is signed out and the calling service forgets the organization. Calls already in Close stay.'
      : 'Disconnect your Close user? Calls you take are logged by a colleague\'s connection until you connect again.';
    if (!window.confirm(msg)) return;
    api('/close/disconnect', { body: { scope: scope } }).then(function () { signedOut('Close disconnected.'); }).catch(function (err) { notice(err.message, 'error'); });
  }
  $('btn-disconnect-me').onclick = function () { disconnect('me'); };
  $('btn-disconnect-company').onclick = function () { disconnect('workspace'); };

  // ─── theme: follows the system unless the agent picks one ──────────────────

  try {
    var savedTheme = localStorage.getItem(THEME_KEY);
    if (savedTheme === 'light' || savedTheme === 'dark') document.documentElement.dataset.theme = savedTheme;
  } catch (e) { /* storage blocked */ }
  $('btn-theme').onclick = function () {
    var root = document.documentElement;
    var dark = root.dataset.theme ? root.dataset.theme === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
    try { localStorage.setItem(THEME_KEY, root.dataset.theme); } catch (e) { /* storage blocked */ }
  };

  window.addEventListener('beforeunload', function (e) { if (rtc) { e.preventDefault(); e.returnValue = ''; } });
  if (window.Notification && Notification.permission === 'default') {
    document.addEventListener('click', function ask() { document.removeEventListener('click', ask); try { Notification.requestPermission(); } catch (e) { /* ignore */ } });
  }

  boot();
})();
