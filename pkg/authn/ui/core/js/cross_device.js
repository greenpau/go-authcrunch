/* Cross-device browser login. Capabilities stay in this page's memory. */
(() => {
  'use strict';
  const base = document.currentScript.dataset.base.replace(/\/$/, '') + '/';
  const status = document.getElementById('cross-device-status');
  const details = document.getElementById('cross-device-details');
  const cancelButton = document.getElementById('cross-device-cancel');
  let request = null;
  let stopped = false;
  let timer;
  let expires = 0;
  const controller = new AbortController();
  const stop = (message) => {
    stopped = true;
    clearTimeout(timer);
    status.textContent = message;
    details.hidden = true;
    cancelButton.disabled = true;
    request = null;
  };
  const post = async (action, values = {}, signal = controller.signal, timeout = 10000) => {
    // Use the original AbortController API so embedded browsers do not need
    // AbortSignal.any/timeout. Release both the timer and listener on every exit.
    const operation = new AbortController();
    const abort = () => operation.abort();
    if (signal) {
      if (signal.aborted) abort();
      else signal.addEventListener('abort', abort, { once: true });
    }
    const deadline = setTimeout(abort, timeout);
    try {
      const response = await fetch(base + 'cross-device/' + action, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(values), signal: operation.signal,
      });
      const body = await response.json();
      if (!response.ok && !(response.status === 429 && body.status === 'slow_down')) throw new Error('unavailable');
      return body;
    } finally {
      clearTimeout(deadline);
      if (signal) signal.removeEventListener('abort', abort);
    }
  };
  const cancel = async () => {
    const pending = request;
    stop('Sign-in cancelled.');
    controller.abort();
    if (pending) {
      try { await post('cancel', { code: pending.code, secret: pending.secret }, null, 5000); } catch (_) { /* The server also expires abandoned requests. */ }
    }
  };
  cancelButton.addEventListener('click', cancel);
  window.addEventListener('pagehide', () => {
    if (!stopped) stop('This sign-in request ended. Return to sign in and try again.');
    controller.abort();
  });
  document.getElementById('cross-device-copy').addEventListener('click', async () => {
    if (stopped) return;
    const link = document.getElementById('cross-device-link');
    try {
      await navigator.clipboard.writeText(link.value);
      if (!stopped) status.textContent = 'Link copied. Waiting for approval…';
    } catch (_) {
      if (!stopped) { link.focus(); link.select(); status.textContent = 'Select and copy the sign-in link.'; }
    }
  });
  const poll = async () => {
    if (stopped) return;
    if (Date.now() >= expires) { stop('This sign-in request expired. Return to sign in and try again.'); return; }
    try {
      const response = await post('poll', { code: request.code, secret: request.secret });
      if (stopped) return;
      if (response.status === 'approved') {
        stop('Sign-in approved. Continuing…');
        window.location.assign(response.next);
        return;
      }
      if (response.status !== 'pending' && response.status !== 'slow_down') throw new Error('unavailable');
      timer = setTimeout(poll, 2000);
    } catch (_) {
      if (!stopped) stop('This sign-in request is no longer available. Return to sign in and try again.');
    }
  };
  (async () => {
    try {
      const result = await post('start');
      if (stopped) {
        try { await post('cancel', { code: result.code, secret: result.secret }, null, 5000); } catch (_) { /* Bounded server expiry. */ }
        return;
      }
      request = result;
      expires = Date.now() + result.expires_in * 1000;
      document.getElementById('cross-device-link').value = result.verification_uri;
      document.getElementById('cross-device-qr').src = result.qr;
      document.getElementById('cross-device-code').textContent = result.display_code;
      details.hidden = false;
      status.textContent = 'Waiting for sign-in and approval. This link expires in five minutes.';
      timer = setTimeout(poll, 2000);
    } catch (_) {
      if (!stopped) stop('Unable to start sign-in. Return to sign in and try again.');
    }
  })();
})();
