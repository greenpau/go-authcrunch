/* Cross-device browser login. Capabilities stay in this page's memory. */
(() => {
  'use strict';
  const messages = JSON.parse(document.currentScript.dataset.i18n || "{}");
  const t = (id, fallback) => messages[id] || fallback;
  const base = document.currentScript.dataset.base.replace(/\/$/, '') + '/';
  const returnURL = document.currentScript.dataset.returnUrl || '';
  const status = document.getElementById('cross-device-status');
  const details = document.getElementById('cross-device-details');
  const controls = document.getElementById('cross-device-controls');
  const copyButton = document.getElementById('cross-device-copy');
  const cancelButton = document.getElementById('cross-device-cancel');
  const heading = document.getElementById('cross-device-title');
  const initialHeading = heading && heading.textContent.trim();
  const titlePrefix = initialHeading && document.title.endsWith(initialHeading)
    ? document.title.slice(0, -initialHeading.length)
    : (document.title ? document.title + ' - ' : '');
  const recovery = document.getElementById('cross-device-recovery');
  // Filesystem templates from before the layout update retain the original
  // required IDs but do not have the new presentation wrappers.
  const copyStatus = document.getElementById('cross-device-copy-status') || status;
  const fallback = document.getElementById('cross-device-link-fallback');
  let request = null;
  let stopped = false;
  let timer;
  let expires = 0;
  const controller = new AbortController();
  const stop = (title, message, recover = true, focus = false) => {
    const active = document.activeElement;
    const moveFocus = focus || active === cancelButton || details.contains(active) || (controls && controls.contains(active));
    stopped = true;
    clearTimeout(timer);
    if (heading) heading.textContent = title;
    document.title = titlePrefix + title;
    status.textContent = message;
    details.hidden = true;
    if (controls) controls.hidden = true;
    cancelButton.disabled = true;
    cancelButton.hidden = true;
    if (recovery) recovery.hidden = !recover;
    // Keep keyboard focus visible when its control disappears. Leave focus on
    // surviving navigation alone during background polling updates.
    if (moveFocus) {
      const target = heading || status;
      target.tabIndex = -1;
      target.focus();
    }
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
      const destination = action === 'start' && returnURL ? '?redirect_url=' + encodeURIComponent(returnURL) : '';
      const response = await fetch(base + 'cross-device/' + action + destination, {
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
    stop(t("cross_device_cancelled_title", "Sign-in cancelled"), t("cross_device_cancelled", "This sign-in request has been cancelled. Start again when you’re ready."), true, true);
    controller.abort();
    if (pending) {
      try { await post('cancel', { code: pending.code, secret: pending.secret }, null, 5000); } catch (_) { /* The server also expires abandoned requests. */ }
    }
  };
  cancelButton.addEventListener('click', cancel);
  window.addEventListener('pagehide', () => {
    if (!stopped) stop(t("cross_device_ended_title", "Sign-in request ended"), t("cross_device_ended", "This sign-in request ended when you left the page. Start again to get a new code."));
    controller.abort();
  });
  copyButton.addEventListener('click', async () => {
    if (stopped || !request) return;
    const link = document.getElementById('cross-device-link');
    const active = document.activeElement;
    try {
      await navigator.clipboard.writeText(link.value);
      if (!stopped) {
        copyStatus.textContent = t("cross_device_copied", "Link copied. Open it on a device you trust.");
        copyStatus.hidden = false;
      }
    } catch (_) {
      if (!stopped) {
        if (fallback) fallback.hidden = false;
        // Permission prompts can outlast the user's next keyboard action.
        // Only select the fallback while focus is still where copying began.
        const select = document.activeElement === active;
        copyStatus.textContent = select
          ? t("cross_device_copy_selected", "Copy the selected link and open it on a device you trust.")
          : t("cross_device_copy_manual", "Copy the sign-in link and open it on a device you trust.");
        copyStatus.hidden = false;
        if (select) { link.focus(); link.select(); }
      }
    }
  });
  const poll = async () => {
    if (stopped) return;
    if (Date.now() >= expires) { stop(t("cross_device_expired_title", "Sign-in link expired"), t("cross_device_expired", "This sign-in link expired. Start again to get a new code.")); return; }
    try {
      const response = await post('poll', { code: request.code, secret: request.secret });
      if (stopped) return;
      if (response.status === 'approved') {
        stop(t("cross_device_approved_title", "Sign-in approved"), t("cross_device_continuing", "Sign-in approved. Continuing…"), false);
        window.location.assign(response.next);
        return;
      }
      if (response.status !== 'pending' && response.status !== 'slow_down') throw new Error('unavailable');
      timer = setTimeout(poll, 2000);
    } catch (_) {
      if (!stopped) stop(t("cross_device_unavailable_title", "Sign-in unavailable"), t("cross_device_unavailable", "This sign-in request is no longer available. Start again to get a new code."));
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
      copyButton.disabled = false;
      status.textContent = t("cross_device_waiting", "Waiting for approval. This link expires in five minutes.");
      timer = setTimeout(poll, 2000);
    } catch (_) {
      if (!stopped) stop(t("cross_device_start_failed_title", "Unable to start sign-in"), t("cross_device_start_failed", "Unable to start sign-in. Check your connection and try again."));
    }
  })();
})();
