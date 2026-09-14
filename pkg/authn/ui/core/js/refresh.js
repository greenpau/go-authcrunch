/**
 * Portal session coordination. Only expiry metadata is stored in JavaScript.
 * Bootstrap, refresh and logout share a Web Lock across tabs. Every rotation
 * names the session whose pending marker it owns. HTML is not session evidence.
 */
(() => {
  "use strict";
  const script = document.currentScript;
  const base = script.dataset.base.replace(/\/$/, "");
  const key = "authcrunch-session:" + base;
  const action = script.dataset.action || "refresh";
  const login = base + "/login?fresh=1";
  let flight;
  let timer;
  let ready;
  let activeSession;
  const read = () => JSON.parse(localStorage.getItem(key) || "null");
  const write = (state) => localStorage.setItem(key, JSON.stringify(state));
  const supported = () => {
    if (!navigator.locks) throw new Error("This browser requires signing in again to continue.");
    localStorage.getItem(key);
  };
  const uncertain = (state) => state && (state.pending || state.blocked);
  const hasSession = (state) => state && typeof state.session_id === "string" && state.session_id.length > 0;
  const signIn = () => new Error("Please sign in again to continue your session.");
  const schedule = (state) => {
    clearTimeout(timer);
    if (hasSession(state) && !uncertain(state) && Number.isFinite(state.access_expires_at) && action === "refresh") {
      timer = setTimeout(() => refresh().catch(showError), Math.max(1000, state.access_expires_at * 1000 - Date.now() - 30000));
    }
  };
  const showError = (err) => {
    clearTimeout(timer);
    const message = document.getElementById("session-message");
    if (message) message.textContent = err.message;
    window.dispatchEvent(new CustomEvent("authcrunch:reauthenticate", { detail: { login } }));
  };
  const post = (operation, sessionID) => {
    const headers = { "Content-Type": "application/json", "X-Authcrunch-Refresh": "1" };
    if (sessionID) headers["X-Authcrunch-Refresh-Session"] = sessionID;
    return fetch(base + "/api/" + operation, {
      method: "POST", credentials: "same-origin", cache: "no-store", headers, body: "{}"
    });
  };
  const initialize = async () => {
    supported();
    return navigator.locks.request(key, async () => {
      const state = read();
      activeSession = hasSession(state) ? state.session_id : undefined;
      // A current signed access cookie identifies a completed login. An HTML
      // data-session value may instead come from a delayed or restored document.
      const response = await fetch(base + "/whoami?probe=true", {
        credentials: "same-origin", cache: "no-store", headers: { "Accept": "application/json" }
      });
      if (response.ok) {
        const current = await response.json();
        if (current.authenticated !== true || typeof current.sid !== "string" || !current.sid || !Number.isFinite(current.exp)) throw signIn();
        if (uncertain(state) && (!hasSession(state) || state.session_id === current.sid)) throw signIn();
        const next = { session_id: current.sid, access_expires_at: current.exp };
        if (hasSession(state) && state.session_id === current.sid) {
          // The current signed access deadline is authoritative. Preserve only
          // the known absolute deadline for the same family.
          if (Number.isFinite(state.session_expires_at)) next.session_expires_at = state.session_expires_at;
        }
        write(next);
        activeSession = next.session_id;
        return next;
      }
      if (response.status !== 401 || uncertain(state)) throw signIn();
      // Access may have expired before the first portal visit. Obtain only the
      // current family ID, without consuming its credential. Never do this to
      // resolve a pending/blocked exchange, whose token may already be spent.
      const lookup = await post("refresh_session");
      if (!lookup.ok) throw signIn();
      const current = await lookup.json();
      if (!hasSession(current)) throw signIn();
      const next = { session_id: current.session_id, access_expires_at: 0 };
      write(next);
      activeSession = next.session_id;
      return next;
    });
  };
  const exchange = async (operation, force) => {
    supported();
    return navigator.locks.request(key, async () => {
      const state = read();
      if (operation === "refresh_token" && (!hasSession(state) || uncertain(state) || !Number.isFinite(state.access_expires_at))) throw signIn();
      if (operation === "refresh_token" && !force && state.access_expires_at * 1000 > Date.now() + 30000) {
        schedule(state);
        return state;
      }
      write({ ...state, pending: true });
      let response;
      try {
        // Bind the pending marker to the family the server may rotate. A login
        // can change cookies while this request is in flight outside this lock.
        response = await post(operation, operation === "refresh_token" ? state.session_id : undefined);
      } catch (_) {
        throw new Error("The session response was interrupted. Please sign in again.");
      }
      if (!response.ok) {
        write({ ...state, blocked: true });
        throw new Error(operation === "logout" ? "Sign out failed. Please try signing out again." : "Please sign in again to continue your session.");
      }
      const result = await response.json();
      if (operation === "logout") {
        if (result.logged_out !== true) throw new Error("Sign out was not confirmed. Please try signing out again.");
        write({ session_id: state && state.session_id, blocked: true });
        clearTimeout(timer);
      } else {
        if (result.session_id !== state.session_id || !Number.isFinite(result.access_expires_at) || !Number.isFinite(result.session_expires_at)) {
          throw new Error("The session response was incomplete. Please sign in again.");
        }
        const next = { session_id: result.session_id, access_expires_at: result.access_expires_at, session_expires_at: result.session_expires_at };
        write(next);
        schedule(next);
      }
      return result;
    });
  };
  const refresh = (force = false) => {
    if (!flight) {
      // Reconfirm access after a failed bootstrap so a real login in another tab
      // can restore this client even before its storage event is dispatched.
      // initialize never looks up or rotates an uncertain refresh credential.
      flight = ready.catch(() => { ready = initialize(); return ready; })
        .then(() => exchange("refresh_token", force)).finally(() => { flight = null; });
    }
    return flight;
  };
  // An explicit logout can still revoke an uncertain credential after bootstrap
  // refuses to rotate it. It shares the lock and never claims a failed logout.
  const logout = () => ready.catch(() => {}).then(() => exchange("logout", true));
  window.AuthCrunchSession = { refresh, logout };
  ready = initialize();
  ready.then(() => {
    if (action === "continue") refresh().then(() => window.location.replace(base + "/portal")).catch(showError);
    if (action === "refresh") schedule(read());
  }).catch(showError);
  const button = document.getElementById("session-logout");
  if (button) button.addEventListener("click", async () => {
    button.disabled = true;
    try { await logout(); window.location.assign(script.dataset.next || login); }
    catch (err) { showError(err); button.disabled = false; }
  });
  if (action === "refresh") {
    window.addEventListener("focus", () => refresh().catch(showError));
    window.addEventListener("storage", (event) => {
      if (event.key === key) {
        try {
          const state = read();
          schedule(state);
          if (hasSession(state) && !uncertain(state) && state.session_id !== activeSession) {
            // A different tab completed a new login. Reconfirm its cookie under
            // the lock before reviving this tab's previously rejected bootstrap.
            ready = initialize();
            ready.then(() => schedule(read())).catch(showError);
          }
        } catch (err) { showError(err); }
      }
    });
  }
})();
