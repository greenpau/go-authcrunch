/**
 * Portal session coordination. Only expiry metadata is stored in JavaScript.
 * Refresh and logout share a Web Lock across tabs. An uncertain exchange is
 * never automatically retried: the server may already have rotated its token.
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
  const read = () => JSON.parse(localStorage.getItem(key) || "null");
  const write = (state) => localStorage.setItem(key, JSON.stringify(state));
  const supported = () => {
    if (!navigator.locks) throw new Error("This browser requires signing in again to continue.");
    // Do not silently fall back to uncoordinated requests if storage is blocked.
    localStorage.getItem(key);
  };
  const schedule = (state) => {
    clearTimeout(timer);
    if (state && !state.pending && !state.blocked && action === "refresh") {
      timer = setTimeout(() => refresh().catch(showError), Math.max(1000, state.access_expires_at * 1000 - Date.now() - 30000));
    }
  };
  const showError = (err) => {
    clearTimeout(timer);
    const message = document.getElementById("session-message");
    if (message) message.textContent = err.message;
    window.dispatchEvent(new CustomEvent("authcrunch:reauthenticate", { detail: { login } }));
  };
  const exchange = async (operation, force) => {
    supported();
    return navigator.locks.request(key, async () => {
      const state = read();
      if (operation === "refresh_token" && state && (state.pending || state.blocked)) {
        throw new Error("Please sign in again to continue your session.");
      }
      if (operation === "refresh_token" && !force && state && state.access_expires_at * 1000 > Date.now() + 30000) {
        schedule(state);
        return state;
      }
      write({ ...state, pending: true });
      // No retries, including on a lost response or a tab closing during fetch.
      let response;
      try {
        response = await fetch(base + "/api/" + operation, {
          method: "POST", credentials: "same-origin", cache: "no-store",
          headers: { "Content-Type": "application/json", "X-Authcrunch-Refresh": "1" },
          body: "{}"
        });
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
        write({ blocked: true });
        clearTimeout(timer);
      } else {
        if (!result.session_id || !Number.isFinite(result.access_expires_at) || !Number.isFinite(result.session_expires_at)) {
          throw new Error("The session response was incomplete. Please sign in again.");
        }
        // Persist only public session metadata, never response credentials.
        const next = { session_id: result.session_id, access_expires_at: result.access_expires_at, session_expires_at: result.session_expires_at };
        write(next);
        schedule(next);
      }
      return result;
    });
  };
  const refresh = (force = false) => {
    if (!flight) flight = exchange("refresh_token", force).finally(() => { flight = null; });
    return flight;
  };
  const logout = () => exchange("logout", true);
  window.AuthCrunchSession = { refresh, logout };
  try {
    supported();
    const state = read();
    const sessionID = script.dataset.session;
    if (sessionID && (!state || state.session_id !== sessionID)) {
      write({ session_id: sessionID, access_expires_at: Number(script.dataset.expires) });
    }
    const button = document.getElementById("session-logout");
    if (button) button.addEventListener("click", async () => {
      button.disabled = true;
      try { await logout(); window.location.assign(script.dataset.next || login); }
      catch (err) { showError(err); button.disabled = false; }
    });
    if (action === "continue") refresh().then(() => window.location.replace(base + "/portal")).catch(showError);
    if (action === "refresh") {
      schedule(read());
      window.addEventListener("focus", () => refresh().catch(showError));
      window.addEventListener("storage", (event) => { if (event.key === key) schedule(read()); });
    }
  } catch (err) { showError(err); }
})();
