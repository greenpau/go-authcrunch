(() => {
  "use strict";

  const BUNDLE_URL = "https://cdn.jsdelivr.net/npm/@scalar/api-reference@1.67.0/dist/browser/standalone.js";
  const BUNDLE_INTEGRITY =
    "sha384-6c7Vmx+i0yi8gBbltn0x1cavD+zsMGw2xmXXVyacPJLIGBxwaVimW5TW0WiW17Ir";
  const app = document.getElementById("app");

  const fail = (message, error) => {
    if (error) console.error(message, error);
    if (!app) return;
    const section = document.createElement("section");
    section.className = "scalar-load-error";
    const heading = document.createElement("h1");
    heading.textContent = "API reference unavailable";
    const detail = document.createElement("p");
    detail.textContent = message;
    section.append(heading, detail);
    app.replaceChildren(section);
  };

  if (!app) return;
  if (window.location.protocol === "file:") {
    fail("Run make serve-openapi and open the printed HTTP address.");
    return;
  }

  const SERVER_STORAGE_KEY = "authcrunch.openapi.portal-server";
  const validServerValue = (key, value) => {
    if (typeof value !== "string" || value.length > 2048) return false;
    if (key === "portalBasePath") return value === "" || /^\/(?!\/)[^?#\\\s]*$/.test(value);
    if (key !== "origin" || !/^https?:\/\/[^/?#\\\s]+$/i.test(value)) return false;
    try {
      const url = new URL(value);
      return !url.username && !url.password;
    } catch { return false; }
  };

  const restorePortalServer = (content, refresh) => {
    const server = content.servers?.find((server) => server.url === "{origin}{portalBasePath}");
    const variables = server?.variables;
    if (!variables?.origin || !variables?.portalBasePath) return;
    let saved;
    try { saved = JSON.parse(window.localStorage.getItem(SERVER_STORAGE_KEY)); } catch { /* storage can be disabled */ }
    const values = {};
    for (const key of ["origin", "portalBasePath"]) {
      if (validServerValue(key, saved?.[key])) variables[key].default = saved[key];
      values[key] = variables[key].default;
    }
    // Scalar leaves an empty variable unsubstituted. Omit that placeholder in
    // the viewer's copy while retaining its editable field. Rebuild only when
    // a committed edit switches between root and non-root mounts.
    const template = () => values.portalBasePath === "" ? "{origin}" : "{origin}{portalBasePath}";
    server.url = template();
    // Scalar's server-change callback only observes server selection. Its pinned
    // variable inputs emit DOM events; capture only the portal's two fields.
    // A portalBasePath sibling distinguishes the shared deployment form from
    // unrelated origin fields. Every operation inherits these server values.
    const remember = ({ target, type }) => {
      if (target?.tagName !== "INPUT") return;
      const match = target.id.match(/^(.*-)(origin|portalBasePath)$/);
      if (!match || !document.getElementById(`${match[1]}portalBasePath`)) return;
      const key = match[2];
      if (!validServerValue(key, target.value)) return;
      values[key] = target.value;
      try { window.localStorage.setItem(SERVER_STORAGE_KEY, JSON.stringify(values)); } catch { /* viewer still works */ }
      if (type === "change" && server.url !== template()) {
        server.url = template();
        for (const name of ["origin", "portalBasePath"]) variables[name].default = values[name];
        return refresh();
      }
    };
    app.addEventListener("input", remember);
    app.addEventListener("change", remember);
  };

  // The viewer receives a fresh object, so browser state cannot reuse an older
  // specification URL. No credentials or cookies are sent with the spec fetch.
  const loadSpecification = async () => {
    const url = new URL("./generated/openapi.json", window.location.href);
    url.searchParams.set("v", Date.now().toString(36));
    const response = await fetch(url, {
      cache: "no-store",
      credentials: "omit",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new Error(`OpenAPI request returned ${response.status}`);
    const content = await response.json();
    if (content.openapi !== "3.1.1" || !content.paths || !Array.isArray(content.tags)) {
      throw new Error("Invalid OpenAPI document");
    }
    return content;
  };

  const bundle = document.createElement("script");
  bundle.src = BUNDLE_URL;
  bundle.integrity = BUNDLE_INTEGRITY;
  bundle.crossOrigin = "anonymous";
  bundle.referrerPolicy = "no-referrer";
  bundle.addEventListener("load", async () => {
    try {
      if (!globalThis.Scalar?.createApiReference) throw new Error("Scalar API is unavailable");
      const content = await loadSpecification();
      let reference;
      restorePortalServer(content, async () => {
        if (!reference) return;
        const configuration = { ...reference.getConfiguration(), content: structuredClone(content) };
        // Updating content alone retains Scalar's loaded-document cache. A new
        // instance is needed only for this committed server-template change.
        try {
          reference.destroy();
          reference = await globalThis.Scalar.createApiReference("#app", configuration);
        } catch (error) {
          fail("Reload the page to restore the API reference and saved server settings.", error);
        }
      });
      const order = new Map(content.tags.map((tag, index) => [tag.name, index]));
      reference = await globalThis.Scalar.createApiReference("#app", {
        content,
        agent: { disabled: true },
        mcp: { disabled: true },
        telemetry: false,
        persistAuth: false,
        showDeveloperTools: "never",
        hideClientButton: true,
        defaultHttpClient: { targetKey: "shell", clientKey: "curl" },
        // Keep the client menu scoped to curl, PowerShell and these Python clients.
        // Recheck the pinned viewer's registry when upgrading Scalar.
        hiddenClients: {
          c: true, clojure: true, csharp: true, dart: true, fsharp: true,
          go: true, http: true, java: true, js: true, julia: true, kotlin: true,
          node: true, objc: true, ocaml: true, php: true,
          powershell: false,
          python: ["aiohttp", "httpx_async", "httpx_sync"],
          r: true, ruby: true, rust: true,
          shell: ["httpie", "wget"],
          swift: true,
        },
        modelsSectionLabel: "Schemas",
        orderSchemaPropertiesBy: "preserve",
        tagsSorter: (a, b) => (order.get(a.name) ?? Infinity) - (order.get(b.name) ?? Infinity),
        // No hosted proxy: requests obey the actual deployment's CORS policy.
      });
    } catch (error) {
      fail("Run make openapi, then reload. Check the browser console if rendering still fails.", error);
    }
  });
  bundle.addEventListener("error", (error) => {
    fail("The pinned Scalar viewer could not load. Check network access to jsDelivr and reload.", error);
  });
  document.head.append(bundle);
})();
