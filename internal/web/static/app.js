(() => {
  "use strict";

  const themeButton = document.querySelector("[data-theme-toggle]");
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
  let savedTheme;
  try { savedTheme = localStorage.getItem("git-proxy-theme"); } catch (_) { /* Storage can be unavailable in private contexts. */ }
  const applyTheme = theme => {
    document.documentElement.dataset.theme = theme;
    if (themeButton) themeButton.setAttribute("aria-label", `Switch to ${theme === "dark" ? "light" : "dark"} theme`);
  };
  applyTheme(savedTheme === "light" || savedTheme === "dark" ? savedTheme : (systemTheme.matches ? "dark" : "light"));
  themeButton?.addEventListener("click", () => {
    savedTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    applyTheme(savedTheme);
    try { localStorage.setItem("git-proxy-theme", savedTheme); } catch (_) { /* The current page still switches theme. */ }
  });
  systemTheme.addEventListener("change", event => { if (!savedTheme) applyTheme(event.matches ? "dark" : "light"); });

  const menu = document.querySelector("[data-menu-toggle]");
  menu?.addEventListener("click", () => {
    const expanded = menu.getAttribute("aria-expanded") !== "true";
    menu.setAttribute("aria-expanded", String(expanded));
    document.querySelector(".sidebar")?.classList.toggle("menu-open", expanded);
  });

  document.querySelectorAll("form[data-confirm]").forEach(form => {
    form.addEventListener("submit", event => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  const routeForm = document.querySelector("[data-route-form]");
  if (routeForm) {
    const owner = routeForm.querySelector("[name=user_id]");
    const keys = routeForm.querySelector("[data-key-picker]");
    const filterKeys = () => {
      for (const option of keys.options) {
        const unavailable = Boolean(option.dataset.owner && option.dataset.owner !== owner.value);
        option.hidden = unavailable;
        option.disabled = unavailable;
      }
      if (keys.selectedOptions[0]?.disabled) keys.value = "";
    };
    owner?.addEventListener("change", filterKeys);
    filterKeys();

    const host = routeForm.querySelector('[name=host]');
    const port = routeForm.querySelector('[name=port]');
    const fingerprint = routeForm.querySelector('[name=host_fingerprint]');
    const discover = routeForm.querySelector('[data-discover-host]');
    const status = routeForm.querySelector('[data-host-status]');
    const panel = routeForm.querySelector('[data-host-identity]');
    const useIdentity = routeForm.querySelector('[data-use-host-identity]');
    let identity;
    let request;
    const clearIdentity = () => {
      request?.abort();
      request = undefined;
      identity = undefined;
      panel.hidden = true;
      status.textContent = '';
      discover.disabled = false;
    };
    host.addEventListener('input', clearIdentity);
    port.addEventListener('input', clearIdentity);
    discover.addEventListener('click', async () => {
      clearIdentity();
      if (!host.reportValidity() || !port.reportValidity()) return;
      const controller = new AbortController();
      request = controller;
      discover.disabled = true;
      status.textContent = 'Connecting to upstream SSH server…';
      try {
        const response = await fetch('/api/host-identity', {
          method: 'POST', credentials: 'same-origin', signal: controller.signal,
          body: new URLSearchParams({host: host.value, port: port.value, csrf: routeForm.querySelector('[name=csrf]').value})
        });
        if (!response.ok) throw new Error((await response.text()).trim());
        const result = await response.json();
        if (request !== controller) return;
        identity = result;
        panel.querySelector('[data-host-address]').textContent = `${result.host}:${result.port}`;
        panel.querySelector('[data-host-algorithm]').textContent = result.algorithm;
        panel.querySelector('[data-host-fingerprint]').textContent = result.fingerprint;
        panel.querySelector('[data-host-public-key]').textContent = result.public_key;
        panel.querySelector('[data-host-comparison]').textContent = !fingerprint.value ? 'No fingerprint configured.' : fingerprint.value === result.fingerprint ? 'Matches the currently configured fingerprint.' : 'Differs from the currently configured fingerprint.';
        panel.hidden = false;
        status.textContent = 'Identity fetched. Review it before selecting.';
      } catch (error) {
        if (request === controller) status.textContent = `Could not fetch host identity: ${error.message}`;
      } finally {
        if (request === controller) { request = undefined; discover.disabled = false; }
      }
    });
    useIdentity.addEventListener('click', () => {
      if (!identity || identity.host !== host.value || identity.port !== Number(port.value)) return;
      fingerprint.value = identity.fingerprint;
      fingerprint.dispatchEvent(new Event('input', {bubbles: true}));
      status.textContent = 'Fingerprint selected. Save the route to apply it.';
      fingerprint.focus();
    });
  }

  document.querySelectorAll("[data-proxy-host]").forEach(node => {
    // Brackets keep IPv6 examples usable in SSH URLs.
    const hostname = window.location.hostname;
    node.textContent = hostname.includes(":") && !hostname.startsWith("[") ? `[${hostname}]` : hostname;
  });

  const activity = document.querySelector("[data-live-activity]");
  if (!activity) return;
  const body = document.getElementById("activity-body");
  const liveStatus = document.getElementById("live-status");
  const activeCount = document.getElementById("active-count");
  const dateFormat = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const bytes = value => {
    let n = Math.max(0, Number(value) || 0);
    const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let unit = 0;
    while (n >= 1024 && unit < units.length - 1) { n /= 1024; unit++; }
    return `${unit ? n.toFixed(1) : n} ${units[unit]}`;
  };
  const element = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  };
  const status = (text, state) => {
    liveStatus.replaceChildren(element("span", undefined, `status-dot${state === "error" ? " warning" : ""}`), document.createTextNode(text));
  };
  const render = events => {
    const fragment = document.createDocumentFragment();
    let active = 0;
    for (const event of events) {
      const row = element("tr");
      const repository = element("td");
      repository.append(element("strong", event.source, "mono"), element("small", event.destination, "mono"));
      if (event.error) repository.append(element("small", event.error, "text-error"));
      const operation = element("td");
      operation.append(element("span", event.operation, "badge neutral"));
      const traffic = element("td");
      traffic.append(element("span", `↑ ${bytes(event.bytes_out)}`, "mono"), element("small", `↓ ${bytes(event.bytes_in)}`, "mono"));
      const result = element("td");
      const running = !event.finished_at;
      if (running) active++;
      result.append(element("span", running ? "Active" : (event.status || (event.error ? "Failed" : "Completed")), `badge ${running ? "info" : event.error ? "danger" : "good"}`));
      const date = new Date(event.started_at);
      result.append(element("small", Number.isNaN(date.getTime()) ? "Unknown start time" : dateFormat.format(date)));
      row.append(repository, element("td", event.username), operation, traffic, result);
      fragment.append(row);
    }
    if (!events.length) {
      const row = element("tr");
      const cell = element("td");
      cell.colSpan = 5;
      const empty = element("div", undefined, "empty-state");
      empty.append(element("span", "⇄", "empty-icon"), element("h3", "Ready for your first connection"), element("p", "Add an SSH key and a repository route, then connect with agent forwarding. Git activity will appear here."));
      const link = element("a", "Configure a route →", "button secondary");
      link.href = "/mappings";
      empty.append(link);
      cell.append(empty);
      row.append(cell);
      fragment.append(row);
    }
    body.replaceChildren(fragment);
    activeCount.textContent = String(active);
  };
  let timer;
  let pending = false;
  let stopped = false;
  const refresh = async () => {
    if (pending || stopped || document.hidden) return;
    pending = true;
    const controller = new AbortController();
    const deadline = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch("/api/activity", { headers: { Accept: "application/json" }, cache: "no-store", credentials: "same-origin", signal: controller.signal });
      if (response.status === 401 || response.redirected) {
        stopped = true;
        status(" Session expired. Sign in to reconnect.", "error");
        const login = element("a", "Sign in", "text-link");
        login.href = "/login";
        liveStatus.append(document.createTextNode(" "), login);
        return;
      }
      if (!response.ok) throw new Error("Activity unavailable");
      const events = await response.json();
      if (!Array.isArray(events)) throw new Error("Invalid activity response");
      render(events);
      status(" Live · updates every 3s", "good");
    } catch (_) {
      status(" Reconnecting · showing last received activity", "error");
    } finally {
      clearTimeout(deadline);
      pending = false;
      if (!stopped && !document.hidden) timer = setTimeout(refresh, 3000);
    }
  };
  document.addEventListener("visibilitychange", () => {
    clearTimeout(timer);
    if (!document.hidden) refresh();
  });
  window.addEventListener("pagehide", () => { stopped = true; clearTimeout(timer); });
  refresh();
})();
