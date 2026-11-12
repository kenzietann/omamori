"use strict";
const $ = (s) => document.querySelector(s);
const fragment = new URLSearchParams(location.hash.slice(1));
if (fragment.has("token")) {
  sessionStorage.setItem("omamori-token", fragment.get("token"));
  const view = fragment.get("view") || "overview";
  history.replaceState(
    null,
    "",
    location.pathname +
      "#" +
      (/^review\/[A-Za-z0-9_-]+\/a[0-9]+$/.test(view) ? view : "overview"),
  );
}
let token = sessionStorage.getItem("omamori-token") || "",
  config = {},
  generation = 0,
  poll;
const node = (tag, attrs = {}, ...children) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "text") e.textContent = v;
    else if (k === "value") e.value = v;
    else if (v !== false && v != null) e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c != null)
      e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
};
function notice(text) {
  $("#notice").hidden = !text;
  $("#notice").textContent = text || "";
}
async function api(path, method = "GET", body) {
  const res = await fetch("/api/" + path, {
    method,
    headers: {
      Authorization: "Bearer " + token,
      ...(method !== "GET" ? { "Content-Type": "application/json" } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
  });
  if (!res.ok) {
    let text = await res.text();
    if (res.status === 401)
      text =
        "Session access is missing or expired. Open the private dashboard link printed by Omamori in your terminal.";
    throw Error(text.trim());
  }
  return res.json();
}
const attempt = (fn) => async (event) => {
  try {
    notice("");
    await fn(event);
  } catch (e) {
    notice(e.message);
  }
};
const button = (text, fn, style = "secondary") =>
  node("button", { type: "button", class: style, onclick: attempt(fn) }, text);
const link = (text, hash) =>
  node("a", { class: "link", href: "#" + hash }, text);
const badge = (text) =>
  node(
    "span",
    { class: "badge " + String(text || "unknown").replace(/[^a-z_-]/g, "") },
    text || "unknown",
  );
const stamp = (value) =>
  value
    ? new Date(value).toLocaleString(undefined, { timeZoneName: "short" })
    : "—";
const short = (id) => (id ? id.slice(0, 13) + "…" : "—");
function kv(value) {
  return node(
    "dl",
    { class: "kv" },
    Object.entries(value || {}).flatMap(([k, v]) => [
      node("dt", {}, k),
      node(
        "dd",
        { class: "mono" },
        typeof v === "object" ? JSON.stringify(v, null, 2) : String(v ?? "—"),
      ),
    ]),
  );
}
function panel(title, body, action) {
  return node(
    "section",
    { class: "panel" },
    node("div", { class: "panel-head" }, node("h2", {}, title), action),
    node("div", { class: "panel-body" }, body),
  );
}
function empty(title, text, action) {
  return node(
    "div",
    { class: "empty" },
    node("h3", {}, title),
    node("p", {}, text),
    action,
  );
}
function table(headers, rows) {
  return node(
    "div",
    {
      class: "table-wrap",
      tabindex: 0,
      role: "region",
      "aria-label": "Scrollable evidence table",
    },
    node(
      "table",
      {},
      node(
        "thead",
        {},
        node(
          "tr",
          {},
          headers.map((x) => node("th", { scope: "col" }, x)),
        ),
      ),
      node(
        "tbody",
        {},
        rows.map((row) =>
          node(
            "tr",
            {},
            row.map((cell) => node("td", {}, cell)),
          ),
        ),
      ),
    ),
  );
}
function field(label, name, type = "text", value = "", extra = {}) {
  return node(
    "label",
    {},
    label,
    node("input", { name, type, value, ...extra }),
  );
}
function select(label, name, values, value = "") {
  return node(
    "label",
    {},
    label,
    node(
      "select",
      { name },
      values.map((v) =>
        node(
          "option",
          {
            value: Array.isArray(v) ? v[0] : v,
            selected: (Array.isArray(v) ? v[0] : v) === value,
          },
          Array.isArray(v) ? v[1] : v,
        ),
      ),
    ),
  );
}
const formValues = (form) => Object.fromEntries(new FormData(form));
function jsonDetails(title, value) {
  return node(
    "details",
    {},
    node("summary", {}, title),
    node("pre", {}, JSON.stringify(value, null, 2)),
  );
}
async function render(title, fn) {
  clearTimeout(poll);
  const current = ++generation;
  $("#page-title").textContent = title;
  $("#page-description").textContent =
    {
      "Alert review": "Review alerts with their source evidence in view.",
      "Saved runs": "Collection history, coverage and checked analysis.",
      "Search evidence": "Find records across your stored runs.",
      Cases: "Track investigations and their linked evidence.",
      "Case detail": "Keep notes and evidence together.",
      Timeline: "Inspect the order of recorded observations.",
      "New run": "Prepare a preview before starting work.",
      "Run activity": "Follow preparation, review and completion.",
    }[title] || "Inspect stored findings and source records.";
  $("#main").replaceChildren(
    node("p", { class: "hint" }, "Loading your workspace…"),
  );
  notice("");
  try {
    const content = await fn();
    if (current === generation) $("#main").replaceChildren(content);
  } catch (e) {
    if (current === generation) {
      notice(e.message);
      $("#main").replaceChildren(
        empty(
          "Could not load this view",
          "Your saved evidence has not been changed.",
          button("Try again", route),
        ),
      );
    }
  }
}
function runsTable(runs) {
  return table(
    ["Run", "Mode", "Events", "Alerts", "Recorded"],
    runs.map((r) => [
      node(
        "div",
        {},
        link(r.label || "Detection run", "run/" + r.id),
        node("div", { class: "mono subtle" }, short(r.id)),
      ),
      badge(r.mode),
      r.event_count.toLocaleString(),
      r.alert_count.toLocaleString(),
      stamp(r.made),
    ]),
  );
}
function alertRows(alerts) {
  return table(
    ["Severity", "Alert", "Evidence", "Fired"],
    alerts.map((a) => [
      badge(a.level),
      button(a.title, () => showAlert(a.run_id, a.id), "link"),
      node(
        "div",
        {},
        a.count + " events / hits",
        node(
          "div",
          { class: "subtle" },
          a.event_ids.length + " linked records",
        ),
      ),
      stamp(a.time),
    ]),
  );
}
function eventRows(events) {
  return table(
    ["Time", "Source", "Reference", "Context"],
    events.map((e) => [
      stamp(e.time),
      badge(e.source),
      button(e.ref, () => showEvent(e.run_id, e.id), "link"),
      node(
        "div",
        { class: "mono" },
        Object.entries(e.fields || {})
          .filter(([k]) =>
            [
              "action",
              "user",
              "src_ip",
              "host",
              "command",
              "signature",
            ].includes(k),
          )
          .map(([k, v]) => k + "=" + v)
          .join(" · ")
          .slice(0, 220),
      ),
    ]),
  );
}
let reviewRun = "",
  reviewSelected = "";
const severityOrder = ["critical", "high", "medium", "low", "informational"];
function svg(tag, attributes = {}, ...children) {
  const e = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attributes)) e.setAttribute(k, v);
  for (const c of children) e.append(c);
  return e;
}
function chartBar(value, max) {
  return svg(
    "svg",
    {
      viewBox: "0 0 200 9",
      "aria-hidden": "true",
      preserveAspectRatio: "none",
    },
    svg("rect", { class: "track", width: 200, height: 9, rx: 2 }),
    svg("rect", {
      class: "fill",
      width: max ? (200 * value) / max : 0,
      height: 9,
      rx: 2,
    }),
  );
}
function distributionChart(alerts) {
  const counts = OmamoriCharts.severityCounts(alerts);
  const max = Math.max(1, ...counts.map((x) => x[1]));
  const rows = node(
    "div",
    { class: "distribution" },
    counts.map(([level, count]) => {
      const row = node(
        "div",
        { class: "distribution-row" },
        node(
          "span",
          {},
          level === "informational"
            ? "Information"
            : level[0].toUpperCase() + level.slice(1),
        ),
        chartBar(count, max),
        node("strong", {}, count),
      );
      row.style.setProperty(
        "--severity",
        `var(--${level === "informational" ? "info" : level})`,
      );
      return row;
    }),
  );
  return node(
    "section",
    { class: "chart-panel" },
    node(
      "div",
      { class: "chart-heading" },
      node("h2", {}, "Alert severity"),
      node("span", {}, alerts.length + " displayed alerts"),
    ),
    rows,
  );
}
function activityChart(alerts) {
  if (!alerts.length)
    return node(
      "section",
      { class: "chart-panel" },
      node("div", { class: "chart-heading" }, node("h2", {}, "Alert activity")),
      empty(
        "No alert activity",
        "A chart appears when the selected run has alerts.",
      ),
    );
  const hour = 3600000;
  const { start, step, width, buckets } = OmamoriCharts.timeBuckets(alerts);
  const highest = Math.max(...buckets.map((b) => b.count), 1);
  const format = (t) =>
    new Date(t).toLocaleString(undefined, {
      timeZone: "UTC",
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  const bars = node(
    "div",
    { class: "histogram", "aria-label": "Alert count by observed time bucket" },
    buckets.map((b) => {
      const height = (80 * b.count) / highest;
      const image = svg(
        "svg",
        {
          viewBox: "0 0 40 90",
          role: "img",
          "aria-label": `${format(b.start)} to ${format(b.start + step * width)} UTC: ${b.count} alerts`,
        },
        svg("rect", { x: 5, y: 90 - height, width: 30, height: height, rx: 2 }),
      );
      const tick =
        step === hour
          ? String(new Date(b.start).getUTCHours()).padStart(2, "0") + ":00"
          : new Date(b.start).getUTCDate() +
            "/" +
            (new Date(b.start).getUTCMonth() + 1);
      return node(
        "div",
        { class: "bar" },
        node("span", {}, b.count),
        image,
        node("span", { class: "bar-tick" }, tick),
      );
    }),
  );
  return node(
    "section",
    { class: "chart-panel" },
    node(
      "div",
      { class: "chart-heading" },
      node("h2", {}, "Alert activity"),
      node(
        "span",
        {},
        width + (step === hour ? "-hour" : "-day") + " buckets · UTC",
      ),
    ),
    node(
      "div",
      {
        class: "chart-plot",
        tabindex: 0,
        role: "region",
        "aria-label": "Alert activity chart",
      },
      bars,
    ),
    node(
      "div",
      { class: "chart-labels" },
      node("span", {}, format(start)),
      node("span", {}, format(buckets.at(-1).start + step * width)),
    ),
    node(
      "details",
      {},
      node("summary", {}, "View chart data"),
      table(
        ["Bucket start (UTC)", "Bucket end (UTC)", "Alerts"],
        buckets.map((b) => [
          new Date(b.start).toISOString(),
          new Date(b.start + step * width).toISOString(),
          b.count,
        ]),
      ),
    ),
  );
}
async function overview() {
  await render("Alert review", async () => {
    const [runs, cases, jobs] = await Promise.all([
      api("runs?limit=50"),
      api("cases?limit=50"),
      api("jobs"),
    ]);
    if (!runs.length)
      return panel(
        "Your investigation workspace",
        empty(
          "Start with your evidence",
          "Prepare a detection or forensic run. Saved alerts, source records and charts will appear here.",
          link("Start a run", "new"),
        ),
      );
    let run = runs.find((r) => r.id === reviewRun);
    if (!run && reviewRun) {
      run = await api("runs/" + encodeURIComponent(reviewRun));
      runs.unshift(run);
    }
    run ||= runs[0];
    reviewRun = run.id;
    const alerts = await api(
      "alerts?run=" + encodeURIComponent(run.id) + "&limit=200",
    );
    alerts.sort(
      (a, b) =>
        severityOrder.indexOf(a.level) - severityOrder.indexOf(b.level) ||
        new Date(b.time) - new Date(a.time),
    );
    const scope = select(
      "Selected run",
      "review-run",
      runs.map((r) => [r.id, (r.label || r.mode) + " · " + stamp(r.made)]),
      run.id,
    );
    scope.querySelector("select").addEventListener(
      "change",
      attempt(async (e) => {
        reviewRun = e.target.value;
        reviewSelected = "";
        await overview();
      }),
    );
    const facts = node(
      "div",
      { class: "run-facts" },
      node(
        "span",
        {},
        node("strong", {}, run.event_count.toLocaleString()),
        "stored events",
      ),
      node(
        "span",
        {},
        node("strong", {}, run.alert_count.toLocaleString()),
        "alerts",
      ),
      node(
        "span",
        {},
        node("strong", {}, cases.filter((c) => c.status !== "closed").length),
        "open cases in recent 50",
      ),
    );
    const inspector = node("section", {
      class: "inspector",
      "aria-label": "Selected alert evidence",
    });
    const list = node("div", { class: "queue-list" });
    let request = 0,
      selection = 0;
    async function inspect(alert, focus = false) {
      reviewSelected = alert.id;
      history.replaceState(
        null,
        "",
        location.pathname + "#review/" + run.id + "/" + alert.id,
      );
      inspector.scrollTop = 0;
      const chosen = ++selection;
      for (const row of list.querySelectorAll("button"))
        row.setAttribute(
          "aria-pressed",
          String(row.dataset.alert === alert.id),
        );
      const ticket = ++request;
      inspector.replaceChildren(
        node("p", { class: "hint" }, "Loading selected evidence…"),
      );
      try {
        const a = await api("runs/" + run.id + "/alerts/" + alert.id);
        if (ticket !== request) return;
        const tabs = node("div", {
          class: "inspector-controls",
          role: "tablist",
          "aria-label": "Alert detail sections",
        });
        const body = node("div", {
          class: "inspector-body",
          role: "tabpanel",
          id: "review-panel",
          tabindex: 0,
        });
        async function show(which) {
          const revision = ++request;
          body.setAttribute("aria-labelledby", "review-tab-" + which);
          for (const tab of tabs.children) {
            tab.setAttribute(
              "aria-selected",
              String(tab.dataset.tab === which),
            );
            tab.tabIndex = tab.dataset.tab === which ? 0 : -1;
          }
          body.replaceChildren(node("p", { class: "hint" }, "Loading…"));
          if (which === "evidence") {
            const cited = Object.entries(a.payload?.analyst_evidence || {})
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([, id]) => id)
              .filter((id) => a.event_ids.includes(id));
            const ids = [...new Set(cited.length ? cited : a.event_ids)].slice(
              0,
              8,
            );
            const events = await Promise.all(
              ids.map((id) => api("runs/" + run.id + "/events/" + id)),
            ).catch((error) => {
              if (revision === request)
                body.replaceChildren(
                  node("p", { class: "warning" }, error.message),
                );
              return null;
            });
            if (!events || revision !== request) return;
            body.replaceChildren(
              node(
                "div",
                { class: "evidence-list" },
                events.map((e) =>
                  node(
                    "article",
                    { class: "evidence-entry" },
                    button(
                      (e.fields.event_id ? e.fields.event_id + " · " : "") +
                        (e.fields.action || e.source),
                      () => showEvent(run.id, e.id),
                      "link",
                    ),
                    node("p", {}, e.ref + " · " + stamp(e.time)),
                    node(
                      "p",
                      { class: "mono" },
                      [e.fields.user, e.fields.src_ip, e.fields.host]
                        .filter(Boolean)
                        .join(" · "),
                    ),
                  ),
                ),
              ),
              node(
                "p",
                { class: "hint" },
                "Showing " +
                  events.length +
                  " of " +
                  a.event_ids.length +
                  " retained evidence records.",
              ),
              button("Open alert details", () => showAlert(run.id, a.id)),
              node(
                "div",
                { class: "actions" },
                link("Open run timeline", "timeline/" + run.id),
              ),
            );
          } else if (which === "rule") {
            body.replaceChildren(
              kv({
                rule: a.rule,
                matched: a.count + " events / hits",
                first: stamp(a.first),
                last: stamp(a.last),
              }),
              jsonDetails("Rule metadata", a.payload || {}),
              node(
                "p",
                { class: "hint" },
                "A rule match does not establish malicious intent.",
              ),
            );
          } else {
            const checked = run.analysis?.analysis;
            const matches = (checked?.verified || []).filter((f) =>
              f.alerts.includes(a.id),
            );
            body.replaceChildren(
              ...(matches.length
                ? matches.map((f) =>
                    node(
                      "article",
                      { class: "claim" },
                      node("p", {}, f.summary),
                      f.weak_times
                        ? node(
                            "p",
                            { class: "warning" },
                            "Some times reflect a file’s last change.",
                          )
                        : null,
                      node(
                        "div",
                        { class: "actions" },
                        f.evidence.map((e) =>
                          button(
                            e.id,
                            () => showCitation(run.id, e.id),
                            "link",
                          ),
                        ),
                      ),
                    ),
                  )
                : [
                    node(
                      "p",
                      { class: "hint" },
                      "No checked AI claim is saved for this alert.",
                    ),
                  ]),
              link("Open full run review", "run/" + run.id),
            );
          }
        }
        for (const [id, label] of [
          ["evidence", "Evidence"],
          ["rule", "Rule details"],
          ["ai", "AI review"],
        ]) {
          const tab = button(label, () => show(id));
          tab.dataset.tab = id;
          tab.id = "review-tab-" + id;
          tab.setAttribute("role", "tab");
          tab.setAttribute("aria-controls", "review-panel");
          tabs.append(tab);
        }
        tabs.addEventListener("keydown", (e) => {
          if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key))
            return;
          e.preventDefault();
          const all = [...tabs.children];
          let index = all.indexOf(document.activeElement);
          index =
            e.key === "Home"
              ? 0
              : e.key === "End"
                ? all.length - 1
                : (index + (e.key === "ArrowRight" ? 1 : -1) + all.length) %
                  all.length;
          all[index].focus();
          all[index].click();
        });
        inspector.replaceChildren(
          node(
            "div",
            { class: "status-line" },
            badge(a.level),
            node("span", { class: "mono subtle" }, a.id),
          ),
          node("h2", {}, a.title),
          node(
            "p",
            { class: "identity" },
            Object.entries(a.group || {})
              .map(([k, v]) => k + "=" + v)
              .join(" · ") || a.rule,
          ),
          tabs,
          body,
        );
        await show("evidence");
        if (chosen === selection && matchMedia("(min-width:901px)").matches) {
          const selected = [...list.children].find(
            (row) => row.dataset.alert === a.id,
          );
          if (selected) {
            const top = selected.offsetTop - list.offsetTop;
            if (top < list.scrollTop) list.scrollTop = top;
            else if (
              top + selected.offsetHeight >
              list.scrollTop + list.clientHeight
            )
              list.scrollTop = top + selected.offsetHeight - list.clientHeight;
          }
        }
        if (
          focus &&
          chosen === selection &&
          matchMedia("(max-width:900px)").matches
        )
          inspector.scrollIntoView({
            block: "start",
            behavior: matchMedia("(prefers-reduced-motion:reduce)").matches
              ? "auto"
              : "smooth",
          });
      } catch (e) {
        if (chosen === selection)
          inspector.replaceChildren(node("p", { class: "warning" }, e.message));
      }
    }
    const filter = select("Severity", "severity", [
      ["", "All severities"],
      ...severityOrder,
    ]);

    const filterControl = filter.querySelector("select");
    filterControl.setAttribute("aria-label", "Filter alert queue by severity");
    function fill() {
      const filtered = alerts.filter(
        (a) => !filterControl.value || a.level === filterControl.value,
      );
      list.replaceChildren(
        ...filtered.map((a) => {
          const row = button("", () => inspect(a, true), "alert-row");
          row.title = a.title;
          row.dataset.alert = a.id;
          row.setAttribute("aria-pressed", "false");
          const severity = node(
            "span",
            { class: "severity-label" },
            a.level === "informational" ? "Info" : a.level,
          );
          severity.style.setProperty(
            "--severity",
            `var(--${a.level === "informational" ? "info" : a.level})`,
          );
          row.append(
            severity,
            node(
              "span",
              {},
              node("span", { class: "row-title" }, a.title),
              node(
                "span",
                { class: "row-meta" },
                a.rule + " · " + a.count + " events / hits",
              ),
            ),
            node(
              "time",
              {},
              new Date(a.time).toLocaleTimeString(undefined, {
                hour: "2-digit",
                minute: "2-digit",
              }),
            ),
          );
          return row;
        }),
      );
      if (filtered.length)
        inspect(filtered.find((a) => a.id === reviewSelected) || filtered[0]);
      else {
        ++request;
        list.append(
          empty(
            "No alerts in this filter",
            "Choose another severity to continue.",
          ),
        );
        inspector.replaceChildren(
          empty("Select an alert", "Evidence appears beside the alert queue."),
        );
      }
    }
    filterControl.addEventListener("change", fill);
    fill();
    const active = jobs.filter((j) =>
      ["preparing", "ready", "running"].includes(j.state),
    );
    return node(
      "div",
      { class: "review-page" },
      node("div", { class: "scope-bar" }, scope, facts),
      node(
        "p",
        { class: "hint" },
        "Charts and queue cover the latest " +
          alerts.length +
          " of " +
          run.alert_count +
          " alerts in the selected run. " +
          (run.alert_count > alerts.length
            ? "Use Search evidence to page through the full run."
            : ""),
      ),
      node(
        "details",
        {
          class: "charts-disclosure",
          open: !matchMedia("(max-width:650px)").matches,
        },
        node("summary", {}, "Charts · " + alerts.length + " displayed alerts"),
        node(
          "div",
          { class: "charts-grid" },
          activityChart(alerts),
          distributionChart(alerts),
        ),
      ),
      active.length
        ? node(
            "div",
            { class: "toolbar" },
            ...active.map((j) => link(j.kind + ": " + j.state, "job/" + j.id)),
          )
        : null,
      node(
        "div",
        { class: "review-workspace" },
        node(
          "section",
          { class: "queue", "aria-label": "Alert queue" },
          node(
            "div",
            { class: "queue-head" },
            node("h2", {}, "Alerts"),
            filter,
          ),
          list,
        ),
        inspector,
      ),
      node(
        "div",
        { class: "actions" },
        link("Open selected run", "run/" + run.id),
        link("Search all evidence", "search/" + run.id),
      ),
    );
  });
}

async function listRuns(offset = 0) {
  await render("Saved runs", async () => {
    const runs = await api("runs?limit=25&offset=" + offset);
    return node(
      "section",
      { class: "panel" },
      node(
        "div",
        { class: "panel-head" },
        node("h2", {}, "Run history"),
        node("span", { class: "subtle" }, "Newest first"),
      ),
      runs.length
        ? runsTable(runs)
        : empty(
            "No runs on this page",
            "Runs saved by the CLI with --store appear here too.",
            link("Start a run", "new"),
          ),
      pager(offset, runs.length, 25, listRuns),
    );
  });
}
function pager(offset, count, size, load) {
  return node(
    "div",
    { class: "pager" },
    node(
      "span",
      { class: "subtle" },
      "Page " + (Math.floor(offset / size) + 1),
    ),
    node(
      "button",
      {
        type: "button",
        disabled: offset === 0,
        onclick: attempt(() => load(Math.max(0, offset - size))),
      },
      "Previous",
    ),
    node(
      "button",
      {
        type: "button",
        disabled: count < size,
        onclick: attempt(() => load(offset + size)),
      },
      "Next",
    ),
  );
}
async function runDetail(id) {
  await render("Run detail", async () => {
    const [r, alerts] = await Promise.all([
      api("runs/" + id),
      api("alerts?run=" + id + "&limit=50"),
    ]);
    const a = r.analysis;
    return node(
      "div",
      {},
      node(
        "div",
        { class: "toolbar" },
        link("Saved runs", "runs"),
        badge(r.mode),
        node("span", { class: "mono subtle" }, r.id),
      ),
      panel(
        r.label || "Detection run",
        node(
          "div",
          {},
          kv({
            recorded: stamp(r.made),
            events: r.event_count,
            alerts: r.alert_count,
          }),
          node(
            "div",
            { class: "actions" },
            link("Search this run", "search/" + id),
            link("Open timeline", "timeline/" + id),
          ),
        ),
      ),
      panel(
        "Coverage and provenance",
        node(
          "div",
          {},
          node(
            "p",
            { class: "hint" },
            "Review omitted evidence and unread inputs before interpreting a quiet run.",
          ),
          jsonDetails("Collection coverage", r.coverage || {}),
        ),
      ),
      node(
        "section",
        { class: "panel" },
        node(
          "div",
          { class: "panel-head" },
          node("h2", {}, "Detected alerts"),
          node("span", { class: "subtle" }, "First 50 · severity in detail"),
        ),
        alerts.length
          ? alertRows(alerts)
          : empty(
              "No rule fired",
              "This does not establish that nothing happened. Review source coverage.",
            ),
      ),
      a
        ? panel(
            "Checked AI review",
            node(
              "div",
              {},
              node(
                "div",
                { class: "status-line" },
                badge(a.status),
                node("span", { class: "subtle" }, a.reason || ""),
              ),
              node(
                "p",
                { class: "hint" },
                "Only locally checked claims are findings. Suggested review steps are not executed.",
              ),
              (a.analysis?.verified || []).map((f) =>
                node(
                  "article",
                  { class: "claim" },
                  node("p", {}, f.summary),
                  f.weak_times
                    ? node(
                        "p",
                        { class: "warning" },
                        "Some timestamps describe a file’s last change, not the time an action happened.",
                      )
                    : null,
                  node(
                    "div",
                    { class: "actions" },
                    f.evidence.map((e) =>
                      button(
                        e.id + " · " + e.ref,
                        () => showCitation(id, e.id),
                        "link",
                      ),
                    ),
                  ),
                  node(
                    "ul",
                    {},
                    (f.suggested_actions || []).map((action) =>
                      node("li", {}, action.text),
                    ),
                  ),
                ),
              ),
              jsonDetails("Rejected claims, unreviewed alerts and limits", {
                rejected: a.analysis?.rejected,
                unreviewed: a.analysis?.unreviewed_alerts,
                coverage: a.analysis?.coverage,
              }),
            ),
          )
        : panel(
            "AI review",
            node(
              "p",
              { class: "hint" },
              "This run has no saved AI review. Its rule alerts and evidence remain available.",
            ),
          ),
    );
  });
}
async function modal(title, load) {
  $("#detail-title").textContent = title;
  $("#detail-body").replaceChildren(node("p", {}, "Loading evidence…"));
  if (!$("#detail").open) $("#detail").showModal();
  try {
    $("#detail-body").replaceChildren(await load());
  } catch (e) {
    $("#detail-body").replaceChildren(
      node("p", { class: "warning" }, e.message),
    );
  }
}
async function showEvent(run, id) {
  await modal("Event evidence", async () => {
    const e = await api("runs/" + run + "/events/" + id);
    return node(
      "div",
      {},
      node(
        "div",
        { class: "status-line" },
        badge(e.source),
        node("span", { class: "mono" }, e.id),
      ),
      kv({ time: stamp(e.time), reference: e.ref, run: e.run_id }),
      node("h3", { style: undefined }, "Event fields"),
      kv(e.fields),
    );
  });
}
async function showCitation(run, id) {
  const alert = id.split("_e")[0];
  const a = await api("runs/" + run + "/alerts/" + alert);
  const event = a.payload?.analyst_evidence?.[id];
  if (!event)
    throw Error(
      "This older run does not contain a full-event mapping for that citation.",
    );
  await showEvent(run, event);
}
async function showAlert(run, id) {
  await modal("Alert evidence", async () => {
    const [a, cases] = await Promise.all([
      api("runs/" + run + "/alerts/" + id),
      api("cases?limit=100"),
    ]);
    const links = node("div", { class: "actions" });
    let offset = 0;
    const more = button("More evidence", () => append());
    function append() {
      const end = Math.min(offset + 50, a.event_ids.length);
      for (; offset < end; offset++) {
        const event = a.event_ids[offset];
        links.append(button(event, () => showEvent(run, event), "link"));
      }
      more.hidden = offset >= a.event_ids.length;
    }
    append();
    const choose = select("Attach to a recent case", "case", [
      ["", "Choose a case"],
      ...cases.map((c) => [c.id, c.title]),
    ]);
    const attach = node(
      "form",
      {
        onsubmit: attempt(async (e) => {
          e.preventDefault();
          const selected = formValues(e.currentTarget).case;
          if (!selected) throw Error("Choose a case first.");
          await api("cases/" + selected + "/alerts", "POST", {
            run_id: run,
            alert_id: id,
          });
          $("#detail").close();
          location.hash = "case/" + selected;
        }),
      },
      choose,
      node(
        "div",
        { class: "actions" },
        node("button", { class: "primary", type: "submit" }, "Add to case"),
        link("Create a case", "cases"),
      ),
    );
    return node(
      "div",
      {},
      badge(a.level),
      node("h3", {}, a.title),
      kv({
        rule: a.rule,
        events_or_hits: a.count,
        first: stamp(a.first),
        last: stamp(a.last),
        run: a.run_id,
      }),
      jsonDetails("Group and rule metadata", {
        group: a.group,
        payload: a.payload,
      }),
      node("h3", {}, "Linked evidence (" + a.event_ids.length + ")"),
      links,
      more,
      node(
        "p",
        { class: "hint" },
        "These are retained evidence links; event counts can exceed the displayed evidence.",
      ),
      attach,
    );
  });
}
function searchPage(run = "") {
  let saved = { run },
    offset = 0;
  render("Search evidence", async () => {
    const form = node(
      "form",
      { class: "form-grid" },
      select("Record type", "kind", [
        ["events", "Events"],
        ["alerts", "Alerts"],
      ]),
      field("Text contains", "text"),
      field("Source", "source"),
      field("Run ID", "run", "text", run),
      field("Exact field", "field"),
      field("Exact value", "value"),
      field("Rule name", "rule"),
      field("Case ID", "case"),
      select("Severity", "level", [
        ["", "All levels"],
        "critical",
        "high",
        "medium",
        "low",
        "informational",
      ]),
      field("From (RFC3339)", "from", "text", "", {
        placeholder: "2026-11-10T00:00:00Z",
      }),
      field("To (RFC3339)", "to"),
      node(
        "div",
        { class: "wide actions" },
        node("button", { type: "submit", class: "primary" }, "Search"),
      ),
    );
    const results = node("div");
    async function load(start = 0) {
      offset = start;
      const params = new URLSearchParams({ ...saved, limit: 25, offset });
      params.delete("kind");
      const rows = await api((saved.kind || "events") + "?" + params);
      results.replaceChildren(
        node(
          "section",
          { class: "panel" },
          rows.length
            ? saved.kind === "alerts"
              ? alertRows(rows)
              : eventRows(rows)
            : empty(
                "No matching evidence",
                "Try a broader time range or fewer filters.",
              ),
          pager(offset, rows.length, 25, load),
        ),
      );
    }
    form.addEventListener(
      "submit",
      attempt(async (e) => {
        e.preventDefault();
        saved = formValues(form);
        await load();
      }),
    );
    await load();
    return node(
      "div",
      {},
      panel(
        "Find the evidence you need",
        node(
          "div",
          {},
          node(
            "p",
            { class: "hint" },
            "Text search is literal. Field/value filters match exact stored values. Times include their zone.",
          ),
          form,
        ),
      ),
      results,
    );
  });
}
async function casesPage() {
  await render("Cases", async () => {
    const cases = await api("cases?limit=100");
    const form = node(
      "form",
      {
        class: "form-grid",
        onsubmit: attempt(async (e) => {
          e.preventDefault();
          const c = await api("cases", "POST", {
            ...formValues(e.currentTarget),
            status: "open",
          });
          location.hash = "case/" + c.id;
        }),
      },
      field("Case title", "title", "text", "", {
        required: true,
        maxlength: 500,
      }),
      node(
        "label",
        { class: "wide" },
        "Notes",
        node("textarea", {
          name: "notes",
          placeholder: "What are you investigating?",
        }),
      ),
      node(
        "div",
        { class: "wide" },
        node("button", { class: "primary", type: "submit" }, "Create case"),
      ),
    );
    return node(
      "div",
      {},
      node(
        "section",
        { class: "panel" },
        node(
          "div",
          { class: "panel-head" },
          node("h2", {}, "Investigations"),
          node("span", { class: "subtle" }, "100 most recently updated"),
        ),
        cases.length
          ? table(
              ["Case", "Status", "Alerts", "Updated"],
              cases.map((c) => [
                link(c.title, "case/" + c.id),
                badge(c.status),
                c.alerts.length,
                stamp(c.updated),
              ]),
            )
          : empty(
              "No investigations yet",
              "Create a case, then attach relevant alerts from any saved run.",
            ),
      ),
      panel("Start an investigation", form),
    );
  });
}
async function caseDetail(id) {
  await render("Case detail", async () => {
    const c = await api("cases/" + id);
    const alerts = await api("alerts?case=" + id + "&limit=100");
    const form = node(
      "form",
      {
        class: "form-grid",
        onsubmit: attempt(async (e) => {
          e.preventDefault();
          await api("cases/" + id, "PATCH", {
            ...formValues(e.currentTarget),
            version: c.version,
          });
          await caseDetail(id);
        }),
      },
      field("Title", "title", "text", c.title, {
        required: true,
        maxlength: 500,
      }),
      select("Status", "status", ["open", "investigating", "closed"], c.status),
      node(
        "label",
        { class: "wide" },
        "Notes",
        node("textarea", { name: "notes" }, c.notes),
      ),
      node(
        "div",
        { class: "wide actions" },
        node("button", { type: "submit", class: "primary" }, "Save changes"),
        node(
          "span",
          { class: "subtle" },
          "Version " + c.version + " · stale changes are refused",
        ),
        button("Reload", () => caseDetail(id)),
      ),
    );
    const attach = node(
      "form",
      {
        class: "form-grid",
        onsubmit: attempt(async (e) => {
          e.preventDefault();
          const input = formValues(e.currentTarget);
          await api("cases/" + id + "/alerts", "POST", input);
          await caseDetail(id);
        }),
      },
      field("Run ID", "run_id", "text", "", { required: true }),
      field("Alert ID", "alert_id", "text", "a1", { required: true }),
      node(
        "div",
        { class: "actions" },
        node("button", { type: "submit" }, "Attach alert"),
      ),
    );
    return node(
      "div",
      {},
      node(
        "div",
        { class: "toolbar" },
        link("Cases", "cases"),
        badge(c.status),
        link("Case timeline", "timeline-case/" + id),
      ),
      panel(c.title, form),
      panel(
        "Linked alerts",
        alerts.length
          ? node(
              "div",
              {},
              alertRows(alerts),
              ...alerts.map((a) =>
                node(
                  "div",
                  { class: "actions" },
                  node("span", { class: "subtle" }, a.title),
                  button("Detach", async () => {
                    await api("cases/" + id + "/alerts", "DELETE", {
                      run_id: a.run_id,
                      alert_id: a.id,
                    });
                    await caseDetail(id);
                  }),
                ),
              ),
            )
          : empty(
              "No alerts attached",
              "Open an alert and add it to this case, or use its run and alert IDs below.",
            ),
      ),
      panel("Attach by reference", attach),
    );
  });
}
function timelinePage(run = "", caseID = "") {
  let saved = { run, case: caseID };
  render("Timeline", async () => {
    const form = node(
      "form",
      { class: "form-grid" },
      field("Run ID", "run", "text", run),
      field("Case ID", "case", "text", caseID),
      field("Text contains", "text"),
      field("From (RFC3339)", "from"),
      field("To (RFC3339)", "to"),
      node(
        "div",
        { class: "actions" },
        node("button", { type: "submit", class: "primary" }, "Update timeline"),
      ),
    );
    const result = node("div");
    async function load(offset = 0) {
      const rows = await api(
        "timeline?" + new URLSearchParams({ ...saved, limit: 50, offset }),
      );
      result.replaceChildren(
        node(
          "section",
          { class: "panel" },
          rows.length
            ? table(
                ["Observed time", "Type", "Evidence", "Run"],
                rows.map((x) => [
                  stamp(x.time),
                  badge(x.alert?.level || x.kind),
                  button(
                    x.alert?.title || x.event?.ref || x.id,
                    () =>
                      x.kind === "alert"
                        ? showAlert(x.run_id, x.id)
                        : showEvent(x.run_id, x.id),
                    "link",
                  ),
                  link(short(x.run_id), "run/" + x.run_id),
                ]),
              )
            : empty(
                "No timeline entries",
                "Select a run, case, or time range with stored evidence.",
              ),
          pager(offset, rows.length, 50, load),
        ),
      );
    }
    form.addEventListener(
      "submit",
      attempt(async (e) => {
        e.preventDefault();
        saved = formValues(form);
        await load();
      }),
    );
    await load();
    return node(
      "div",
      {},
      panel(
        "Follow the sequence",
        node(
          "div",
          {},
          node(
            "p",
            { class: "hint" },
            "Oldest first. A case includes linked alerts and their retained evidence. Equal timestamps do not establish causation.",
          ),
          form,
        ),
      ),
      result,
    );
  });
}
async function newRun() {
  await render("New run", async () => {
    const form = node(
      "form",
      { class: "form-grid" },
      select("Run type", "kind", [
        ["detect", "Detect · local rules"],
        ["analyze", "Analyze · checked AI review"],
        ["forensics", "Forensics · local triage"],
        ["forensics-analyze", "Forensics + AI review"],
      ]),
      field("Evidence path", "path", "text", "", {
        required: true,
        placeholder: "logs or host/root",
      }),
      field("Rules folder (optional)", "rules", "text", "", {
        placeholder: "Use built-in rules",
      }),
      field("Log year", "year", "number", new Date().getFullYear(), {
        min: 1970,
        max: 2200,
      }),
      field(
        "Time zone",
        "timezone",
        "text",
        Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
      ),
      select("Log format", "format", [
        ["", "Auto detect"],
        "syslog",
        "web",
        "json",
        "suricata",
        "zeek",
        "wazuh",
        "windows",
      ]),
    );
    const ai = node(
      "div",
      { class: "wide form-grid", hidden: true },
      select(
        "AI provider",
        "provider",
        [
          ["", "Choose a provider"],
          ...config.providers.map((p) => [
            p.id,
            p.name + (p.local ? " · local" : ""),
          ]),
        ],
        config.provider,
      ),
      field("Model", "model", "text", config.model || ""),
      field(
        "Reasoning (optional)",
        "reasoning",
        "text",
        config.reasoning || "",
      ),
      node(
        "p",
        { class: "hint wide" },
        "Keys come from your environment or existing CLI key setup. No API key is entered in this page.",
      ),
    );
    const snapshots = node(
      "div",
      { class: "wide form-grid", hidden: true },
      field("Process snapshot (optional)", "processes", "text", "", {
        placeholder: "host/snapshots/ps.txt",
      }),
      field("Socket snapshot (optional)", "sockets", "text", "", {
        placeholder: "host/snapshots/ss.txt",
      }),
      node(
        "p",
        { class: "hint wide" },
        "Previously collected text snapshots only. No host commands are executed.",
      ),
    );
    form.append(
      ai,
      snapshots,
      node(
        "p",
        { class: "wide hint" },
        "Paths are relative to: " + config.root,
      ),
      node(
        "div",
        { class: "wide actions" },
        node("button", { class: "primary", type: "submit" }, "Prepare preview"),
        node(
          "span",
          { class: "subtle" },
          "No AI request or run output until you confirm.",
        ),
      ),
    );
    const changeKind = () => {
      ai.hidden = !form.elements.kind.value.includes("analyze");
      snapshots.hidden = !form.elements.kind.value.includes("forensics");
      for (const element of ai.querySelectorAll("input,select"))
        element.disabled = ai.hidden;
      for (const element of snapshots.querySelectorAll("input"))
        element.disabled = snapshots.hidden;
      form.elements.format.disabled = !snapshots.hidden;
    };
    form.elements.kind.addEventListener("change", changeKind);
    changeKind();
    form.elements.provider.addEventListener("change", () => {
      const p = config.providers.find(
        (p) => p.id === form.elements.provider.value,
      );
      form.elements.model.value = p?.model || "";
    });
    form.addEventListener(
      "submit",
      attempt(async (e) => {
        e.preventDefault();
        const input = formValues(form);
        input.year = Number(input.year);
        const j = await api("jobs", "POST", input);
        location.hash = "job/" + j.id;
      }),
    );
    return panel(
      "Start with a preview",
      node(
        "div",
        {},
        node(
          "p",
          { class: "hint" },
          "Read evidence from the approved root, inspect the preview, then confirm. Completed runs are saved to the configured store.",
        ),
        form,
      ),
    );
  });
}
async function activity() {
  await render("Run activity", async () => {
    const jobs = await api("jobs");
    return panel(
      "This dashboard session",
      jobs.length
        ? table(
            ["Type", "Status", "Progress", "Action"],
            jobs.map((j) => [
              j.kind,
              badge(j.state),
              j.message,
              link("Open", "job/" + j.id),
            ]),
          )
        : empty(
            "No active work",
            "Prepare a new run to inspect its preview.",
            link("New run", "new"),
          ),
    );
  });
}
async function jobPage(id) {
  await render("Run activity", async () => {
    const j = await api("jobs/" + id);
    const body = node(
      "div",
      {},
      node(
        "div",
        { class: "status-line" },
        badge(j.state),
        node("span", {}, j.message),
      ),
      j.consent ? node("p", {}, j.consent) : null,
      ...j.progress.map((p) => node("div", { class: "progress" }, p)),
      j.state === "ready"
        ? node(
            "div",
            {},
            node("h3", {}, "Exact request / local run preview"),
            node("pre", {}, j.preview),
            node(
              "div",
              { class: "actions" },
              button(
                "Confirm and run",
                async () => {
                  await api("jobs/" + id + "/confirm", "POST", {});
                  await jobPage(id);
                },
                "primary",
              ),
            ),
          )
        : null,
      ["preparing", "ready", "running"].includes(j.state)
        ? node(
            "div",
            { class: "actions" },
            button("Cancel run", async () => {
              await api("jobs/" + id + "/cancel", "POST", {});
              await jobPage(id);
            }),
          )
        : null,
      j.run_id
        ? node(
            "div",
            { class: "actions" },
            link("Open saved run", "run/" + j.run_id),
          )
        : null,
      j.saved_to
        ? node("p", { class: "mono subtle" }, "Reports: " + j.saved_to)
        : null,
    );
    if (["preparing", "running"].includes(j.state))
      poll = setTimeout(() => {
        if (location.hash === "#job/" + id) jobPage(id);
      }, 1200);
    return panel(j.kind, body);
  });
}
async function route() {
  if ($("#detail").open) $("#detail").close();
  const [page, id, alertID] = location.hash.slice(1).split("/");
  for (const a of document.querySelectorAll("nav a"))
    a.classList.toggle(
      "active",
      a.hash ===
        "#" +
          ({
            run: "runs",
            review: "overview",
            case: "cases",
            "timeline-case": "timeline",
            job: "activity",
          }[page] ||
            page ||
            "overview"),
    );
  switch (page) {
    case "overview":
      reviewRun = "";
      reviewSelected = "";
      return overview();
    case "review":
      reviewRun = id;
      reviewSelected = alertID;
      return overview();
    case "runs":
      return listRuns();
    case "run":
      return runDetail(id);
    case "search":
      return searchPage(id);
    case "cases":
      return casesPage();
    case "case":
      return caseDetail(id);
    case "timeline":
      return timelinePage(id);
    case "timeline-case":
      return timelinePage("", id);
    case "new":
      return newRun();
    case "activity":
      return activity();
    case "job":
      return jobPage(id);
    default:
      return overview();
  }
}
$(".skip").addEventListener("click", (event) => {
  event.preventDefault();
  $("#main").focus();
});
$("#close-detail").addEventListener("click", () => $("#detail").close());
window.addEventListener("hashchange", async () => {
  const access = new URLSearchParams(location.hash.slice(1));
  if (access.has("token")) {
    token = access.get("token");
    sessionStorage.setItem("omamori-token", token);
    history.replaceState(null, "", location.pathname + "#overview");
    try {
      config = await api("config");
    } catch (error) {
      notice(error.message);
      return;
    }
  }
  await route();
});
(async () => {
  try {
    config = await api("config");
    await route();
  } catch (e) {
    notice(e.message);
    $("#main").replaceChildren(
      empty(
        "Open your private workspace",
        "Use the dashboard link printed by the running Omamori command. Your session token never leaves this local server.",
      ),
    );
  }
})();

function applyTheme() {
  const dark = document.documentElement.dataset.theme === "dark";
  $("#theme-toggle").textContent = dark
    ? "Switch to light theme"
    : "Switch to dark theme";
  $("#theme-toggle").setAttribute("aria-pressed", String(dark));
  $("#brand-icon").src = dark ? "/icon.png" : "/icon-light.png";
  document.querySelector('meta[name="theme-color"]').content = dark
    ? "#151d20"
    : "#f2f3ef";
}
$("#theme-toggle").addEventListener("click", () => {
  const next =
    document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try {
    localStorage.setItem("omamori-theme", next);
  } catch {}
  const address = new URL(location.href);
  address.searchParams.delete("theme");
  history.replaceState(
    null,
    "",
    address.pathname + address.search + address.hash,
  );
  applyTheme();
});
applyTheme();
$("#menu-toggle").addEventListener("click", () => {
  const open = $("#mobile-nav").hidden;
  $("#mobile-nav").hidden = !open;
  $("#menu-toggle").setAttribute("aria-expanded", String(open));
});
$("#mobile-nav").addEventListener("click", (e) => {
  if (e.target.closest("a")) {
    $("#mobile-nav").hidden = true;
    $("#menu-toggle").setAttribute("aria-expanded", "false");
  }
});
