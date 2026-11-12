"use strict";
const $ = (s) => document.querySelector(s);
const fragment = new URLSearchParams(location.hash.slice(1));
if (fragment.has("token")) {
  sessionStorage.setItem("omamori-token", fragment.get("token"));
  history.replaceState(null, "", location.pathname + "#overview");
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
async function overview() {
  await render("Overview", async () => {
    const [runs, cases, jobs] = await Promise.all([
      api("runs?limit=50"),
      api("cases?limit=50"),
      api("jobs"),
    ]);
    const open = cases.filter((c) => c.status !== "closed").length;
    const active = jobs.filter((j) =>
      ["preparing", "ready", "running"].includes(j.state),
    );
    return node(
      "div",
      {},
      node(
        "section",
        { class: "hero" },
        node(
          "div",
          {},
          node("div", { class: "hero-label" }, "YOUR LOCAL DEFENSE WORKSPACE"),
          node("h2", {}, "Evidence, connected."),
          node(
            "p",
            {},
            "Follow the signals. Review checked findings. Build investigations with the evidence always one click away.",
          ),
        ),
        node("div", { class: "hero-mark", "aria-hidden": "true" }, "守"),
      ),
      node(
        "div",
        { class: "stats" },
        [
          ["Saved runs", runs.length, "Most recent 50 runs"],
          [
            "Observed events",
            runs.reduce((n, r) => n + r.event_count, 0),
            "Across these runs",
          ],
          [
            "Detected alerts",
            runs.reduce((n, r) => n + r.alert_count, 0),
            "Rule matches, not verdicts",
          ],
          ["Open investigations", open, "Among 50 recent cases"],
        ].map(([label, count, note]) =>
          node(
            "div",
            { class: "stat" },
            node("span", { class: "label" }, label),
            node("strong", {}, count.toLocaleString()),
            node("small", {}, note),
          ),
        ),
      ),
      active.length
        ? panel(
            "In progress",
            active.map((j) =>
              node(
                "div",
                { class: "status-line" },
                badge(j.state),
                link(j.message, "job/" + j.id),
              ),
            ),
          )
        : null,
      node(
        "section",
        { class: "panel" },
        node(
          "div",
          { class: "panel-head" },
          node("h2", {}, "Recent runs"),
          link("View all runs →", "runs"),
        ),
        runs.length
          ? runsTable(runs.slice(0, 6))
          : empty(
              "Your workspace is ready",
              "Start with local logs or a prepared Linux evidence folder. Every run preserves its provenance.",
              link("Create your first run →", "new"),
            ),
      ),
      node(
        "div",
        { class: "split" },
        panel(
          "Investigation flow",
          node(
            "div",
            {},
            node("h3", {}, "Collect → Detect → Review → Investigate"),
            node(
              "p",
              { class: "hint" },
              "Use local rules to find signals, ask the analyst for checked reviews, and attach relevant alerts to a case.",
            ),
            link("Browse investigations →", "cases"),
          ),
        ),
        panel(
          "Built around your evidence",
          node(
            "p",
            { class: "hint" },
            "The AI never executes tools. Source limits, rejected claims and uncertain timestamps remain visible alongside every review.",
          ),
        ),
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
            link("Start a run →", "new"),
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
        link("← Saved runs", "runs"),
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
            link("Search this run →", "search/" + id),
            link("Open timeline →", "timeline/" + id),
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
        link("Create a case →", "cases"),
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
        link("← Cases", "cases"),
        badge(c.status),
        link("Case timeline →", "timeline-case/" + id),
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
            link("New run →", "new"),
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
            link("Open saved run →", "run/" + j.run_id),
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
  const [page, id] = location.hash.slice(1).split("/");
  for (const a of document.querySelectorAll("nav a"))
    a.classList.toggle(
      "active",
      a.hash ===
        "#" +
          ({
            run: "runs",
            case: "cases",
            "timeline-case": "timeline",
            job: "activity",
          }[page] ||
            page ||
            "overview"),
    );
  switch (page) {
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
