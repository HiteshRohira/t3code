// The admin console. Every value is rendered with textContent, never as HTML.
const view = document.getElementById("view");
const status = document.getElementById("status");
let me = { permissions: [] };

const can = (permission) => me.permissions.includes(permission);

async function api(path, options = {}) {
  const response = await fetch(`/v1/admin${path}`, {
    ...options,
    headers: { "content-type": "application/json", "x-t3e-admin": "1", ...options.headers },
  });
  if (response.status === 401) {
    location.href = "/admin/login";
    throw new Error("signed out");
  }
  const body = await response.json();
  if (!response.ok) throw new Error(body.message ?? `request failed (${response.status})`);
  return body;
}

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value !== undefined && value !== null) node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child !== null && child !== undefined)
      node.append(typeof child === "string" ? child : child);
  }
  return node;
}

const text = (value) => (value === null || value === undefined ? "—" : String(value));
const tokens = (value) =>
  value === null || value === undefined ? "unlimited" : Number(value).toLocaleString();

function table(headers, rows) {
  return el(
    "div",
    { class: "table" },
    el(
      "table",
      {},
      el(
        "thead",
        {},
        el(
          "tr",
          {},
          headers.map((h) => el("th", {}, h)),
        ),
      ),
      el("tbody", {}, rows),
    ),
  );
}

async function run(action, success) {
  status.textContent = "Working…";
  try {
    await action();
    status.textContent = success ?? "";
  } catch (error) {
    status.textContent = error.message;
  }
}

const parseModels = (value) => {
  const list = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  return list.length === 0 ? null : list;
};
const parseTokens = (value) => (value.trim() === "" ? null : Number(value));

const views = {
  async users() {
    const { users } = await api("/users");
    return table(
      ["Email", "Roles", "Team", "Status", "Tokens this month", "Models", ""],
      users.map((user) => {
        const roles = el("input", { value: user.roles.join(","), size: 18 });
        const team = el("input", { value: user.team ?? "", size: 10 });
        const limit = el("input", {
          value: user.monthlyTokens ?? "",
          size: 10,
          placeholder: "inherit",
        });
        const models = el("input", {
          value: (user.models ?? []).join(","),
          size: 16,
          placeholder: "inherit",
        });
        const editable = can("write:users");
        for (const input of [roles, team, limit, models])
          if (!editable) input.setAttribute("disabled", "");
        return el(
          "tr",
          {},
          el("td", {}, user.email),
          el("td", {}, roles),
          el("td", {}, team),
          el("td", {}, user.active ? "active" : "deactivated"),
          el("td", {}, `${tokens(user.budget.used)} / `, limit),
          el("td", {}, models),
          el(
            "td",
            { class: "row" },
            editable
              ? el(
                  "button",
                  {
                    onclick: () =>
                      run(async () => {
                        await api(`/users/${encodeURIComponent(user.id)}`, {
                          method: "PATCH",
                          body: JSON.stringify({
                            roles: roles.value
                              .split(",")
                              .map((r) => r.trim())
                              .filter(Boolean),
                            team: team.value.trim() || null,
                            monthlyTokens: parseTokens(limit.value),
                            models: parseModels(models.value),
                          }),
                        });
                        await show("users");
                      }, "Saved."),
                  },
                  "Save",
                )
              : null,
            editable
              ? el(
                  "button",
                  {
                    class: user.active ? "danger" : "",
                    onclick: () =>
                      run(async () => {
                        await api(`/users/${encodeURIComponent(user.id)}`, {
                          method: "PATCH",
                          body: JSON.stringify({ active: !user.active }),
                        });
                        await show("users");
                      }),
                  },
                  user.active ? "Deactivate" : "Reactivate",
                )
              : null,
          ),
        );
      }),
    );
  },

  async devices() {
    const { devices } = await api("/devices");
    return table(
      ["Device", "User", "Host", "Platform", "Version", "Last seen", "Expires", "Status", ""],
      devices.map((device) =>
        el(
          "tr",
          {},
          el("td", {}, el("code", {}, device.id.slice(0, 8))),
          el("td", {}, text(device.email)),
          el("td", {}, device.hostname),
          el("td", {}, device.platform),
          el("td", {}, text(device.clientVersion)),
          el("td", {}, text(device.lastSeenAt)),
          el("td", {}, device.expiresAt),
          el("td", {}, device.status),
          el(
            "td",
            {},
            can("revoke:devices") && device.revokedAt === null
              ? el(
                  "button",
                  {
                    class: "danger",
                    onclick: () =>
                      confirm(`Revoke ${device.hostname}? Its agents stop within a minute.`) &&
                      run(async () => {
                        await api(`/devices/${encodeURIComponent(device.id)}/revoke`, {
                          method: "POST",
                        });
                        await show("devices");
                      }, "Revoked."),
                  },
                  "Revoke",
                )
              : null,
          ),
        ),
      ),
    );
  },

  async teams() {
    const { teams } = await api("/teams");
    const name = el("input", { placeholder: "team name", size: 14 });
    const limit = el("input", { placeholder: "monthly tokens", size: 14 });
    const models = el("input", { placeholder: "models, e.g. claude-haiku-*", size: 24 });
    const save = (teamName, limitValue, modelValue) =>
      run(async () => {
        await api(`/teams/${encodeURIComponent(teamName)}`, {
          method: "PUT",
          body: JSON.stringify({
            monthlyTokens: parseTokens(limitValue),
            models: parseModels(modelValue),
          }),
        });
        await show("teams");
      }, "Saved.");
    return el(
      "div",
      {},
      table(
        ["Team", "Used this month", "Monthly limit", "Models", ""],
        teams.map((team) =>
          el(
            "tr",
            {},
            el("td", {}, team.name),
            el("td", {}, tokens(team.used)),
            el("td", {}, tokens(team.monthlyTokens)),
            el("td", {}, team.models === null ? "inherit" : team.models.join(", ")),
            el(
              "td",
              {},
              can("write:teams")
                ? el(
                    "button",
                    {
                      class: "danger",
                      onclick: () =>
                        run(async () => {
                          await api(`/teams/${encodeURIComponent(team.name)}`, {
                            method: "DELETE",
                          });
                          await show("teams");
                        }),
                    },
                    "Delete",
                  )
                : null,
            ),
          ),
        ),
      ),
      can("write:teams")
        ? el(
            "p",
            { class: "row" },
            name,
            limit,
            models,
            el(
              "button",
              {
                onclick: () =>
                  name.value.trim() && save(name.value.trim(), limit.value, models.value),
              },
              "Save team",
            ),
          )
        : null,
    );
  },

  async policy() {
    const { policy } = await api("/policy");
    const editor = el("textarea", { spellcheck: "false" });
    editor.value = JSON.stringify(
      policy?.document ?? {
        schemaVersion: 1,
        organization: me.organization,
        limits: { connect: false },
      },
      null,
      2,
    );
    if (!can("write:policy")) editor.setAttribute("readonly", "");
    return el(
      "div",
      {},
      el(
        "p",
        {},
        policy === null
          ? "No policy published yet. Devices use the bootstrap policy from their enterprise config."
          : `Version ${policy.version}, published ${policy.createdAt} by ${policy.createdBy}. Devices apply a new version when T3 Code restarts.`,
      ),
      editor,
      can("write:policy")
        ? el(
            "p",
            {},
            el(
              "button",
              {
                onclick: () =>
                  run(async () => {
                    const document = JSON.parse(editor.value);
                    const { version } = await api("/policy", {
                      method: "PUT",
                      body: JSON.stringify({ document }),
                    });
                    await show("policy");
                    status.textContent = `Published version ${version}.`;
                  }),
              },
              "Publish",
            ),
          )
        : null,
    );
  },

  async usage() {
    const month = new Date().toISOString().slice(0, 7);
    const { rows } = await api(`/usage?month=${month}`);
    return el(
      "div",
      {},
      el("p", {}, `Model usage for ${month}, from the gateway.`),
      table(
        ["Team", "User", "Model", "Requests", "Input tokens", "Output tokens"],
        rows.map((row) =>
          el(
            "tr",
            {},
            el("td", {}, text(row.team)),
            el("td", {}, row.email),
            el("td", {}, row.model),
            el("td", {}, String(row.requests)),
            el("td", {}, tokens(row.inputTokens)),
            el("td", {}, tokens(row.outputTokens)),
          ),
        ),
      ),
    );
  },

  async audit() {
    const { events } = await api("/audit?limit=500");
    return el(
      "div",
      {},
      el(
        "p",
        {},
        "Oldest first. Export everything as JSON lines from ",
        el("code", {}, "/v1/admin/audit.jsonl?after=0"),
        ".",
      ),
      table(
        ["#", "Occurred", "Type", "User", "Device", "Thread", "Detail"],
        events.map((event) =>
          el(
            "tr",
            {},
            el("td", {}, String(event.seq)),
            el("td", {}, event.occurredAt),
            el("td", {}, event.type),
            el("td", {}, el("code", {}, event.userId.slice(0, 8))),
            el("td", {}, el("code", {}, event.deviceId.slice(0, 8))),
            el("td", {}, text(event.threadId)),
            el(
              "td",
              {},
              el("code", {}, event.detail === undefined ? "" : JSON.stringify(event.detail)),
            ),
          ),
        ),
      ),
    );
  },
};

const NEEDS = {
  users: "read:directory",
  devices: "read:directory",
  teams: "read:directory",
  policy: "read:policy",
  usage: "read:usage",
  audit: "read:audit",
};

async function show(name) {
  for (const button of document.querySelectorAll("#tabs button")) {
    if (button.dataset.tab === name) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  try {
    view.replaceChildren(await views[name]());
    localStorageSet("tab", name);
  } catch (error) {
    view.replaceChildren(el("p", {}, error.message));
  }
}

function localStorageSet(key, value) {
  try {
    localStorage.setItem(`t3e:${key}`, value);
  } catch {
    // Storage can be unavailable; the tab is only a convenience.
  }
}

function localStorageGet(key) {
  try {
    return localStorage.getItem(`t3e:${key}`);
  } catch {
    return null;
  }
}

me = await api("/me");
document.getElementById("org").textContent = `${me.organization} · T3 Enterprise`;
document.getElementById("me").textContent = `${me.email} (${me.roles.join(", ")})`;
for (const button of document.querySelectorAll("#tabs button")) {
  if (!can(NEEDS[button.dataset.tab])) button.remove();
  else button.addEventListener("click", () => show(button.dataset.tab));
}
const remembered = localStorageGet("tab");
const first = document.querySelector("#tabs button")?.dataset.tab;
if (first !== undefined)
  await show(remembered !== null && can(NEEDS[remembered]) ? remembered : first);
