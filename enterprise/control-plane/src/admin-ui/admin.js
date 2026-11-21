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
      ["Email", "Roles", "Team", "Region", "Status", "Tokens this month", "Models", ""],
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
        const region = el("select", {});
        for (const option of ["", ...me.regions]) {
          const node = el("option", { value: option }, option === "" ? "default" : option);
          if ((user.region ?? "") === option) node.setAttribute("selected", "");
          region.append(node);
        }
        const editable = can("write:users");
        for (const input of [roles, team, limit, models, region])
          if (!editable) input.setAttribute("disabled", "");
        return el(
          "tr",
          {},
          el("td", {}, user.email),
          el("td", {}, roles),
          el("td", {}, team),
          el("td", {}, region),
          el(
            "td",
            {},
            user.active ? "active" : "deactivated",
            user.legalHold ? el("span", { class: "tag" }, "legal hold") : null,
          ),
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
                            region: region.value || null,
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
            can("write:holds")
              ? el(
                  "button",
                  {
                    onclick: () =>
                      run(async () => {
                        if (user.legalHold) {
                          await api(`/legal-holds/${encodeURIComponent(user.id)}`, {
                            method: "DELETE",
                          });
                        } else {
                          const reason = prompt(`Why hold ${user.email}'s records?`);
                          if (!reason) return;
                          await api(`/legal-holds/${encodeURIComponent(user.id)}`, {
                            method: "PUT",
                            body: JSON.stringify({ reason }),
                          });
                        }
                        await show("users");
                      }),
                  },
                  user.legalHold ? "Release hold" : "Legal hold",
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
        [
          "Team",
          "User",
          "Model",
          "Region",
          "Requests",
          "Input tokens",
          "Output tokens",
          "Secrets redacted",
        ],
        rows.map((row) =>
          el(
            "tr",
            {},
            el("td", {}, text(row.team)),
            el("td", {}, row.email),
            el("td", {}, row.model),
            el("td", {}, text(row.region ?? "default")),
            el("td", {}, String(row.requests)),
            el("td", {}, tokens(row.inputTokens)),
            el("td", {}, tokens(row.outputTokens)),
            el("td", {}, String(row.redactions)),
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

const ago = (iso) => {
  if (iso === null || iso === undefined) return "never";
  const minutes = Math.round((Date.now() - Date.parse(iso)) / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  return hours < 48 ? `${hours} h ago` : `${Math.round(hours / 24)} d ago`;
};

/** A heartbeat older than this means T3 Code is closed or the machine is offline. */
const STALE_MINUTES = 15;

function fleetHealth(device) {
  if (device.status !== "active") return device.status.replace(/_/g, " ");
  const beat = device.heartbeat;
  if (beat === null) return "never reported";
  if ((Date.now() - Date.parse(beat.receivedAt)) / 60_000 > STALE_MINUTES) return "offline";
  if (beat.modelAccess !== "ok") return `models ${beat.modelAccess}`;
  if (beat.restartRequired) return "restart pending";
  return "healthy";
}

let activityTimer;

Object.assign(views, {
  async fleet() {
    const { devices } = await api("/devices");
    const live = devices.filter((device) => device.revokedAt === null);
    const versions = new Map();
    for (const device of live) {
      const version = device.heartbeat?.clientVersion ?? device.clientVersion ?? "unknown";
      versions.set(version, (versions.get(version) ?? 0) + 1);
    }
    return el(
      "div",
      {},
      el(
        "p",
        {},
        `${live.length} enrolled ${live.length === 1 ? "machine" : "machines"}. Versions: `,
        [...versions].map(([version, count]) => `${version} × ${count}`).join(", ") || "none",
        ".",
      ),
      table(
        ["Machine", "User", "Version", "Health", "Active turns", "Policy", "Last seen"],
        live.map((device) =>
          el(
            "tr",
            {},
            el("td", {}, device.hostname, " ", el("code", {}, device.platform)),
            el("td", {}, text(device.email)),
            el("td", {}, text(device.heartbeat?.clientVersion ?? device.clientVersion)),
            el("td", {}, fleetHealth(device)),
            el("td", {}, text(device.heartbeat?.activeTurns)),
            el("td", {}, text(device.heartbeat?.policyVersion ?? "bootstrap")),
            el("td", {}, ago(device.lastSeenAt)),
          ),
        ),
      ),
    );
  },

  async activity() {
    const teamFilter = el("input", { placeholder: "team (all)", size: 14 });
    teamFilter.value = localStorageGet("activityTeam") ?? "";
    const list = el("div", {});
    const refresh = async () => {
      const team = teamFilter.value.trim();
      localStorageSet("activityTeam", team);
      const { events } = await api(`/activity?limit=200&team=${encodeURIComponent(team)}`);
      list.replaceChildren(
        table(
          ["When", "Who", "Team", "What", "Thread", "Detail"],
          events.map((event) =>
            el(
              "tr",
              {},
              el("td", {}, ago(event.occurredAt)),
              el("td", {}, text(event.email)),
              el("td", {}, text(event.team)),
              el("td", {}, event.type),
              el("td", {}, text(event.threadId)),
              el("td", {}, el("code", {}, describeDetail(event))),
            ),
          ),
        ),
      );
    };
    teamFilter.addEventListener("change", () => void refresh());
    await refresh();
    // Polls while this tab is open; the console stays idle otherwise.
    activityTimer = setInterval(() => {
      if (document.visibilityState === "visible") void refresh().catch(() => {});
    }, 10_000);
    return el(
      "div",
      {},
      el("p", { class: "row" }, "Live agent work, newest first. Team: ", teamFilter),
      list,
    );
  },

  async library() {
    const { items } = await api("/library");
    const editable = can("write:library");
    const kind = el(
      "select",
      {},
      ["skill", "prompt", "instructions", "mcp-server"].map((value) =>
        el("option", { value }, value),
      ),
    );
    const name = el("input", { placeholder: "name, e.g. deploy-checklist", size: 22 });
    const team = el("input", { placeholder: "team (everyone)", size: 14 });
    const description = el("input", { placeholder: "when to use it", size: 40 });
    const content = el("textarea", {
      spellcheck: "false",
      placeholder: "Markdown, or JSON for an MCP server",
    });
    const load = (item) => {
      kind.value = item.kind;
      name.value = item.name;
      team.value = item.team ?? "";
      description.value = item.description;
      content.value = item.content;
    };
    return el(
      "div",
      {},
      el(
        "p",
        {},
        "Every enrolled machine installs these for Claude Code and Codex: skills and prompts as slash commands, instructions in a managed block of the user's instruction files, MCP servers in Codex's config. A team's item replaces an org item of the same kind and name.",
      ),
      table(
        ["Kind", "Name", "Team", "Description", "Updated", ""],
        items.map((item) =>
          el(
            "tr",
            {},
            el("td", {}, item.kind),
            el("td", {}, el("code", {}, item.name)),
            el("td", {}, text(item.team ?? "everyone")),
            el("td", {}, item.description),
            el("td", {}, ago(item.updatedAt)),
            el(
              "td",
              { class: "row" },
              el("button", { onclick: () => load(item) }, editable ? "Edit" : "View"),
              editable
                ? el(
                    "button",
                    {
                      class: "danger",
                      onclick: () =>
                        confirm(`Remove ${item.name} from every machine?`) &&
                        run(async () => {
                          await api(`/library/${encodeURIComponent(item.id)}`, {
                            method: "DELETE",
                          });
                          await show("library");
                        }, "Removed."),
                    },
                    "Remove",
                  )
                : null,
            ),
          ),
        ),
      ),
      editable
        ? el(
            "div",
            { class: "editor" },
            el("p", { class: "row" }, kind, name, team),
            el("p", {}, description),
            content,
            el(
              "p",
              {},
              el(
                "button",
                {
                  onclick: () =>
                    run(async () => {
                      await api("/library", {
                        method: "PUT",
                        body: JSON.stringify({
                          kind: kind.value,
                          name: name.value.trim(),
                          team: team.value.trim() || null,
                          description: description.value.trim(),
                          content: content.value,
                        }),
                      });
                      await show("library");
                    }, "Saved. Machines pick it up within their next refresh."),
                },
                "Save item",
              ),
            ),
          )
        : null,
    );
  },

  async shared() {
    const { threads } = await api("/shared-threads");
    return el(
      "div",
      {},
      el("p", {}, "Threads people handed to their team or the whole organization."),
      table(
        ["Shared", "Title", "By", "Audience", "Repository", "Patch", "Note", ""],
        threads.map((thread) =>
          el(
            "tr",
            {},
            el("td", {}, ago(thread.createdAt)),
            el("td", {}, thread.title),
            el("td", {}, thread.sharedBy),
            el("td", {}, thread.audience === "org" ? "everyone" : `team ${text(thread.team)}`),
            el("td", {}, el("code", {}, text(thread.repository))),
            el("td", {}, `${Math.ceil(thread.patchBytes / 1024)} KB`),
            el("td", {}, thread.note),
            el(
              "td",
              {},
              can("write:library")
                ? el(
                    "button",
                    {
                      class: "danger",
                      onclick: () =>
                        confirm(`Unshare "${thread.title}"?`) &&
                        run(async () => {
                          await api(`/shared-threads/${encodeURIComponent(thread.id)}`, {
                            method: "DELETE",
                          });
                          await show("shared");
                        }),
                    },
                    "Unshare",
                  )
                : null,
            ),
          ),
        ),
      ),
    );
  },
});

function describeDetail(event) {
  const detail = event.detail ?? {};
  return (
    detail.command ??
    detail.title ??
    detail.path ??
    (Object.keys(detail).length > 0 ? JSON.stringify(detail) : "")
  );
}

const NEEDS = {
  fleet: "read:directory",
  activity: "watch:team",
  library: "read:directory",
  shared: "watch:team",
  users: "read:directory",
  devices: "read:directory",
  teams: "read:directory",
  policy: "read:policy",
  usage: "read:usage",
  audit: "read:audit",
};

async function show(name) {
  clearInterval(activityTimer);
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
