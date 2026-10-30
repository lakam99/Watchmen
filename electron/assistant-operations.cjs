// Fixed operational surface. No model-supplied paths, URLs, IPC names, SQL or settings.
const { createHash } = require("node:crypto");
const digest = (value) =>
  createHash("sha256")
    .update(JSON.stringify(value ?? null))
    .digest("hex");
const choice = (description, values) => ({
  type: "string",
  description,
  enum: values,
});
const str = (description) => ({
  type: "string",
  description,
  minLength: 1,
  maxLength: 160,
});
const tasks = [
  "start_capture",
  "stop_capture",
  "import_capture",
  "export_session",
  "reveal_application",
  "restart_elevated",
  "choose_app_block",
  "choose_app_only",
  "enable_rule",
  "forget_rule",
  "unblock_all",
  "dismiss_change",
  "reopen_change",
  "dismiss_all_changes",
  "save_change_explanation",
  "check_updates",
  "download_update",
  "install_update",
  "open_release",
  "open_country_source",
];
const pages = [
  "Overview",
  "Applications",
  "Destinations",
  "Locations",
  "Connections",
  "Traffic profile",
  "Changes",
  "Packets",
  "Network rules",
  "AI console",
];
const specs = {
  app_capabilities: {
    description:
      "List available operational tasks and boundaries. App settings and credentials cannot be changed by chat.",
    properties: {},
  },
  operation_status: {
    description:
      "Read fresh packet capture, network-rule job/progress and updater status. Never cached.",
    properties: {},
  },
  country_catalog: {
    description:
      "List supported country codes and regions for geographic policies. Optional country/region name query.",
    properties: { query: str("Country code, name or region filter") },
  },
  profile_detail: {
    description:
      "Read saved app destinations, services, countries and measured bytes using a profileRef from traffic_profile. Paths and private addresses are excluded.",
    properties: {
      profileRef: str("Discovered profileRef"),
      range: choice("History window", ["all", "7d", "30d", "90d"]),
    },
    required: ["profileRef"],
  },
  change_detail: {
    description:
      "Read saved change evidence and baseline for explanation in this chat. No packet contents or private addresses.",
    properties: { changeRef: str("Discovered changeRef") },
    required: ["changeRef"],
  },
  packet_headers: {
    description:
      "Read packet header metadata and packetRefs from the current capture/import. Decoded text, DNS names, payloads, raw headers and private addresses stay local. Use show_view to open readable packet detail locally.",
    properties: {
      query: str("App or protocol filter"),
      direction: choice("Packet direction", ["all", "in", "out", "unknown"]),
    },
  },
  show_view: {
    description:
      "Operate the monitor UI: navigate, filter/search/group/sort, pause/resume display, choose chart adapter/window, inspect a discovered connection, profile, change or packet locally. Does not change app settings or data-sharing permissions.",
    properties: {
      page: choice("Page", pages),
      query: { ...str("Local search; empty clears it"), minLength: 0 },
      group: choice("Live grouping", [
        "app",
        "destination",
        "country",
        "protocol",
      ]),
      scope: choice("Network scope", ["all", "internet", "local", "listener"]),
      direction: choice("Direction", ["both", "in", "out"]),
      activity: choice("Connection lifecycle", ["active", "connected", "all"]),
      sort: choice("Live sort", [
        "name",
        "connections",
        "download",
        "upload",
        "total",
      ]),
      display: choice("Display only; collection continues", [
        "pause",
        "resume",
      ]),
      window: choice("Chart seconds", ["60", "300"]),
      adapterRef: str("Adapter reference from network_status, or all"),
      targetRef: str(
        "Discovered connectionRef, profileRef, changeRef or packetRef",
      ),
      range: choice("Profile range", ["all", "7d", "30d", "90d"]),
      tab: choice("Profile tab", ["applications", "destinations"]),
      metric: choice("Profile chart", ["observations", "bytes"]),
      ruleStatus: choice("Saved rule filter", ["all", "active", "inactive"]),
      ruleTask: choice("Rule task display", ["minimize", "show", "dismiss"]),
      changeStatus: choice("Change filter", [
        "open",
        "dismissed",
        "archived",
        "all",
      ]),
      changeType: choice("Change category", [
        "all",
        "new_destination",
        "new_service",
        "new_country",
        "traffic_spike",
      ]),
    },
  },
  propose_app_action: {
    description:
      "Prepare ONE operational task for explicit local approval. Never executes it. File tasks open local pickers; models cannot choose paths. choose_app_* opens an executable picker then a SECOND exact firewall review. Broad actions require acknowledgement. Settings are excluded.",
    properties: {
      task: choice("Task", tasks),
      targetRef: str("Discovered appRef, ruleRef or changeRef where required"),
      seconds: choice("Capture duration", ["5", "10", "20", "30"]),
      explanation: {
        type: "string",
        description:
          "Concise single-line explanation to save on the discovered change; only for save_change_explanation",
        minLength: 1,
        maxLength: 3000,
      },
    },
    required: ["task"],
  },
  cancel_network_task: {
    description:
      "Request cancellation of the current cancellable Windows rule job. Returns rollback progress; commit stages cannot be cancelled. Does not disable saved rules.",
    properties: {},
  },
};

function status(host) {
  const p = host.operations.packets?.status() || {},
    f = host.firewall.status(),
    u = host.operations.updates?.status() || {};
  return {
    cacheable: false,
    packets: {
      active: !!p.active,
      processing: !!p.processing,
      totalRecords: p.totalRecords || 0,
      startedAt: p.startedAt,
      endsAt: p.endsAt,
      error: !!p.error,
    },
    network: {
      busy: !!f.busy,
      phase: f.phase,
      verified: f.isolationVerified === true,
      job: f.job
        ? {
            id: f.job.id,
            status: f.job.status,
            stage: f.job.stage,
            message: f.job.message,
            completed: f.job.completed,
            total: f.job.total,
            canCancel: f.job.canCancel,
          }
        : null,
      error: !!f.error,
    },
    update: {
      currentVersion: u.currentVersion,
      availableVersion: u.availableVersion,
      phase: u.phase,
      percent: u.percent,
      error: !!u.error,
    },
  };
}
const labels = {
  start_capture: "Start local packet capture",
  stop_capture: "Stop packet capture",
  import_capture: "Choose and import a local PCAP file",
  export_session: "Export traffic snapshot using Save As",
  reveal_application: "Reveal the selected executable in Explorer",
  restart_elevated: "Restart Watchmen as administrator (UAC)",
  choose_app_block: "Choose an executable to block",
  choose_app_only: "Choose the only allowed executable",
  enable_rule: "Enable the selected saved network rule",
  forget_rule: "Remove the selected disabled rule from history",
  unblock_all: "Disable all currently enabled Watchmen rules",
  dismiss_change: "Dismiss this application/type change group",
  reopen_change: "Reopen this saved change",
  dismiss_all_changes: "Dismiss all currently open changes",
  save_change_explanation: "Save the reviewed AI explanation on this change",
  check_updates: "Check GitHub for updates",
  download_update: "Download the available update",
  install_update: "Install the downloaded update and restart",
  open_release: "Open the official GitHub release page",
  open_country_source: "Open the DB-IP country-data source",
};

async function execute(host, name, args, options, signal) {
  const { clean, ToolError } = require("./assistant-tools.cjs");
  const store = () => {
    const s = host.history();
    if (!s) throw new ToolError("Traffic history is unavailable.");
    return s;
  };
  if (name === "app_capabilities")
    return {
      tasks,
      views: pages,
      reads: [
        "network_status",
        "list_applications",
        "inspect_connections",
        "traffic_profile",
        "profile_detail",
        "connection_changes",
        "change_detail",
        "network_rules",
        "country_catalog",
        "packet_headers",
        "operation_status",
      ],
      boundaries:
        "Settings and credentials are excluded. All mutations require a local review. Packet contents remain local. Pickers are controlled by the user. Row explanations and traffic insights use these read tools in this chat.",
    };
  if (name === "operation_status") return status(host);
  if (name === "country_catalog") {
    const c = host.firewall.catalog(),
      rows = (c.countries || []).filter(
        (c) =>
          !args.query ||
          [c.code, c.name, c.region]
            .join(" ")
            .toLowerCase()
            .includes(args.query.toLowerCase()),
      );
    return {
      countries: rows.slice(0, 60),
      total: rows.length,
      truncated: rows.length > 60,
      regions: c.regions,
      limits:
        "Filter by country name, code or region for the full selection. Approximate monthly geolocation; VPNs/CDNs affect coverage.",
    };
  }
  if (name === "profile_detail") {
    const id = host.profiles.get(args.profileRef)?.value.id;
    if (!id) throw new ToolError("Inspect traffic_profile first.");
    const s = store().detail({ appId: id, range: args.range || "7d" });
    return {
      app: clean(s.application?.name),
      endpoints: s.endpoints.slice(0, 40).map((e) => ({
        scope: e.scope,
        country: clean(e.country),
        owner: clean(e.org),
        protocol: e.protocol,
        port: e.port,
        localServicePort: e.localServicePort,
        received: e.received,
        sent: e.sent,
        observations: e.observations,
        measuredMs: e.measuredMs,
        firstSeen: e.firstSeen,
        lastSeen: e.lastSeen,
        ...host.publicAddress(e.address, options),
      })),
      truncated: s.endpoints.length > 40,
    };
  }
  if (name === "change_detail") {
    const id = host.changes.get(args.changeRef)?.value.id;
    if (!id) throw new ToolError("Inspect connection_changes first.");
    // explainPayload(false) removes every observed/recent destination address.
    return store().anomalies.explainPayload(id, false);
  }
  if (name === "packet_headers") {
    const p = host.operations.packets?.status();
    if (!p) throw new ToolError("Packet capture is unavailable.");
    const rows = (p.packets || []).filter(
      (p) =>
        (!args.query ||
          `${p.app} ${p.protocol}`
            .toLowerCase()
            .includes(args.query.toLowerCase())) &&
        (!args.direction ||
          args.direction === "all" ||
          p.direction === args.direction),
    );
    return {
      cacheable: false,
      active: p.active,
      total: rows.length,
      packets: rows.slice(0, 25).map((p) => ({
        packetRef: host.ref(host.packets, "packet_", digest(p), {
          id: p.id,
          fingerprint: digest(p),
        }),
        app: clean(p.app),
        protocol: clean(p.protocol),
        direction: p.direction,
        timestamp: p.timestamp,
        sourcePort: p.sourcePort,
        destinationPort: p.destinationPort,
        length: p.length,
        capturedLength: p.capturedLength,
        truncated: p.truncated,
        encrypted: p.encrypted,
        ...(options.shareIPs
          ? {
              sourcePublicIP: host.publicAddress(p.source, options).publicIP,
              destinationPublicIP: host.publicAddress(p.destination, options)
                .publicIP,
            }
          : {}),
      })),
      limits:
        "Only transport header metadata. Open the packet locally for human-readable content.",
    };
  }
  if (name === "show_view") {
    const command = { ...args };
    if (args.adapterRef) {
      const a = host.adapters.get(args.adapterRef)?.value;
      if (args.adapterRef !== "all" && !a)
        throw new ToolError("Inspect network_status for adapter references.");
      command.adapter = a?.id || "all";
      delete command.adapterRef;
    }
    if (args.targetRef) {
      if (host.connections.has(args.targetRef)) {
        const f = host.resolve(args.targetRef);
        command.connectionId = f.id;
        command.groupId = f.protocol;
        command.group = "protocol";
        command.page = "Connections";
      } else if (host.profiles.has(args.targetRef)) {
        command.profileId = host.profiles.get(args.targetRef).value.id;
        command.page = "Traffic profile";
      } else if (host.changes.has(args.targetRef)) {
        command.changeId = host.changes.get(args.targetRef).value.id;
        command.page = "Changes";
        command.changeStatus = "all";
      } else {
        const ref = host.packets.get(args.targetRef)?.value,
          p = host.operations.packets
            ?.status()
            .packets.find(
              (p) => p.id === ref?.id && digest(p) === ref.fingerprint,
            );
        if (!p)
          throw new ToolError("The selected item is stale. Inspect it again.");
        command.packetId = p.id;
        command.page = "Packets";
      }
      delete command.targetRef;
    }
    if (!Object.keys(command).length)
      throw new ToolError("Choose a view operation.");
    await host.operations.showView(command, signal);
    return {
      cacheable: false,
      status: "view_updated",
      view: command.page || "current",
      note: "Display controls do not stop traffic collection.",
    };
  }
  if (name === "cancel_network_task") {
    host.firewall.cancel();
    return status(host);
  }
  if (name !== "propose_app_action") return undefined;
  const task = args.task,
    epoch = host.epoch;
  if (args.seconds && task !== "start_capture")
    throw new ToolError("Duration applies only to capture.");
  if (args.explanation && task !== "save_change_explanation")
    throw new ToolError(
      "Explanation text applies only to saving a change explanation.",
    );
  if (task === "save_change_explanation" && !args.explanation)
    throw new ToolError(
      "Provide a succinct explanation to review before saving.",
    );
  let selected = null,
    local = {},
    requiresAdmin = [
      "start_capture",
      "enable_rule",
      "forget_rule",
      "unblock_all",
    ].includes(task),
    broad = [
      "unblock_all",
      "dismiss_all_changes",
      "choose_app_only",
      "install_update",
      "restart_elevated",
    ].includes(task);
  const targetTasks = [
    "reveal_application",
    "enable_rule",
    "forget_rule",
    "dismiss_change",
    "reopen_change",
    "save_change_explanation",
  ];
  if (args.targetRef && !targetTasks.includes(task))
    throw new ToolError("This task does not accept a target.");
  if (targetTasks.includes(task) && !args.targetRef)
    throw new ToolError("Select a discovered target reference.");
  if (task === "reveal_application") {
    const f = host.resolve(args.targetRef, true);
    local = { appPath: f.processPath, label: clean(f.app) };
    selected = { id: f.id, fingerprint: digest([f.pid, f.processPath]) };
  }
  if (["enable_rule", "forget_rule", "unblock_all"].includes(task)) {
    const s = await host.firewall.refresh();
    if (s.error)
      throw new ToolError("Refresh rules successfully before changing them.");
    if (task === "unblock_all") {
      selected = s.rules.filter((r) => r.enabled);
      if (!selected.length)
        throw new ToolError("There are no enabled Watchmen rules.");
      local.summary = `Disable ${selected.length} reviewed rules. Other firewall products are unaffected. New rules created after this review will not be disabled.`;
      local.reviewedRules = structuredClone(selected);
    } else {
      const id = host.rules.get(args.targetRef)?.value.id;
      selected = s.rules.find((r) => r.id === id);
      if (!selected) throw new ToolError("Inspect saved rules first.");
      if (
        (task === "enable_rule" && selected.enabled) ||
        (task === "forget_rule" && selected.enabled)
      )
        throw new ToolError("Select a disabled rule.");
      local = structuredClone(selected);
      local.summary = `${labels[task]}: ${selected.kind} / ${clean(selected.label)}.${selected.kind === "onlyApp" ? " All other applications will be blocked." : ""}${selected.kind === "onlyRegion" ? ` Destinations outside these countries will be blocked. Local networks: ${selected.allowLocalNetwork ? "allowed" : "blocked"}; unknown locations: ${selected.allowUnknown ? "allowed" : "blocked"}.` : ""}`;
      broad = ["region", "onlyRegion", "onlyApp"].includes(selected.kind);
    }
  }
  if (
    ["dismiss_change", "reopen_change", "save_change_explanation"].includes(
      task,
    )
  ) {
    const id = host.changes.get(args.targetRef)?.value.id;
    if (!id) throw new ToolError("Inspect connection_changes first.");
    const a = store().anomalies.explainPayload(id, false);
    selected = { id };
    local.summary = `${clean(a.app)} / ${a.type}. Dismissal covers the matching open application/type/direction group.`;
    if (task === "save_change_explanation")
      local.summary = `${clean(a.app)} / ${a.type}: ${args.explanation}`;
  }
  if (task === "dismiss_all_changes") {
    selected = store().anomalies.openIds();
    local.summary = `Dismiss ${selected.length} reviewed change groups. New groups will be left open.`;
  }
  if (task === "start_capture")
    local.summary = `Capture locally for ${args.seconds || 10} seconds. Packet contents will not be sent to AI.`;
  if (task === "choose_app_block" || task === "choose_app_only")
    local.summary =
      "Opens a local executable picker. Selection creates a second exact rule review; it does not apply a rule.";
  if (task === "install_update") {
    const s = host.operations.updates.status();
    if (s.phase !== "ready") throw new ToolError("Download an update first.");
    selected = { version: s.availableVersion };
    local.summary = `Install ${s.availableVersion} and restart. Chat is not retained; active capture/rule tasks must finish first.`;
  }
  if (signal?.aborted || host.epoch !== epoch)
    throw new ToolError("This action was cancelled.");
  return host.proposeTask(
    task,
    { ...local, kind: "app_task", label: labels[task], requiresAdmin },
    {
      selected,
      args: structuredClone(args),
      fingerprint: selected ? digest(selected) : null,
    },
    broad,
  );
}

async function approve(host, p) {
  const { ToolError } = require("./assistant-tools.cjs"),
    { task, selected, args } = p.internal;
  const op = host.operations;
  const history = () => {
    const s = host.history();
    if (!s) throw new ToolError("Traffic history is unavailable.");
    return s;
  };
  if (task === "start_capture") {
    await op.packets.start(Number(args.seconds || 10));
    return "Local capture started. Packet contents remain local; use operation_status for progress.";
  }
  if (task === "stop_capture") {
    await op.packets.stop();
    return "Packet capture stopped. Inspect operation_status and packet_headers for results.";
  }
  if (task === "import_capture") {
    const r = await op.importCapture();
    return r === null
      ? "File selection cancelled; nothing imported."
      : "Local capture imported. Packet contents remain local.";
  }
  if (task === "export_session") {
    const r = await op.exportSession();
    if (r.error) throw new ToolError(r.error);
    return r.canceled
      ? "Save cancelled; no export written."
      : "Traffic session exported to the user-selected file.";
  }
  if (task === "reveal_application") {
    const f = host.resolve(args.targetRef, true);
    if (digest([f.pid, f.processPath]) !== selected.fingerprint)
      throw new ToolError("Application changed; request a fresh review.");
    await op.revealApplication(f);
    return "Selected executable revealed locally in Explorer.";
  }
  if (task === "restart_elevated") {
    if (!(await op.restartElevated()))
      throw new ToolError("Administrator restart cancelled or unavailable.");
    return "Administrator restart requested.";
  }
  if (task === "choose_app_block" || task === "choose_app_only") {
    const preview = await op.pickApplication(task === "choose_app_only");
    if (!preview) return "Executable selection cancelled.";
    host.propose("block", preview);
    return "Executable selected. A second exact firewall review requires approval before anything is blocked.";
  }
  if (["enable_rule", "forget_rule", "unblock_all"].includes(task)) {
    const s = await host.firewall.refresh();
    if (s.error) throw new ToolError("Windows rule refresh failed.");
    const rules = task === "unblock_all" ? selected : [selected];
    for (const r of rules)
      if (digest(s.rules.find((c) => c.id === r.id)) !== digest(r))
        throw new ToolError("Reviewed rules changed. Request a fresh review.");
    let result = s;
    for (const r of rules) {
      const current = await host.firewall.refresh();
      if (
        current.error ||
        digest(current.rules.find((c) => c.id === r.id)) !== digest(r)
      )
        throw new ToolError(
          "A reviewed rule changed. Earlier verified changes, if any, remain applied; refresh Network rules.",
        );
      result =
        task === "forget_rule"
          ? await host.firewall.forget(r.id)
          : await host.firewall.toggle(r.id, task === "enable_rule");
      const actual = result.rules?.find((c) => c.id === r.id);
      if (
        result.error ||
        result.isolationVerified !== true ||
        (task === "forget_rule"
          ? !!actual
          : !actual ||
            actual.enabled !== (task === "enable_rule") ||
            actual.partial)
      )
        throw new ToolError(
          "Windows did not verify the complete requested change. Refresh Network rules; earlier verified changes, if any, remain applied.",
        );
    }
    return task === "forget_rule"
      ? "Disabled rule removed and verified."
      : `${rules.length} reviewed rule(s) changed and verified. Overlapping rules can still block traffic.`;
  }
  if (
    ["dismiss_change", "reopen_change", "dismiss_all_changes"].includes(task)
  ) {
    const a = history().anomalies;
    if (task === "dismiss_all_changes")
      for (const id of selected) a.setStatus(id, "dismissed");
    else
      a.setStatus(
        selected.id,
        task === "dismiss_change" ? "dismissed" : "open",
      );
    op.historyChanged?.();
    return "Saved change status updated. Collection and baselines continue.";
  }
  if (task === "save_change_explanation") {
    const identity = op.aiIdentity?.() || {
      provider: "AI console",
      model: "configured model",
    };
    history().anomalies.saveExplanation(selected.id, {
      text: args.explanation,
      provider: identity.provider,
      model: identity.model,
      generatedAt: new Date().toISOString(),
    });
    op.historyChanged?.();
    return "Reviewed explanation saved on the selected traffic change.";
  }
  if (task === "check_updates") {
    const s = await op.updates.check();
    if (s.error)
      throw new ToolError("Update check failed; inspect the update status.");
    return "Update check finished. Read operation_status for the current result.";
  }
  if (task === "download_update") {
    const s = await op.updates.download();
    if (s.error)
      throw new ToolError("Update download failed; inspect the update status.");
    return "Update download finished. Read operation_status before installation.";
  }
  if (task === "install_update") {
    if (
      op.updates.status().phase !== "ready" ||
      op.updates.status().availableVersion !== selected.version
    )
      throw new ToolError(
        "The reviewed update changed. Request a fresh review.",
      );
    await op.installUpdate();
    return "Installer launch requested.";
  }
  if (task === "open_release" || task === "open_country_source") {
    await op.openOfficial(task);
    return "Official reference page opened.";
  }
  throw new ToolError("Unsupported app task.");
}
module.exports = { specs, execute, approve, tasks, pages };
