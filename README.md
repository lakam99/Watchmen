# Watchmen

A local-first Windows desktop network monitor with a spaceship terminal interface, built with Electron, React, and a native .NET collector. This is an independent app, with no affiliation to Proton.

## Run the desktop app

Open `release/0.10.9/Watchmen-win32-x64/Watchmen.exe`. Keep the entire folder together: the executable needs its adjacent runtime files. The collector runtime is bundled; installing .NET is unnecessary for the packaged app. Releases use versioned folders so a running older version does not block a new build.

Closing the window keeps Watchmen running in the Windows notification area (system tray, beside the clock). Monitoring, local traffic profiling, captures, rule tasks and AI responses continue. Click the tray icon or choose **Show Watchmen** to return to the same window. Choose **Quit Watchmen** in its right-click menu to stop the app and collector. The tray menu also offers **Hide window**.

The standard mode reads live TCP connections, UDP listening sockets, process ownership, and incoming/outgoing network-interface rates. Use **Enable detailed capture** to relaunch with Windows administrator approval and enable per-process TCP/UDP byte counts. Canceling UAC leaves standard monitoring available.

## What you can do

- Group traffic by application/executable, destination IP, approximate country, or protocol.
- Search application names, PIDs, IPs, ports, countries, cities, and network owners.
- Filter Internet/local/listening sockets, active/session activity, and observed byte direction.
- Inspect individual endpoints, process IDs, ports, connection state, process paths, and observed session bytes. Reveal an executable in File Explorer.
- Expand any main row to browse its connections in a searchable, sortable, paginated table. Select an individual connection to inspect it directly.
- Choose System, Light, or Dark appearance in Settings. Your preference persists across restarts.
- Watch incoming/outgoing rates over 60 seconds or five minutes, choosing a specific interface when needed.
- Pause the displayed view while collection continues, then resume. Export the latest collector snapshot and retained flow totals as JSON.

## App updates from GitHub Releases

Version 0.7 adds **Settings & privacy > App updates**. Packaged Windows builds check the public `lakam99/Watchmen` GitHub repository ten seconds after launch and every six hours. New stable releases download in the background by default. Both automatic checking and background downloading can be turned off; **Check for updates** and **Download update** remain available. No traffic data or OpenRouter token is sent to GitHub.

The Windows updater uses `electron-updater` with the release's `latest.yml` metadata and SHA-512 verification. It ignores prereleases and downgrades. A verified download shows **Install & restart** in Settings and the main monitor. It never installs merely because you close the app. Rule changes and packet capture/import must finish first. Quit other Watchmen instances from their tray menus before installation; hiding their windows leaves their processes running. The Windows installer runs per user and creates normal app shortcuts.

The data directory is remembered in `watchmen-workspace.json` inside the stable Electron user profile before installation. Updated/installed copies reopen that directory, including `.watchmen/traffic.sqlite`, settings and encrypted credentials. The Chromium profile owning the DPAPI encryption key stays in place. If that pointer cannot be saved, installation is blocked. For an existing portable installation, open the new portable 0.7 build from the existing working directory once before using in-app installation. A first-time installation with no prior workspace uses its own application folder.

The app reports that no update is available until a stable Windows release includes both its installer and `latest.yml` metadata. Version 0.6 itself has no updater; use the 0.7 build for this first upgrade.

For maintainers, `npm run release:build` produces the portable app/ZIP, `Watchmen-Setup-<version>-x64.exe`, `latest.yml` and `SHA256SUMS.txt` under `release/<version>`. The workflow in `.github/workflows/release.yml` runs for pushes to `master`/`main`, explicit stable version tags, and manual dispatch. It runs tests, builds and audits the packages, uploads a draft, then publishes only after all assets are present. A new package version is honored; subsequent pushed changes automatically use the next unused stable patch. If a version bump is needed, a version-only commit is created on the release tag, leaving the development branch intact. Already published releases are preserved. Update `RELEASE_NOTES.md` alongside each user-facing change. Authenticode signing is not configured; the current release integrity check is the SHA-512 digest delivered by the configured GitHub feed.

## Block and unblock traffic

Use **Block** in an application, destination, country, or expanded connection row. The review shows the executable, address and port scope before applying. Administrator access is required; a normal window can view saved rules and prepare a review. **Network rules** lists active and unblocked rules across all Watchmen windows and working directories.

- **Application:** blocks every process using that executable path, across launches. Launchers, helpers and executable updates at different paths need their own rules.
- **Connection:** blocks the selected executable's remote IP, TCP/UDP protocol and remote port across current and future connections. It is not restricted to one PID or ephemeral local port.
- **Destination:** blocks that IP for every app and port. Shared/CDN IPs can serve several unrelated sites.
- **Region:** select countries/territories or continent groups. The review downloads/caches the current monthly [DB-IP Lite country database](https://db-ip.com/db/lite.php), then displays the exact dataset date, range count and Windows filter count before applying. IPv4 and IPv6 address ranges cover unseen destinations too. Country assignments are approximate and can differ from the live location provider, VPN exits, proxies and CDNs. Unknown country assignments are outside the selection.
- **Allow only selected countries / regions:** choose this mode in Network rules, then choose countries or continent groups. **Allow Canada + US only** is a quick preset. All other public destinations, including unknown locations, are blocked by default. Local/private, loopback, link-local, shared-carrier and multicast addresses are exempt by default; both local and unknown-location behavior have explicit switches in the review. Existing block rules still apply. Only one country-only preset can be active at a time. A persistent banner provides **Turn off country-only mode**; the saved preset can also be unblocked from the rules table.
- **Allow only one app:** use the shield button beside an application row, or choose an executable in Network rules. A separate acknowledgement enables a block for every other executable, including Windows services. The selected executable remains subject to other Windows/Watchmen policies. System DNS, separate helpers, proxies, lookups and AI may stop working when their executable is excluded. The local **Turn off app isolation** control stays available.

Rules use the native [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page), with persistent filters at incoming/outgoing IPv4/IPv6 application-enforcement layers. Changes commit in a Windows transaction. There is no change to Windows Firewall's default actions or unrelated providers' rules. Persistent rules reload when the Base Filtering Engine starts; early boot before that service is outside this mode's coverage. Existing sockets can remain listed briefly even when their traffic is blocked. Kernel drivers, third-party filters and VPN software can affect networking behavior.

**Long-running changes:** applying and removing rules shows actual completed filter steps, elapsed time, and separate waiting, staging, commit and verification phases. Counts describe staged work; enforcement changes atomically at commit. Select **Minimize task** to keep using live tables, search, pause and export. The floating task panel restores the review and offers cancellation before commit. Cancellation waits for rollback; the commit and verification stages cannot be cancelled. A helper heartbeat keeps healthy large jobs running beyond the old five-minute limit. No completed steps for 30 seconds produces a waiting notice; a silent or interrupted helper requires refreshing committed Windows state. Closing the app is different from minimizing the task. Operations from another window are serialized; a busy-window conflict is reported after 30 seconds. Version 0.5 jobs already running do not gain progress reporting until a new operation is started in this version.

Windows enforces these rules while Watchmen is closed. Editable metadata and region ranges are stored machine-wide in **`C:\ProgramData\WatchmenNetworkMonitor\Rules`**, with administrator/System write access and ordinary-user read access. Each rule is checked against committed Windows filters when refreshed. Monthly downloads stay in **`.watchmen/country-ranges`** in the current working directory. Downloading region data does not submit your traffic IPs. IP Geolocation by [DB-IP](https://db-ip.com), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Region selections are limited to 250,000 compact address ranges; large selections can take several minutes to apply. A region rule retains its dated snapshot: unblock and remove it, then create it again to use newer data.

Use **Unblock**, **Block again**, **Turn off app isolation**, or **Unblock all Watchmen rules**. Turning off one rule leaves other matching restrictions in place. Remove an unblocked rule to forget its saved metadata. Close or remove Watchmen only after unblocking any restrictions you no longer want.

For recovery without the app, double-click **`Unblock-Watchmen.cmd`** in the release folder and accept Windows administrator elevation. Keep its `.ps1` companion and the complete app folder together. From an administrator PowerShell window, the native recovery command is:

```powershell
& '.\resources\app.asar.unpacked\native\bin\0.8.0\Watchmen.Agent.exe' --unblock-watchmen
```

Recovery removes filters only from Watchmen's own Windows filtering sublayer and can work even if saved rule metadata is missing or damaged. Reinstalling this build also gives access to the machine-wide rules and recovery control.

## Persistent traffic profiles

Open **Traffic profile** for history shared across launches and windows. Watchmen stores a local SQLite database at **`.watchmen/traffic.sqlite` in this working directory**. It starts accumulating when this version runs; it cannot recover traffic from times when Watchmen was closed or from older versions that did not save history.

The database records applications (executable path, with a name-only fallback), remote destinations, TCP/UDP services, first/last observations, recording sessions, daily observed-flow counts, and measured incoming/outgoing byte deltas. Repeated observations build application and destination profiles. Select an application to drill into its learned endpoints and ports. Search and all-history/7-day/30-day/90-day views are available; day buckets use UTC, while observation times display locally.

Running several windows against the same working directory does not sum duplicate collectors. A SQLite transaction elects one recorder, preferring an instance with working detailed capture. Other windows read the shared history and take over when the recorder exits or its eight-second lease expires. Each ownership change establishes a byte-counter baseline; only subsequent positive deltas are added. Duplicate snapshots, counter resets, and closed transfers between normal flushes are handled explicitly. First samples and measurement gaps are excluded from totals rather than estimated. Per-app byte totals require detailed capture; ordinary mode still builds application, endpoint, port, and session history. A dash means those byte totals have not been measured.

**Flow observations are not connection attempts.** A socket first observed in a new recording session is another observation, even if the physical connection was already open. Application identity survives PID changes when the executable path stays the same. A different executable path is a different identity; unavailable paths use a name-only identity. Profiles and daily aggregates are retained without automatic expiration. Individual connection/counter records are retained for 30 days. Lists display up to 200 profiles or services, while the database retains the complete aggregates.

Successful opt-in IP lookups are cached in the database and reused for seven days. Previously learned country/network-owner labels remain visible in historical profiles when new lookups are off. These historical records are local network metadata, stored in SQLite without database encryption. The API token remains in its separate Windows-encrypted credential file and is never added to the database. The entire `.watchmen` directory is ignored by Git and excluded from packaged builds.

SQLite uses WAL transactions and versioned schema initialization. A damaged or newer database is preserved and reported in the UI; live monitoring can continue. For a simple file copy backup, close all Watchmen windows first. While recording, recent commits can also be in `traffic.sqlite-wal` and `traffic.sqlite-shm`; do not discard those companion files.

Version 0.4 upgrades existing profiles to schema 2 while retaining their history. Use version 0.4 or newer for future launches; version 0.3 cannot reopen this newer schema.

## Changes against your saved profile

Changes are grouped by application and change type, with upload and download spikes kept separate. The badge counts unresolved groups with activity in the last 24 hours, rather than every observed IP or lifetime history. New observations update a group and retain its original baseline; the detail shows up to 20 recent examples. Repeat events are deduplicated. Old notices remain in Archived/history, and **Mark all reviewed** clears the current queue while keeping learned profiles and evidence. Temporary remote ports (49152–65535) stay in the traffic profile and do not create new-service notices. Existing per-IP notices are consolidated on first launch without deleting their source records.

Open **Changes** to see new destination IPs, unfamiliar remote protocol/port combinations, new countries, and sustained upload/download spikes. Detection runs locally against the shared SQLite history; alert evidence preserves what was known before the change. Each app needs two minutes of recorded presence before destination/service notices start. Existing history contributes to that baseline. Location notices require previously learned countries and a newly observed endpoint with an opt-in or cached location result. A changed country can reflect a CDN, VPN, proxy, or approximate lookup.

Spike detection needs working detailed capture and five earlier completed measured minutes within the previous 24 hours. Each eligible minute needs at least 30 seconds of measured coverage. A completed minute is flagged when its measured rate exceeds the greater of 128 KiB/s, five times the baseline median, and the median plus six median absolute deviations, with at least 4 MiB transferred. Lost-event and counter-reset windows are excluded. Notices are limited to one per app/direction per ten-minute bucket; measured windows expire after seven days. This detects sustained changes and can miss brief bursts. Ordinary mode can detect new endpoints/services but cannot measure per-app spikes.

Select a notice to compare the saved baseline with the observation, dismiss or reopen it, or inspect matching packets. These are changes worth reviewing, not malware verdicts. Alerts, dismissal state, and requested explanations persist across restarts without automatic expiration. The feed shows up to 200 matching notices.

**Explain this change → Generate explanation** uses your saved OpenRouter settings to explain the selected change. Review the exact metadata before generating. The preview contains the frozen before/after evidence; remote IPs are excluded unless you opt in. No packet contents, process IDs, local IPs, or executable paths are sent. Explanations run only when requested and are saved beside that alert. General AI reviews remain separate and stay in memory.

## Readable packets

Open **Packets** and choose a 5–30 second capture, or import a local PCAP/PCAPNG file up to 64 MB. Live capture requires **Restart as administrator** and uses native Windows IPv4 sockets on active interfaces. It streams the first 512 bytes of up to 500 records into memory; total records are counted separately. No capture driver installation, machine-wide Packet Monitor session, or temporary payload file is needed. Visibility depends on Windows, adapter, VPN, and firewall behavior; loopback and live IPv6 capture are outside this mode. Imported files support the implemented IPv4/IPv6 link formats and are left intact.

Search addresses, apps, protocols, and summaries, filter incoming/outgoing records, then select a packet for readable header fields, DNS questions, HTTP/plaintext where present, and header bytes. Common credential headers and token/password fields are redacted from text previews. This is a limited per-packet preview: it does not reassemble streams, decode every binary protocol, or decrypt TLS/HTTPS/QUIC. Encrypted payloads are labeled accordingly. App ownership is matched to current socket tuples when unambiguous; historical imports can remain unattributed. Packet direction uses this machine's current interface addresses.

Live packet data stays in memory until another capture/import or app exit and is never stored in the profile database or sent to AI. On systems with several adapters, a packet may appear more than once. Imported captures remain the user's original files.

## Row explanations

Right-click a data-table row and select **What is this?** for a succinct, read-only AI explanation of that frozen row. This works for live applications, destinations, countries, protocols and nested connections; saved application/destination/service profiles; change notices; captured packets; and saved firewall rules. Focus a row and press **Shift+F10** for the same menu. Opening the menu makes no AI request; selecting the action uses your configured OpenAI, OpenRouter or compatible insights provider. An unconfigured account opens the AI setup flow. Close the panel or press Escape to cancel a pending overview.

Row overviews send only validated, bounded names, ports, states, counts and measured counters. Addresses, full executable paths, packet summaries/payloads, local process IDs and arbitrary evidence are excluded; packet overviews use header metadata only. Configured credentials are redacted from metadata and output. Executable basenames can identify saved app rules. The basic request has no tools and asks for 2–3 sentences, at most 80 words. When an app name is present, it leads with that software's usual purpose and likely network use, while acknowledging unknown or ambiguous names. No chat history is attached or saved. Metadata can explain a protocol or rule without proving the destination's identity, an app's legitimacy, or a threat verdict. Provider charges may apply.

**About the app** adds cited, timestamped research through OpenAI or OpenRouter when **Allow web research** is already enabled in the AI console. Otherwise, **Research app on web** authorizes one isolated lookup without changing your saved permission or repeating the basic analysis. Its query includes only a validated app/process name, never the row's IPs, paths, counters, packet content or chat. It prefers official documentation, offers clickable source citations, and retains the basic overview if search fails or returns no valid citations. Unknown/generic names and custom compatible endpoints use the basic overview without web search. Search charges and model/account support vary. Research identifies the named software generally; a matching name does not verify the local executable's publisher, signature or safety. Neither overview mode can execute app actions. Closing the panel cancels pending work.

## AI command console and function tools

Open **AI console** from the numbered navigation or header. Configure **OpenAI** or **OpenRouter** and a model with function/tool support under **Settings & privacy**. Your saved provider and Windows-encrypted token are reused; an existing OpenAI configuration now enables chat directly. The console never sends the token in a message or tool result. OpenAI-compatible custom endpoints remain available for one-shot insights only. The console heading and sharing notices identify the selected provider.

The chatbot can read current capture health, applications and connections, bounded historical apps/destinations/services/daily totals, filtered connection changes and their baseline evidence, saved Watchmen rules, country catalogs, packet header metadata, and live capture/rule/update progress. Live app/connection/rule lists support result offsets to reach later rows. Tool activity and results are inspectable beside the conversation. Responses keep running when you return to monitoring. **Stop response** aborts a model turn and invalidates its pending reviews. **Clear session** clears the in-memory transcript, tool results and pending reviews. Chat history is not saved across app restarts.

External tools start disabled. **Allow public IP lookups** permits the fixed ipwho.is HTTPS endpoint to receive a public destination IP selected from a current connection. Private/local/reserved destinations are refused. **Allow web research** permits an isolated public research query using the selected provider: OpenAI's [Responses web search](https://developers.openai.com/api/docs/guides/tools-web-search) or OpenRouter's [web search server tool](https://openrouter.ai/docs/guides/features/server-tools/web-search). Citations are required; OpenAI research also requires a completed search item. Research may add search charges and depends on model/account support. Its request contains the public query rather than the local conversation/tool transcript. OpenRouter's legacy web plugin is explicitly disabled on console requests. Model variants with the automatic `:online` suffix are refused. Account/provider policies still govern service behavior and logging.

Direct OpenAI chat uses the [Responses function-calling format](https://developers.openai.com/api/docs/guides/function-calling), with `store: false`. Returned reasoning items, tool calls and call IDs are replayed in memory to continue stateless multi-step requests. No stored response/conversation ID is used. Changing providers, credentials or models clears previous context and pending reviews. Incomplete/refused responses and unsupported built-in tools cannot execute local functions. Research is limited to one provider search call per isolated request; per-message console lookup budgets still apply.

Each pass starts with six AI rounds and eight tool-call attempts. Reaching either budget stops further tool execution and permits one final summary request with no offered tools and `tool_choice: "none"`. Extra calls in a batch are marked unexecuted, with paired outputs retained for valid conversation replay. The final answer summarizes the collected evidence and remaining unknowns instead of showing the old step-limit error. If the summary is unavailable, empty, incomplete, exceeds the remaining deadline, or asks for more tools, a local **Collected Results** recap preserves the usable findings. Sampled applications, distinct connection queries and source links are retained. Pending action cards still need local approval; summarization does not apply rules. Cancellation and permission changes continue to stop the response rather than returning stale data. Chat and recaps remain session-only.

Two investigation controls are available during a response and on the latest limit summary:

- **Raise the tool limit by 6** adds six AI rounds and six tool-call attempts. During a response it extends that pass; from a limit summary it resumes the same investigation with the stopped budget increased by six. Each increase adds one minute to the pass deadline, starting at 90 seconds. Up to three increases are permitted (24 rounds / 26 attempts / 270 seconds); the current pass budget is shown beside the controls.
- **Summarize & continue** finishes the current operation, stops further tool execution, produces a checkpoint summary, then resumes once with a fresh six-round/eight-attempt budget. On an existing limit summary, the checkpoint already exists, so the button resumes directly. It does not create an automatic continuation loop.

Successful lookups are retained in the investigation and reused rather than queried again, including public IP and web lookups. Cached results carry their original timestamps and are marked **cached** in Tool activity. The original request, collected evidence, citations and skipped checks carry forward. Repeating an action proposal returns the existing review and its current status; approval expiry and native verification remain in force. Fresh operational status, packet metadata, display actions and cancellation are never replayed from the lookup cache. A fresh typed question starts a new investigation and allows new measurements. Investigations are held only in memory, expire after ten minutes, and retain at most 64 successful result sets. Only the latest limit summary can resume. Cancel/reset, permission changes, and provider/model/token changes invalidate old controls and findings. There is no separate Continue investigation button.

**Share public destination IPs** separately controls address fields supplied to the model. It starts off. Structured local tool results omit executable paths, private IPs, and packet payloads. Your typed messages are sent as written, except the configured API token is redacted if pasted accidentally. Permission choices persist in the local SQLite database; changing them clears the conversation to prevent older shared context from being reused.

The model can **prepare** app, connection, destination, country/region, country-only and only-app policies; disable or re-enable saved rules; remove disabled rules; and disable the exact set of rules shown in a bulk review. Country-only proposals explicitly specify local-network and unknown-location exceptions. Targets come from discovered opaque references, never model-supplied paths or arbitrary IPs. The local review card displays the exact executable, address, protocol, port and scope. Only the local **Approve block/unblock/task** control executes a frozen proposal. Approvals expire after five minutes and are invalidated by a new message, cancellation, reset or AI credential change. Broad policy changes require an extra scope acknowledgement. Windows administrator access is still required for network rules and live packet capture. Other overlapping rules may continue to block the target; an unverified Windows commit is shown as needing verification.

Chat can show the window or hide it to the tray through a fixed display tool. It can navigate and operate table search, grouping, scope/direction/activity filters, sort, chart adapter/window, profile range/tab/metric, changes/rule filters, pause/resume and local row inspection. It can minimize/show a rule task, read progress, and request cancellation while Windows allows rollback. A running approved task leaves chat available for progress and cancellation. App settings (theme, model/provider, token, sharing/location permissions and update preferences) remain unavailable to tools.

Reviewed app tasks include 5/10/20/30-second packet captures and stopping them, PCAP import, session JSON export, revealing a discovered executable, choosing an executable for a second exact firewall review, dismissing/reopening change groups, saving a reviewed chat explanation on a change, checking/downloading updates, reviewed install/restart with existing guards, and opening the official release/data-source page. File tasks always use local pickers; model-supplied paths are refused. Cancelled dialogs write nothing. Decoded packet bodies, DNS/text summaries, raw headers and private addresses never enter tool results; the model can open the human-readable viewer locally using a discovered packet reference.

No shell commands, arbitrary URLs/file reads, SQL or custom tool installation are exposed. External source text and app metadata are treated as untrusted data. This release's provider flow and Windows operations were tested with simulated responses/transport; no real user token or paid inference was used.

## AI insights and token storage

In **Settings & privacy → AI insights**, choose OpenRouter (the default), OpenAI, or an OpenAI-compatible HTTPS service. Choose an OpenAI model from the **Model** dropdown, or select **Custom model ID…** for other models and compatible services. The curated presets use provider-specific IDs from the [OpenAI model catalog](https://developers.openai.com/api/docs/models) and [OpenRouter catalog](https://openrouter.ai/api/v1/models); account access and pricing vary. Saved custom IDs are preserved, and selecting a model makes no network request. Enter the provider's API token, then select **Save AI settings**. Nonsecret settings are stored in the local traffic SQLite database. A saved token is never returned to the renderer; the password field clears after saving. Changing providers or endpoints requires a new token. **Remove token** deletes the saved encrypted credential.

The token is encrypted using Electron's asynchronous `safeStorage` API backed by Windows DPAPI and stored at **`.watchmen/ai-token.bin` in this working directory**. Nonsecret appearance/provider preferences, update preferences, monitor grouping/filter/search/adapter/chart choices, window size, and the IP lookup choice are stored in the `app_settings` table of `.watchmen/traffic.sqlite`. Existing `settings.json` and `update-settings.json` files are imported once and preserved as legacy backups; subsequent saves use SQLite. The directory is ignored by Git and excluded from packaged builds. The settings screen displays the exact credential path. If Windows encryption is unavailable, token saving fails without writing a plaintext fallback. DPAPI protects stored data from other Windows users; software running as your own Windows account is inside the same trust boundary. See [Electron safeStorage](https://www.electronjs.org/docs/latest/api/safe-storage).

For this repository's packaged build, the working directory is the repository root. A standalone copy falls back to its executable's folder; `WATCHMEN_WORKSPACE_DIR` can explicitly set a different workspace. Moving encrypted credentials to another Windows account or machine may require entering the token again.

Open **AI insights**, then **Preview data to share**. Review the frozen JSON snapshot before selecting **Generate insights**. App names, ports, protocols, connection states, available country/network-owner data, measured byte counts, and up to 20 saved application summaries are included. Saved summaries contain counts, usual ports, dates, and measured lifetime totals, including the current recording; they contain no executable paths or endpoint addresses. The current-connection sample is limited to 120 connections and 50 application summaries. Local addresses, process IDs, executable paths, and packet contents are omitted. Remote IP addresses are off by default and can be explicitly included. Nothing is sent automatically or by the preview step. Provider charges and retention policies apply to generated reviews.

OpenAI uses the [Responses API](https://developers.openai.com/api/docs/guides/migrate-to-responses) with `store: false`; compatible providers use Chat Completions. HTTPS is required, redirects are rejected, and credentials are bound to the configured provider/endpoint. Reviews can be canceled and time out after 60 seconds. The response is rendered as text and cannot execute actions. Insights are hypotheses based on the captured metadata, not malware verdicts. General reports are kept in memory and are not included in traffic exports. Explanations requested from a saved change are retained locally with that alert.

## IP location lookup

Location lookup is **off until you opt in**. Your choice is stored locally and reused on later launches. In **Settings & privacy**, enable it to submit public destination IPs over HTTPS to [ipwho.is](https://ipwhois.io/documentation). Local/reserved addresses and packet contents are not submitted. Country, city, and network owner are approximate, especially with VPNs, proxies, CDNs, and anycast.

Lookups run at roughly one request per second, stop on provider rate limits, and are capped at 1,000 per launch. The provider also imposes a shared daily limit. A network or service failure appears as “Lookup unavailable.” Disabling lookups stops new requests; an already-started request may complete. Successful lookups are cached locally for reuse, and are hidden from the live view while lookup is off. Historical profiles retain previously learned labels.

Traffic metadata is saved locally for persistent profiling. Exported session files also contain endpoint IPs, process paths, and traffic metadata, so treat them as local network records. Live packet contents are held only in memory. Electron retains a stable app profile for its Windows encryption key. Each instance uses a separate temporary disk cache; GPU shader disk caching is disabled to avoid cross-instance file locks.

## Measurement boundaries

- Per-app/destination bytes require successful administrator ETW capture. A dash means unavailable, not zero. Adapter rates work without elevation.
- Adapter rates and ETW bytes measure different layers and can differ. Summing virtual and physical interfaces can count VPN traffic twice; choose one interface for its own measurements.
- TCP and UDP IPv4/IPv6 metadata are supported. The separate on-demand packet inspector captures IPv4 live and reads supported IPv4/IPv6 PCAP files. Network rules can block traffic. Watchmen does not decrypt TLS or actively resolve destination hostnames.
- TCP connection state does not identify who initiated the connection. Download/upload describe byte direction. “Active now” excludes closed/time-wait TCP sockets. Listening sockets are identifiable separately.
- Without ETW, UDP tables show local ownership, not remote peers. ETW adds observed UDP peers when traffic occurs. An event-only connection can appear as “Closed” after its last transfer because no corresponding socket was found in that poll.
- Per-flow totals begin when Watchmen observes traffic. They are not historical OS totals. Process ownership/path can be unavailable for protected or exited processes. PID 0 is explicitly unattributed.
- Old inactive flow records are evicted beyond 10,000 retained entries; exports report the number evicted. Table views render at most 200 groups; exports include all retained flows. Charts retain at most 300 samples. Collection stops when the app exits.
- Export during a paused view contains the latest collector data, not the frozen display.

## Develop and build

Requirements: Windows x64, Node 22.21+ (or a supported newer version), and .NET 9 SDK.

```powershell
npm ci
npm run agent:build
npm run build
npm start
```

`npm run dev` runs a browser UI preview; real collection uses the Electron bridge and is available through `npm start`. Preview mode displays no fabricated traffic.

```powershell
npm test
node scripts/collector-smoke.cjs
npm run test:smoke
node scripts/features-smoke.cjs
node scripts/profile-smoke.cjs
node scripts/inspection-smoke.cjs
npm run package
npm run release:build
node scripts/smoke.cjs --packaged
node scripts/features-smoke.cjs --packaged
node scripts/profile-smoke.cjs --packaged
node scripts/inspection-smoke.cjs --packaged
node scripts/rules-smoke.cjs --packaged
```

The collector smoke test generates controlled loopback TCP/UDP traffic over IPv4 and IPv6, checks process attribution, and checks byte capture when run as administrator. The desktop test exercises live data, grouping, search, the inspector, privacy defaults, pause/resume, JSON export, and the minimum window size. Test outputs and screenshots go in ignored `test-results/`.

Production UI uses a sandboxed renderer with context isolation and narrow IPC methods, no renderer Node access, denied navigation/popups/permissions, and a self-only content-security policy. Windows collection follows [Microsoft TraceEvent](https://github.com/microsoft/perfview) APIs; renderer isolation follows [Electron security guidance](https://www.electronjs.org/docs/latest/tutorial/security).



If a local development network requires Windows certificate trust, Node 22.21 supports `NODE_OPTIONS=--use-system-ca`. An existing Electron ZIP directory can be supplied through `WATCHMEN_ELECTRON_ZIP_DIR` when packaging. TLS verification stays enabled.
