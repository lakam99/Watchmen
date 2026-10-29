# Watchmen

A local-first Windows desktop network monitor with a spaceship terminal interface, built with Electron, React, and a native .NET collector. This is an independent app, with no affiliation to Proton.

## Run the desktop app

Open `release/0.9.0/Watchmen-win32-x64/Watchmen.exe`. Keep the entire folder together: the executable needs its adjacent runtime files. The collector runtime is bundled; installing .NET is unnecessary for the packaged app. Releases use versioned folders so a running older version does not block a new build.

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

The Windows updater uses `electron-updater` with the release's `latest.yml` metadata and SHA-512 verification. It ignores prereleases and downgrades. A verified download shows **Install & restart** in Settings and the main monitor. It never installs merely because you close the app. Rule changes and packet capture/import must finish first. Other Watchmen windows must be closed before installation; the updater leaves their processes running. The Windows installer runs per user and creates normal app shortcuts.

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

## AI insights and token storage

In **Settings & privacy → AI insights**, choose OpenRouter (the default), OpenAI, or an OpenAI-compatible HTTPS service. Enter the provider's API token and model ID, then select **Save AI settings**. Nonsecret settings are stored in the local traffic SQLite database. A saved token is never returned to the renderer; the password field clears after saving. Changing providers or endpoints requires a new token. **Remove token** deletes the saved encrypted credential.

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
