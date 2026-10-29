## Changes

- Store appearance, AI configuration, updater preferences, monitor filters/grouping and window size in the local traffic SQLite database. Existing JSON settings import once and remain preserved as legacy backups. API tokens retain Windows encryption in their separate file.
- Group connection-change notices by application and change type. Repeated observations no longer grow the badge, inactive notices leave the open count after 24 hours, and temporary remote ports no longer create service notices. Original evidence and history remain available, with a Mark all reviewed control.
- Add verified background downloads from GitHub Releases and a guarded Install & restart action. Pushed changes now build and publish a fresh Windows release automatically.

## Known limits

Large geographic filter sets can still hit Windows resource limits (`0x000005AA`). This release improves diagnostics but does not resolve that backend capacity issue. Windows installer binaries are not Authenticode-signed; download integrity is checked against the GitHub release feed.
