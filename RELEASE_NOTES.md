## Changes

- Rework Watchmen as a spaceship-style network terminal: graphite instrument panels, cyan telemetry, amber warnings, numbered navigation, square controls, and monospaced labels and measurements.
- Replace promotional headings with direct operational labels. Add a collector status strip showing the acquisition mode, active socket count, last sample time and local database availability from actual monitoring state.
- Apply a shared terminal palette across tables, connection inspectors, profiles, Changes, packet inspection, network rules and settings. Retain dark/light/system appearance, visible keyboard focus, reduced-motion support, and compact layouts down to the existing 1,000-pixel minimum width.

## Known limits

Large geographic filter sets can still hit Windows resource limits (`0x000005AA`); this visual update does not resolve that backend capacity issue. Windows installer binaries are not Authenticode-signed; download integrity is checked against the GitHub release feed. Settings, traffic profiles, credentials, and saved network rules retain their existing storage and behavior.
