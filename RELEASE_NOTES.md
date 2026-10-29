## Changes

- Add an OpenRouter chatbot in a starship command panel with live tool activity, background responses, cancellation, and session reset.
- Let the assistant inspect current applications/connections, saved traffic profiles, grouped changes, and Watchmen rules through bounded local tools.
- Add opt-in public-IP lookups and cited web research. The app uses fixed HTTPS endpoints, disables the default web plugin, and keeps public-IP sharing off by default. Lookup preferences persist locally; chat and tool results remain in memory.
- Let the assistant prepare persistent app/connection/destination blocks and single-rule unblocks. Exact executable and endpoint scopes are reviewed locally; only a user approval can execute a proposal. Stale/expired reviews, invented targets, unsupported tools, and replayed approvals are refused. Existing administrator and verification requirements still apply.

## Known limits

Use an OpenRouter model with function/tool support. Web research depends on the provider's beta search service and may add charges; IP lookups may be rate-limited. Integration tests simulate model responses and native rule transport; no paid inference or global firewall policy was used in validation. Region/isolation creation and bulk policy changes remain in the manual Network rules view. Large geographic filter sets can still hit Windows resource limits (`0x000005AA`). Windows installer binaries remain unsigned; updater downloads are verified against the release feed.
