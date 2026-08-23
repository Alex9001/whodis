# Whodis v2.3.0

Whodis 2.3 expands site investigation with a curated research workspace. It
turns each investigated domain and public IP into useful manual pivots without
silently sharing targets with third parties.

## Research workspace

- The native desktop app adds a dedicated **Research** view, grouped by domain,
  IPv4 address, and IPv6 address.
- A single native **Open selected** or **Copy link** action replaces repetitive
  buttons throughout the Stack view.
- Core links cover AlienVault OTX, VirusTotal, BuiltWith, urlscan.io, crt.sh,
  the Wayback Machine, Shodan, and Censys.
- Optional links add Wappalyzer, Netcraft, GreyNoise, AbuseIPDB, BGP.Tools, and
  IPinfo.
- Every link is created locally. A research service receives a target only
  when the user explicitly opens its link.

## Flexible defaults

- `--research-links core|all|off|<id>[,<id>...]` controls links for one CLI
  investigation.
- `whodis config set research-links ...` persists a CLI default, and the
  configuration wizard exposes the same choices.
- The desktop Advanced dialog offers Core, All, Off, and individual provider
  selection, with settings remembered between sessions.
- Existing custom HTTPS investigation-link templates remain supported and can
  be combined with built-in providers.

## Compatibility

- Public report schema remains version 5; JSON and YAML research links retain
  the existing link shape.
- Saved investigations preserve their research-provider selection for replay.
- The private GUI engine protocol advances to version 5 so the engine can send
  the provider catalog and descriptions to the native interface.
- OTX enrichment remains separate and explicitly opt-in with `--enrich otx`.

The release pipeline builds and verifies the CLI and native GUI for Linux,
Windows, and macOS, then publishes checksums, SBOMs, provenance, installers,
archives, native packages, and the multi-architecture container image.
