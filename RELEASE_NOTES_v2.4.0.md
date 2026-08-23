# Whodis v2.4.0

Whodis 2.4 makes site investigation substantially more useful without turning
the project into a crawler or a synthetic website grader. One bounded homepage
response now produces a granular, evidence-backed technology profile and a
concise set of practical homepage observations.

## Better technology detection

- Stack components can now report a detected version, parent platform,
  descriptive traits, confidence basis, and the total number of evidence
  signals.
- Wappalyzer fingerprints are categorized more precisely. Technologies found
  only through another product's implication are clearly marked low confidence.
- Explicit server, runtime, WordPress, and edge headers retain high-confidence
  evidence and expose useful version information when present.
- WordPress asset paths and markup recognize WooCommerce, Gravity Forms, Ninja
  Forms, ACF, Elementor, Genesis, common cache/optimization plugins, and other
  popular extensions.
- Unrecognized public WordPress plugin and theme slugs remain visible as
  explicitly unmapped observations rather than disappearing from the report.
- Loose page text is not treated as product evidence, and repeated signals are
  deduplicated behind a bounded evidence list.

## Score-free homepage observations

- `whodis investigate` records response protocol, status, encoding, cache
  hints, decoded size, and whether the HTML analysis was truncated.
- Source-level delivery observations cover scripts, blocking hints,
  stylesheets, image markup, preload/preconnect hints, minified filenames, and
  third-party origins without fetching those resources.
- Basic SEO observations cover title, description, canonical, viewport,
  robots directives, H1 count, structured data, Open Graph, and Twitter cards.
- Browser security-header and transport observations cover HTTPS, HSTS, CSP,
  frame protection, nosniff, referrer policy, permissions policy, and insecure
  resource references.
- Lightweight accessibility observations cover document language, image alt
  attributes, and static form labels/ARIA names.
- Deterministic pass, info, and warning observations appear in the normal
  Findings output. There is deliberately no overall score.

## CLI, reports, and desktop

- Terminal and Markdown reports add a compact Homepage observations table and
  show component versions, relationships, confidence basis, and capped evidence.
- One-row-per-target CSV adds homepage URL, status, and summary columns.
- JSON and YAML expose the complete additive homepage profile and structured
  component metadata.
- The native Overview groups platform, commerce, plugins/forms, themes,
  optimization, infrastructure, and homepage observations without adding a
  cluttered new tab.
- Stack remains a master/detail workspace and now shows version, parent,
  traits, basis, and hidden-evidence counts for the selected component.

## Boundaries and compatibility

- Whodis reads no more than the first 1 MiB of one final homepage response. It
  does not execute JavaScript, fetch referenced assets, crawl additional pages,
  calculate Lighthouse/Core Web Vitals, grade a site, or make vulnerability or
  product-absence claims.
- Redirect query strings, credentials, cookie values, and terminal control
  characters are excluded from retained evidence.
- Public report schema remains version 5; the new fields are additive.
- The private GUI protocol remains version 5 and advertises the additive
  `homepage_profile` capability.

The release pipeline builds and verifies the CLI and native GUI for Linux,
Windows, and macOS, then publishes checksums, SBOMs, provenance, installers,
archives, native packages, and the multi-architecture container image.
