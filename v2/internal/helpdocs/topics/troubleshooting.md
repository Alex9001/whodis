# Troubleshooting

When a result is partial, check the scoped warning before concluding that the target is broken.

- Allow a newly built executable through the local firewall before judging DNS, SMTP, trace, or web probes.
- Note whether a proxy, VPN, split DNS, or custom resolver changes the result.
- Path tracing may require operating-system ICMP permissions.
- Use a longer `--timeout` for slow registries or complex investigations.
- Use `--allow-private` only when intentionally diagnosing managed internal infrastructure.
- Unsigned Windows and macOS desktop packages may require the documented first-launch override.

Use the online documentation for installation and release verification. Report reproducible defects through the GitHub issue tracker without including secrets or private-domain data.
