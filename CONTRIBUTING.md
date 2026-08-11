# Contributing to Whodis

Bug reports, protocol edge cases, packaging improvements, documentation fixes,
and focused pull requests are welcome.

## Before opening an issue

- Check existing issues and the latest release.
- Include `whodis --version`, operating system, architecture, command, and
  output format.
- Remove private domain or contact data before posting output publicly.
- Note whether a firewall, proxy, VPN, split DNS, or restricted network could
  affect the result.

Security vulnerabilities should be reported privately as described in
[SECURITY.md](SECURITY.md), not in a public issue.

## Development

Whodis requires Go 1.25 or newer. The native desktop build also needs CMake,
Ninja, Qt 6 Core/Gui/Widgets/Test, and a C++17 compiler.

```sh
git clone https://github.com/Alex9001/whodis.git
cd whodis
go test -race ./...
go vet ./...
```

See [desktop/README.md](desktop/README.md) for GUI build instructions. Keep
network-dependent behavior behind injectable providers or local fixtures;
tests must not consume public registry or Globalping quota.

## Pull requests

- Keep changes focused and explain the user-visible behavior.
- Add regression tests for fixes and tests for new behavior.
- Preserve stable output schemas unless the change is explicitly versioned.
- Run the Go and relevant desktop/package checks before submitting.
- Do not include generated binaries, credentials, tokens, or private lookup
  results.

By contributing, you agree that your contribution is licensed under the MIT
License used by this repository.
