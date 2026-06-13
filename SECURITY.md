# Security Policy

## Project status

`opaque-zig` is pre-1.0, experimental cryptographic software. It has **not**
been independently audited or formally reviewed, and its implementation, API,
and release process are still maturing. Do not rely on it to protect real
secrets or production credentials yet.

## Supported versions

There is no long-term support commitment and no formal Service Level Agreement
(SLA) at this stage. Only the latest `main` is worked on; older commits and any
pre-1.0 tags receive no backported fixes. Expect breaking changes between
releases until a 1.0 line exists.

## Reporting a vulnerability

Please report suspected security issues privately rather than opening a public
issue or pull request.

- Email: **nullstyle@gmail.com**
- Use a clear subject such as `opaque-zig security report`.
- Include a description of the issue, the affected version or commit, and, if
  possible, a minimal reproduction and your assessment of the impact.

If you wish to encrypt your report, mention that in an initial message and we
can arrange a key exchange.

## Response posture

This is a best-effort, volunteer-maintained project. We aim to acknowledge
reports within a reasonable window and to investigate credible issues, but no
specific response, triage, or fix timeline is guaranteed. We will coordinate a
disclosure timeline with you on a case-by-case basis and credit reporters who
wish to be named.

## Scope

Reports about the OPAQUE protocol implementation, the cryptographic suite
components, message parsing/serialization, and the WASM ABI are in scope.
Note the documented threat model in [`docs/threat-model.md`](docs/threat-model.md):
in particular, the library relies on caller-supplied randomness and assumes the
caller does not reuse or substitute values that are required to be fresh. Issues
that depend on violating those documented assumptions may be treated as out of
scope, but a report that clarifies or strengthens the documentation is still
welcome.
