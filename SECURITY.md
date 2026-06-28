# Security Policy

Etchlog is a tamper-evident transparency log. The correctness of its
cryptographic proofs **is** the product, so security reports — especially
anything affecting proof generation, hashing, or signature verification — are
taken seriously.

## Supported versions

| Version | Supported              |
| ------- | ---------------------- |
| 0.1.x   | ✅ (current)           |
| < 0.1   | ❌                     |

Etchlog is pre-1.0; only the latest released minor receives fixes.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub's
**[Report a vulnerability](https://github.com/harungungorer/ETCHLOG/security/advisories/new)**
(repository **Security → Advisories → Report a vulnerability**). This opens a
private advisory visible only to the maintainer.

Please include:

- the affected component (`etchlog-core` / `etchlog-server` / `etchlog-cli` /
  `etchlog-spring-boot-starter` / `dashboard`) and version,
- a description and, ideally, a minimal reproduction,
- the impact — e.g. a proof that verifies for data **not** in the log, an STH
  forgery, an append-authorization bypass, or a consistency proof that accepts a
  rewritten history.

You can expect an initial acknowledgement within a few days. As a
single-maintainer side project, fix timelines are best-effort; issues in the
cryptographic core are prioritised over everything else.

## Scope

In scope (highest priority):

- A **subtly-incorrect Merkle proof** — an inclusion or consistency proof that
  verifies when it should not. This is a false security claim and is treated as a
  vulnerability, not a bug.
- STH signature forgery or verification bypass (`etchlog-core` Ed25519 path).
- Appender-authorization bypass (writing to the log without a valid API key).

Out of scope (documented, intentional limitations — see
[What Etchlog is NOT](./README.md#what-etchlog-is-not)):

- **Tamper-evident, not tamper-proof.** Etchlog makes tampering *detectable*, not
  impossible. An operator appending false data, or mutating storage, is the
  threat model it is designed to *expose* — not prevent.
- **No witness / gossip cosigning in v1.** Detecting a forked or rewritten history
  requires an external monitor that periodically fetches and verifies Signed Tree
  Heads. The absence of a built-in witness is a known v1 limitation.

## Cryptographic surface

The trust-critical code lives in `etchlog-core` (Merkle hashing,
inclusion/consistency proofs, Ed25519 STH signing) and is covered by
[jqwik](https://jqwik.net/) property-based tests. The module is enforced to have
**zero** framework dependencies (an ArchUnit rule fails the build otherwise), so
the verifier stays auditable and independently reusable. Reports against this
module receive the fastest response.
