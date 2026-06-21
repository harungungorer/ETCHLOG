---
name: Feature request
about: Propose a new capability for Etchlog
title: "feat: "
labels: enhancement
assignees: ""
---

## Before you open this request — check the anti-goals

Etchlog has locked positioning. Requests that conflict with the items below
will be redirected (kindly, but firmly). Please confirm your idea does not:

- [ ] Treat Etchlog as a blockchain, a distributed ledger, or a consensus
      system. It is a **single-operator verifiable log** — no nodes, no tokens,
      no peer network in any version.
- [ ] Benchmark or position Etchlog against Trillian or Rekor on throughput or
      scale. The differentiator is *correctness, approachability, single-binary,
      embeddable, JVM-native* — not raw performance.
- [ ] Use the phrase "tamper-proof." Etchlog is **tamper-evident**: it makes
      tampering *detectable*, not *impossible*.
- [ ] Add deferred-scope features (witness/gossip cosigning, multi-node
      replication, gRPC, public-blockchain anchoring) without a prior discussion
      on the [ROADMAP](../../docs/reference/ROADMAP.md). These items are
      intentionally deferred, not forgotten.

Full anti-goals are documented in the
[CONTRIBUTING guide](../../docs/contributing/CONTRIBUTING.md#honoring-the-anti-goals)
and the [ROADMAP](../../docs/reference/ROADMAP.md#guiding-principles).

---

## Problem / motivation

<!--
What problem does this solve, or what capability gap does it address?
Be specific: who needs this, and in what situation?
-->

## Proposed solution

<!--
Describe the change you'd like. If it touches etchlog-core (proof/hashing
logic, STH format), note that: (a) it will require property-based jqwik
tests, and (b) it must not introduce Spring or JPA dependencies into the core.
-->

## Alternatives considered

<!--
What other approaches did you consider? Why is this one preferred?
-->

## Would you be willing to contribute this?

- [ ] Yes, I can open a PR (with tests)
- [ ] No, I'm requesting it for the maintainers to consider

## Additional context

<!-- Diagrams, prior art, related issues, links to specs (e.g. RFC 6962). -->
