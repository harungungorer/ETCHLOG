# Pull request

## Summary

<!-- One or two sentences: what does this change and why? -->

## Related issue / TASKS.md item

<!--
Link the GitHub issue (Closes #NNN) and the TASKS.md milestone item this PR
addresses (e.g. "M1 — RFC 6962 inclusion-proof generation").
-->

- Closes #
- TASKS.md item:

---

## Checklist

Work through each item before requesting review. A reviewer will check these
mechanically — anything left unchecked needs an explanation in the PR
description.

### Commit hygiene

- [ ] PR title follows **Conventional Commits** style:
      `type(scope): short imperative summary`
      e.g. `feat(core): add consistency-proof verifier`,
      `fix(server): return 409 on duplicate leaf-hash append`,
      `test(core): property test for inclusion proof over any N, i<N`
      (types: `feat`, `fix`, `test`, `docs`, `chore`, `refactor`, `ci`)

### Crypto-core correctness (CRITICAL — read even if you didn't touch the core)

> The items below are **non-negotiable** for any change to `etchlog-core`.
> A subtly-wrong Merkle proof is worse than no proof — it is a false security
> claim. Proofs without property-based tests will be sent back.
> See [CONTRIBUTING — Test Requirements](docs/contributing/CONTRIBUTING.md#test-requirements)
> and [CONTRIBUTING — The Crypto-Core Rule](docs/contributing/CONTRIBUTING.md#the-crypto-core-has-no-spring-deps-rule).

- [ ] **N/A — this PR does not touch `etchlog-core` proof, hashing, or STH logic.**
      *(If checked, skip the three items below.)*

- [ ] Any new or modified **proof generation, proof verification, audit-path
      construction, Merkle hashing, or STH signing** ships with
      **jqwik property-based tests** asserting the relevant invariant
      (e.g. "for any N and any i < N, the inclusion proof verifies against the
      STH root"). Example-based tests alone are not sufficient.

- [ ] A **negative / tamper-detection property** is included: mutating a leaf
      or a path element makes the proof fail against the original root.

- [ ] `etchlog-core` still has **zero Spring / JPA / servlet imports**.
      The ArchUnit rule (`CryptoCorePurityTest`) must stay green.
      (`./mvnw -pl etchlog-core test` is a fast check with no Docker required.)

### Full test gate

- [ ] `./mvnw verify` passes locally — this runs unit tests, jqwik property
      tests, ArchUnit boundary checks, Testcontainers integration tests against
      real Postgres, and the JaCoCo core-coverage gate (> 90% for
      `etchlog-core`).
- [ ] If the dashboard or the in-browser TypeScript verifier was changed:
      `cd dashboard && npm test` passes, and the TS verifier matches
      `etchlog-core` bit for bit on the same vectors.

### Persistence and security

- [ ] No SQL built by string concatenation. All persistence uses Spring Data
      JPA / parameterized JPQL.
- [ ] No signing keys, `.pem` files, `.env` files, or secrets committed.
      (The `.gitignore` excludes `keys/`, `*.pem`, and `.env` — verify
      nothing new slips through.)

### Scope and documentation

- [ ] This PR does **not** introduce anti-goal violations:
      no "tamper-proof" language, no blockchain/consensus framing, no
      Trillian-scale benchmarking claims. See
      [CONTRIBUTING — Honoring the Anti-Goals](docs/contributing/CONTRIBUTING.md#honoring-the-anti-goals).
- [ ] Docs updated if any user-visible behaviour, API shape, or CLI flag
      changed. Terminology is consistent (`leaf`, `auditPath`,
      `InclusionProof`, `ConsistencyProof`, `SignedTreeHead`/`STH`,
      `tamper-evident`).
- [ ] User-visible changes are noted in the PR description so they can be
      captured in release notes.

---

## Notes for reviewers

<!--
Anything that needs extra attention: edge cases exercised, invariant the
property test asserts, migration steps, performance considerations, or
anything that reviewers should scrutinise beyond CI output.

For crypto-core changes specifically: state the invariant your property test
asserts and why that invariant is sufficient. A green CI run is necessary
but not sufficient for core changes — a maintainer must agree the property
tests assert the *right* invariant.
-->
