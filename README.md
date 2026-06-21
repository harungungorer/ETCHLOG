# Etchlog

> **Etched in — can't be erased.**
> A self-hostable, single-binary **transparency log**: an append-only, cryptographically verifiable record service built on a Merkle tree.

[![Build](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)](#)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](./LICENSE)
[![GraalVM Native](https://img.shields.io/badge/GraalVM-native--image-orange)](#)
[![Java 21](https://img.shields.io/badge/Java-21-007396)](#)
[![Spring Boot 3.x](https://img.shields.io/badge/Spring%20Boot-3.x-6DB33F)](#)

**Last Updated: 2026-06-21**

---

## Table of Contents

- [What is Etchlog?](#what-is-etchlog)
- [Why it matters: the QLDB vacuum](#why-it-matters-the-qldb-vacuum)
- [What Etchlog is NOT](#what-etchlog-is-not)
- [Key Features](#key-features)
- [The tamper demo](#the-tamper-demo)
- [Tech Stack](#tech-stack)
- [5-Minute Quick Start](#5-minute-quick-start)
  - [Option A — Docker Compose](#option-a--docker-compose)
  - [Option B — Native binary](#option-b--native-binary)
  - [Append and verify your first record](#append-and-verify-your-first-record)
- [How it works (60 seconds)](#how-it-works-60-seconds)
- [Project / Module Structure](#project--module-structure)
- [Comparison](#comparison)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
- [Related Documentation](#related-documentation)

---

## What is Etchlog?

Etchlog is an **append-only, cryptographically verifiable log**. Applications append records; anyone can later prove — **without trusting the operator** — that:

- a specific record exists in the log at a given position (an **inclusion proof**), and
- the log's history was never rewritten, truncated, or forked (a **consistency proof**).

It implements the **RFC 6962** Merkle-tree algorithms — the same ones behind Certificate Transparency and Google Trillian — as a clean, approachable, **JVM-native** implementation that ships as a single GraalVM-compiled native binary.

> ℹ️ **Info** — The guarantee is **tamper-evidence, not tamper-prevention.** Etchlog cannot stop someone from appending false data. What it does is make the log **append-only and independently verifiable**, so that any mutation, deletion, reordering, or fork of past history is detectable by anyone holding a previous Signed Tree Head — including auditors who do not trust the operator.

An audit log the operator can silently edit is worthless as evidence. Etchlog makes the log independently verifiable, so even the operator cannot tamper undetectably.

---

## Why it matters: the QLDB vacuum

**AWS retired Amazon QLDB** — its managed ledger database — with end of support on **July 31, 2025**. The official migration path points customers at **Aurora PostgreSQL**, which **drops the cryptographic verifiability** that was QLDB's entire value proposition. Azure SQL Ledger remains cloud-locked.

That leaves a gap: teams who want a verifiable, tamper-evident ledger but **without managed-cloud lock-in**. Etchlog targets exactly that vacated space — a **vendor-neutral, self-hostable** verifiable log.

> 💡 **Tip** — The guiding principle: **a ledger should outlive its operator.** Etchlog is a single binary plus a Postgres database you own. No SaaS, no proprietary format, no vendor that can sunset you.

The verifiable-log ecosystem today is almost entirely Go (Trillian, Sigstore Rekor, immudb). **Etchlog's differentiator is being a clean, correct, self-hostable, single-binary, embeddable, JVM-native implementation** — not scale or feature-parity with Trillian.

---

## What Etchlog is NOT

> ⚠️ **Read this before you evaluate Etchlog.** Honesty about scope is a feature.

- ❌ **Not a blockchain.** No consensus, no distributed nodes, no tokens, no mining. It is a single-operator verifiable log.
- ❌ **Not a Trillian / Rekor competitor on scale.** Do not expect tile-based, billion-entry, multi-sequencer throughput. Etchlog is a single-node sequencer.
- ❌ **Tamper-evident, not tamper-proof.** It makes tampering *detectable*, not *impossible*.
- ❌ **v1 does not solve "who watches the log"** (witness / gossip cosigning). Full guarantees require an external monitor that periodically fetches and verifies Signed Tree Heads. This is a known, intentional v1 limitation tracked in the ROADMAP.

---

## Key Features

| Feature | Description |
|---|---|
| **Append-only log** | Submit a raw payload or a pre-computed leaf hash; receive the assigned leaf index and the resulting Signed Tree Head. |
| **Merkle tree engine** | RFC 6962 leaf/node hashing over all leaves. |
| **Signed Tree Head (STH)** | `{ tree_size, root_hash, timestamp, ed25519_signature }` — the log's tamper-evident commitment to its current state. |
| **Inclusion proofs** | Prove a given leaf is in the log at index *i* for a tree of size *N* (a Merkle **audit path**). |
| **Consistency proofs** | Prove the log at size *M* is an unmodified prefix of the log at size *N* (the append-only / no-rewrite guarantee). |
| **Standalone verifier** | A library + CLI that validates inclusion proofs, consistency proofs, and STH signatures using only a root hash and the log's **Ed25519 public key** — no trust in the server. |
| **REST API + OpenAPI** | Append, get-entry (by index / by hash), inclusion proof, consistency proof, Signed Tree Head — documented via Swagger/OpenAPI. |
| **Appender authorization** | API-key write authentication (Spring Security). **Reads and proofs are public** — that *is* the transparency property. |
| **`etchlog-spring-boot-starter`** | Auto-configuration so any Spring Boot app appends via a single injected bean and a few properties. |
| **Verification dashboard** | React/TS UI: append entries, watch the Merkle tree grow, verify proofs **in-browser**, and run the live tamper-detection demo. |
| **Single-binary distribution** | GraalVM native image, sub-50 ms startup, low memory. |
| **Observability** | Micrometer metrics (append latency, tree size, proof-generation time) on a Prometheus scrape endpoint. |

---

## The tamper demo

The signature demo makes the value visceral in a ~10-second GIF:

1. Append entries → watch the Merkle tree grow.
2. Click an entry → fetch an **inclusion proof** → **verify it in the browser** (the verifier is reimplemented in TypeScript, so the browser does not trust the server).
3. Press the **"Tamper"** button, which mutates a stored leaf **directly in the database**.
4. The next consistency check **fails** and the dashboard **lights up red**.

> 📷 _Placeholder:_ `assets/tamper-demo.gif` — append → grow → verify (green) → tamper → verify (red).

This is the whole thesis in 10 seconds: the operator changed the database, and the math caught it.

---

## Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Language | Java | 21 (LTS) |
| Framework | Spring Boot | 3.x |
| API docs | springdoc-openapi | 2.x |
| Persistence | Spring Data JPA + Flyway | — |
| Primary DB | PostgreSQL | 16+ |
| Embedded DB | SQLite (profile) | 3.x |
| STH signing | Ed25519 (JDK 21 EdDSA / BouncyCastle) | — |
| Security | Spring Security (API-key) | 6.x |
| CLI | Picocli | 4.x |
| Native build | GraalVM Native Image | 21+ |
| Metrics | Micrometer + Prometheus | — |
| Frontend | React + TypeScript + Vite + Tailwind | 18 / 5 / 5 / 3 |
| Testing | JUnit 5, Testcontainers, jqwik (property-based), ArchUnit | — |

See TECH_STACK.md for the justification of each choice.

---

## 5-Minute Quick Start

### Option A — Docker Compose

```bash
git clone https://github.com/harungungorer/etchlog.git
cd etchlog
docker compose up -d
# Server on http://localhost:8080, dashboard on http://localhost:5173
```

This brings up PostgreSQL + the Etchlog server. A demo Ed25519 key and a demo API key are generated on first boot (printed to the logs — **do not use them in production**).

### Option B — Native binary

```bash
# Download the single self-contained binary for your platform from Releases
chmod +x etchlog
# Run with the embedded SQLite profile — zero external dependencies
./etchlog --spring.profiles.active=sqlite
# Startup is sub-50ms; the log lives in ./etchlog.db
```

> 💡 **Tip** — The SQLite profile is perfect for demos, laptops, and air-gapped evaluation. Use the PostgreSQL profile for anything you intend to keep.

### Append and verify your first record

```bash
# 1. Append a record (write requires an API key)
curl -sS -X POST http://localhost:8080/api/v1/log/entries \
  -H "Content-Type: application/json" \
  -d '{"payload":"aGVsbG8gZXRjaGxvZw=="}' \
  -H "X-API-Key: demo-appender-key"   # base64 payload = "hello etchlog"; placeholder key — gitleaks:allow
# → { "leafIndex": 0, "leafHash": "...", "sth": { ... } }

# 2. Fetch an inclusion proof (public — no key needed)
curl -sS "http://localhost:8080/api/v1/log/proofs/inclusion?leafIndex=0&treeSize=1"

# 3. Verify it locally with the CLI — trusting only the public key, NOT the server
etchlog-cli verify-inclusion \
  --leaf-index 0 \
  --tree-size 1 \
  --leaf-hash <leafHash> \
  --root-hash <rootHash> \
  --audit-path <path.json> \
  --public-key etchlog-public.pem
# → ✅ INCLUSION PROOF VALID
```

See QUICK_START.md for the full one-minute walkthrough.

---

## How it works (60 seconds)

Leaves are hashed and combined pairwise into a Merkle tree. The root hash commits to **every** leaf; change any leaf and the root changes.

```
                        root = H(d0..3)            <-- committed by the STH
                       /              \
              H(d0,d1)                H(d2,d3)
              /      \                /      \
        leaf0       leaf1       leaf2        leaf3
       H(0x00‖e0)  H(0x00‖e1)  H(0x00‖e2)   H(0x00‖e3)
         e0          e1          e2           e3        <-- your records

  RFC 6962:  leaf hash  = SHA-256(0x00 ‖ entry)
             node hash  = SHA-256(0x01 ‖ left ‖ right)
```

An **inclusion proof** for `leaf2` is the audit path `[ leaf3, H(d0,d1) ]` — just enough sibling hashes to recompute the root. A **consistency proof** shows that the size-2 tree's root is a prefix-preserving ancestor of the size-4 tree's root. The **STH** signs the root with Ed25519, so the operator cannot present two different histories.

Full detail: MERKLE_LOG_ENGINE.md and PROOFS_AND_VERIFICATION.md.

---

## Project / Module Structure

```
etchlog/
├── etchlog-core/                 # Pure-Java crypto core — ZERO Spring deps (ArchUnit-enforced)
│   ├── MerkleTree                #   RFC 6962 leaf/node hashing, root computation
│   ├── InclusionProof            #   audit-path generation + verification
│   ├── ConsistencyProof          #   prefix-consistency generation + verification
│   └── SignedTreeHead / Ed25519  #   STH construction + signing/verification
├── etchlog-server/               # Spring Boot app: REST API, JPA persistence, security, metrics
│   ├── api/                      #   controllers + DTOs + OpenAPI
│   ├── domain/                   #   sequencer, leaf/node entities
│   └── db/migration/             #   Flyway migrations (Postgres + SQLite)
├── etchlog-spring-boot-starter/  # Auto-config: inject an EtchlogClient to append from any Spring app
├── etchlog-cli/                  # Picocli verifier: validate proofs + STHs offline
└── dashboard/                    # React + TS + Vite: visualize tree, verify in-browser, tamper demo
```

> 🔒 **Security** — `etchlog-core` has **no Spring dependencies** by design. An ArchUnit test fails the build if anyone imports `org.springframework.*` into the crypto core. This keeps the verifier auditable, embeddable, and reusable in the CLI, the dashboard's TS port, and third-party apps. See DEVELOPMENT_GUIDE.md.

---

## Building from source

**Prerequisites**

| Tool | Version | Needed for |
|---|---|---|
| JDK | **21** (LTS) | Java modules — the build targets `release 21` and will fail on an older JDK |
| Maven | bundled via `./mvnw` | no system Maven required |
| Node.js | 20+ (with npm) | the `dashboard/` frontend only |

> ⚠️ The build pins `maven.compiler.release=21`. If your default `java` is older, point `JAVA_HOME` at a JDK 21 install before running the wrapper, e.g. on macOS/Homebrew:
> ```bash
> export JAVA_HOME="$(/usr/libexec/java_home -v 21 2>/dev/null || echo /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home)"
> ```

**Build the JVM modules**

```bash
./mvnw clean package -DskipTests   # build all four modules
./mvnw verify                      # full gate: unit + jqwik property + ArchUnit + Testcontainers
./mvnw -pl etchlog-core test       # crypto core only (fast)
```

**Code style** — the build runs [Spotless](https://github.com/diffplug/spotless) (Google Java Format, AOSP 4-space). Check and auto-fix:

```bash
./mvnw spotless:check   # verify formatting (also runs in verify)
./mvnw spotless:apply   # auto-format the codebase
```

**Build the dashboard** (separate Node project, outside the Maven reactor)

```bash
cd dashboard
npm install
npm run build   # production bundle → dist/
npm test        # in-browser verifier tests
npm run dev     # Vite dev server on :5173
```

---

## Comparison

| | **Etchlog** | Google Trillian | AWS QLDB | Azure SQL Ledger |
|---|---|---|---|---|
| Verifiable (Merkle / RFC 6962) | ✅ | ✅ | ✅ | ✅ |
| Self-hostable | ✅ | ✅ | ❌ (managed) | ❌ (managed) |
| Single binary | ✅ (GraalVM) | ❌ | n/a | n/a |
| JVM-native / embeddable starter | ✅ | ❌ (Go) | ❌ | ❌ |
| Status | Active | Active | **Retired 2025-07-31** | Active (cloud-locked) |
| Scale target | Single node | Massive / tiled | Managed | Managed |
| Witness / cosigning | ❌ v1 | Ecosystem | n/a | n/a |

> ⚠️ **Warning** — Etchlog does **not** compete with Trillian on throughput or scale, and this table is not a benchmark. Pick Trillian for planet-scale CT logs; pick Etchlog when you want a correct, auditable, self-hosted verifiable log you can run as one binary.

---

## Contributing

Contributions are welcome. The short version:

```bash
git clone https://github.com/harungungorer/etchlog.git
cd etchlog
./mvnw verify            # runs unit + Testcontainers + jqwik + ArchUnit checks
```

> ✅ **Do** — Every change to proof logic must come with **jqwik property-based tests** asserting the relevant invariant. A subtly-wrong proof is worse than none — it is a false security claim.

> ❌ **Don't** — Add a Spring (or any framework) import to `etchlog-core`. The ArchUnit boundary test will fail the build.

Full guide: CONTRIBUTING.md.

---

## License

The Etchlog **server** is licensed under **AGPL-3.0**. See [LICENSE](./LICENSE).

> ℹ️ **Open decision** — The reusable `etchlog-spring-boot-starter` may instead ship under **Apache-2.0** to maximize adoption (a client library under AGPL discourages embedding). This is the single open licensing decision, tracked in ROADMAP.md and discussed in OPERATOR_AND_LICENSE_NOTES.md.

---

## Related Documentation

- [LICENSE](./LICENSE) — AGPL-3.0 + the starter-license note
