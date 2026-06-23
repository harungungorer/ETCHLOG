# Etchlog Verification Dashboard

React 18 + TypeScript 5 + Vite 5 + Tailwind CSS 3 frontend for the Etchlog transparency log.

It appends records, visualizes the Merkle tree, and verifies inclusion & consistency proofs (and
the STH Ed25519 signature) **entirely in the browser** — the server is never trusted for the
verdict. The verifier in `src/verifier/` is an independent TypeScript re-implementation of
`etchlog-core`'s RFC 6962 algorithms, checked for parity against shared core-generated vectors.

## Running against a local server

```bash
# 1) Start etchlog-server with the demo profile (enables the tamper button):
#    ./mvnw -pl etchlog-server spring-boot:run -Dspring-boot.run.profiles=demo
# 2) Start the dashboard — dev proxies /api → http://localhost:8080 (no CORS needed):
npm run dev
```

To point at a server on another origin, set `VITE_ETCHLOG_BASE_URL` (direct mode) instead of using
the proxy. Paste the log's Ed25519 public key (PEM) into the dashboard, or bundle it via
`VITE_ETCHLOG_PUBLIC_KEY`, to also verify the STH signature.

## Prerequisites

- Node 22+
- npm 10+

## Commands

```bash
# Install dependencies
npm install

# Start dev server (http://localhost:5173)
npm run dev

# Production build → dist/
npm run build

# Preview production build locally
npm run preview

# Run tests
npm test
```

## Stack

| Tool | Version |
|------|---------|
| React | 18.x |
| TypeScript | 5.x (strict) |
| Vite | 5.x |
| Tailwind CSS | 3.x |
| Vitest | 2.x |

## Project layout

```
dashboard/
├── src/
│   ├── App.tsx              # Root component: composes the panels + tree, holds verify state
│   ├── api/etchlog.ts       # public REST client (reads, append, demo tamper)
│   ├── verifier/            # standalone TS RFC 6962 verifier (mirrors etchlog-core)
│   │   ├── merkle.ts        # hashing, MTH, verifyInclusion/Consistency, tree model
│   │   ├── sth.ts           # canonical STH encoding + Ed25519 verify (Web Crypto)
│   │   └── encoding.ts      # base64 / base64url / hex / PEM helpers
│   ├── verify/flow.ts       # in-browser verification flows + audit-path highlight
│   ├── hooks/useEtchlogLog.ts
│   ├── components/          # MerkleTreeView, AppendPanel, VerifyPanel, TamperDemo, VerdictBanner
│   └── main.tsx             # Entry point
├── index.html
├── vite.config.ts
├── tsconfig.json
├── tailwind.config.js
└── postcss.config.js
```
