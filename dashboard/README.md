# Etchlog Verification Dashboard

React 18 + TypeScript 5 + Vite 5 + Tailwind CSS 3 frontend for the Etchlog transparency log.

> **Status (Milestone 0):** Scaffold only. The in-browser Merkle-proof verifier ships in Milestone 7.

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
│   ├── App.tsx          # Root component (placeholder)
│   ├── App.test.tsx     # Smoke tests
│   ├── main.tsx         # Entry point
│   └── index.css        # Tailwind directives
├── index.html
├── vite.config.ts
├── tsconfig.json
├── tailwind.config.js
└── postcss.config.js
```
