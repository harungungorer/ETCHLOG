/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base URL of the etchlog-server REST API (e.g. http://localhost:8080). */
  readonly VITE_ETCHLOG_BASE_URL?: string;
  /** Optional log Ed25519 public key (PEM) bundled at build time. */
  readonly VITE_ETCHLOG_PUBLIC_KEY?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
