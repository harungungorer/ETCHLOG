# etchlog-spring-boot-starter

Auto-configuration that exposes a single injectable **`EtchlogClient`** bean so any Spring Boot
application can append records to a running [`etchlog-server`](../etchlog-server) over its public
REST API — add one dependency, set a few properties, inject one bean.

> The starter is a thin REST client. It does **not** embed the Merkle engine; the server sequences,
> hashes, and signs. The starter reuses `etchlog-core` only for the `SignedTreeHead` value type so
> the STH it returns can be verified offline with the same core verifier the CLI uses.

**License:** Apache-2.0 (the server is AGPL-3.0 — see [LICENSE note](#license)).

## Add the dependency

```xml
<dependency>
    <groupId>dev.hg.etchlog</groupId>
    <artifactId>etchlog-spring-boot-starter</artifactId>
    <version>0.1.0</version>
</dependency>
```

That is the entire wiring step — no `@Enable…` annotation, no manual `@Bean`. The starter
auto-configures on classpath presence and backs off if `etchlog.enabled=false`.

## Configure

All properties live under the `etchlog` prefix:

```yaml
etchlog:
  enabled: true                       # master switch (default true)
  base-url: https://log.internal:8443 # REQUIRED — URL of the running etchlog-server
  api-key: ${ETCHLOG_API_KEY}         # appender key, sent as X-Api-Key (inject from a secret store)
  connect-timeout: 2s
  read-timeout: 5s
  append:
    mode: SYNC                        # SYNC | ASYNC
    fail-open: false                  # see "Failure handling" below
    retry:
      max-attempts: 3
      backoff: 200ms
```

If `base-url` is blank the context fails fast at startup with a clear message.

> **Security — keep `api-key` out of Actuator output.** Spring Boot 3 sanitizes config
> values by default (`management.endpoint.configprops.show-values` / `env.show-values`
> default to `NEVER`). If your app sets either to `ALWAYS`, ensure `etchlog.api-key` is
> sanitized (its key contains `key`, which the default sanitizer masks) or restrict those
> Actuator endpoints — otherwise the appender key can leak via `/actuator/configprops`.

## Exposed beans

| Bean | Type | Notes |
|------|------|-------|
| `etchlogClient` | `EtchlogClient` | The bean you inject. `@ConditionalOnMissingBean` — declare your own to override (e.g. a fake in tests). |
| `etchlogRestClient` | `RestClient` | Pre-configured base URL, `X-Api-Key` header, timeouts, and a snake_case JSON converter matching the server wire format. Overridable by name. |
| `etchlogProperties` | `EtchlogProperties` | Bound, typed config. |

> **If you override `etchlogRestClient`** (e.g. to add connection pooling), it **must** keep a
> Jackson converter using `PropertyNamingStrategies.SNAKE_CASE` — the server speaks snake_case, so a
> default camelCase mapper would silently fail to deserialize STHs and proofs. Easiest path: start
> from `EtchlogAutoConfiguration.snakeCaseObjectMapper()`.

## Worked example: append-on-write

A payments service that etches an immutable, independently-verifiable record every time an invoice
is marked paid. The returned `leafIndex` is the permanent, provable position in the log — persist it
next to your domain entity so you can later fetch an inclusion proof.

```java
import dev.hg.etchlog.starter.AppendResult;
import dev.hg.etchlog.starter.EtchlogClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class InvoiceService {

    private final InvoiceRepository invoices;
    private final EtchlogClient etchlog;   // injected by the starter — that's all the wiring

    public InvoiceService(InvoiceRepository invoices, EtchlogClient etchlog) {
        this.invoices = invoices;
        this.etchlog = etchlog;
    }

    @Transactional
    public PaidReceipt markPaid(long invoiceId, String payerRef) {
        Invoice inv = invoices.findByIdOrThrow(invoiceId);
        inv.markPaid(payerRef);

        // A canonical, append-only record of the business event.
        String record = """
            {"event":"INVOICE_PAID","invoiceId":%d,"amount":"%s","payerRef":"%s","at":"%s"}"""
            .formatted(invoiceId, inv.getAmount(), payerRef, inv.getPaidAt());

        // Etch it. With fail-open=false (default) an append failure throws and rolls back this
        // @Transactional method, so you never commit a business event that was not etched.
        AppendResult etched = etchlog.append(record);

        // Persist the provable position so we can later produce an inclusion proof.
        inv.setEtchlogLeafIndex(etched.leafIndex());
        invoices.save(inv);

        return new PaidReceipt(invoiceId, etched.leafIndex(), etched.sth());
    }
}
```

Later, prove to an auditor that the record is in the log — without trusting the operator:

```java
public InclusionProofResponse proveInvoicePaid(long invoiceId) {
    Invoice inv = invoices.findByIdOrThrow(invoiceId);
    var sth = etchlog.signedTreeHead();
    return etchlog.inclusionProof(inv.getEtchlogLeafIndex(), sth.treeSize());
    // The auditor verifies this with the CLI or the in-browser verifier using only
    // the log's PUBLIC key.
}
```

## Failure handling

Appending crosses a network boundary. The client retries **transient** failures (IO / connection /
read-timeout and `5xx` responses) up to `max-attempts` with a fixed `backoff`. Non-transient `4xx`
responses (missing/invalid API key, duplicate leaf, bad request) **fail fast without retry**.

- **`fail-open: false`** (default, fail-closed): after exhausting retries, `append()` throws
  `EtchlogAppendException`. Inside a `@Transactional` method this rolls back your business write too.
- **`fail-open: true`**: failures are logged at WARN and `append()` returns a **sentinel**
  `AppendResult` with `leafIndex == -1` (the record was *not* etched); your transaction commits.

> Choose `fail-open` deliberately. For audit-critical events prefer fail-closed, or an outbox pattern
> that re-drives un-etched events without coupling your write availability to the log's.

## Async mode

With `etchlog.append.mode=ASYNC`, use `appendAsync(byte[])` → `CompletableFuture<AppendResult>`. The
append runs on a small bounded pool of **daemon** threads (so it never blocks JVM shutdown).

## License

This module is licensed under **Apache-2.0** (resolved 2026-06-23). The `etchlog-server` and the
remainder of the project tree are licensed under **AGPL-3.0**. The permissive license lets you embed
the starter in a closed-source application. The authoritative license is this module's POM metadata.
