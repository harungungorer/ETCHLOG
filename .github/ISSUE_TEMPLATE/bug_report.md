---
name: Bug report
about: Report a reproducible defect in Etchlog
title: "bug: "
labels: bug
assignees: ""
---

## Description

<!-- A clear, concise description of what the bug is. -->

## Steps to reproduce

1. 
2. 
3. 

## Expected behaviour

<!-- What you expected to happen. -->

## Actual behaviour

<!-- What actually happened. Include any error messages verbatim. -->

## Environment

| Field | Value |
|-------|-------|
| Etchlog version | <!-- e.g. 0.1.0 or commit SHA --> |
| Runtime | <!-- JVM (e.g. `java -version` output) or GraalVM native binary --> |
| Database | <!-- Postgres (version) / SQLite (demo profile) --> |
| OS | <!-- e.g. Ubuntu 22.04, macOS 14 --> |

## Logs / stack trace

<!--
Paste relevant log output here. Use the DEBUG log level for server issues:

  java -jar etchlog-server.jar --logging.level.dev.hg.etchlog=DEBUG

For proof failures, include the output of the CLI verifier in verbose mode:

  ./etchlog verify inclusion --server http://... --leaf-index N --verbose

It prints the audit path, the recomputed root, and the committed STH root
side by side, which is usually enough to pinpoint the discrepancy.

For crypto-core (jqwik) failures, paste the failing seed — jqwik prints it
on failure so the test is fully reproducible:

  | FailureSample{... seed=1234567890}
-->

```
<paste here>
```

## Additional context

<!--
- Is this a proof-verification failure (inclusion/consistency/STH)?
  If yes, is the log running on Postgres or SQLite?
- Is it reproducible on the JVM build only, the native binary only, or both?
- Security vulnerabilities must NOT be reported here. See the repository
  security policy / GitHub Security Advisories for private disclosure.
-->
