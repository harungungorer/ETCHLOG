package dev.hg.etchlog.cli.io;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * A deliberately thin read-only HTTP client for the Etchlog REST API, built on the JDK's {@code
 * java.net.http.HttpClient} (no extra dependency). It fetches the STH and proofs so a verifier can
 * check a <em>live</em> log in one command — the headline being the monitoring cron that fetches
 * the current STH and re-checks consistency against its last-seen STH.
 *
 * <p>Fetching is <strong>not</strong> trust. Every byte returned here is re-verified against the
 * log's Ed25519 public key by {@code etchlog-core}; a lying or compromised server cannot make a
 * proof verify against a signed root it does not control. The client only saves the operator from
 * piping {@code curl} output into files.
 */
public final class HttpLogClient {

    private final HttpClient http;
    private final String base; // normalized: no trailing slash
    private final Duration requestTimeout;

    public HttpLogClient(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalArgumentException("--url must not be empty");
        }
        String b = baseUrl.trim();
        while (b.endsWith("/")) {
            b = b.substring(0, b.length() - 1);
        }
        this.base = b;
        this.requestTimeout = Duration.ofSeconds(15);
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    /** GET {@code /api/v1/log/sth} → the current Signed Tree Head. */
    public ProofJson.Sth fetchSth() throws IOException, InterruptedException {
        return ProofJson.parseSth(get("/api/v1/log/sth"));
    }

    /** GET {@code /api/v1/log/proofs/inclusion?leaf_index=I&tree_size=N}. */
    public ProofJson.Inclusion fetchInclusion(long leafIndex, long treeSize)
            throws IOException, InterruptedException {
        return ProofJson.parseInclusion(
                get(
                        "/api/v1/log/proofs/inclusion?leaf_index="
                                + leafIndex
                                + "&tree_size="
                                + treeSize));
    }

    /** GET {@code /api/v1/log/proofs/consistency?first=M&second=N}. */
    public ProofJson.Consistency fetchConsistency(long first, long second)
            throws IOException, InterruptedException {
        return ProofJson.parseConsistency(
                get("/api/v1/log/proofs/consistency?first=" + first + "&second=" + second));
    }

    private String get(String path) throws IOException, InterruptedException {
        HttpRequest req =
                HttpRequest.newBuilder()
                        .uri(URI.create(base + path))
                        .timeout(requestTimeout)
                        .header("Accept", "application/json")
                        .GET()
                        .build();
        HttpResponse<String> resp;
        try {
            resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            // ConnectException and friends often carry a null message — add context so the CLI
            // never reports a bare "error: null" when the server is down or the URL is wrong.
            String m = e.getMessage();
            throw new IOException(
                    "could not reach "
                            + base
                            + path
                            + (m != null ? ": " + m : " (" + e.getClass().getSimpleName() + ")"),
                    e);
        }
        if (resp.statusCode() != 200) {
            throw new IOException(
                    "GET "
                            + base
                            + path
                            + " returned HTTP "
                            + resp.statusCode()
                            + snippet(resp.body()));
        }
        return resp.body();
    }

    private static String snippet(String body) {
        if (body == null || body.isBlank()) {
            return "";
        }
        String s = body.strip();
        return ": " + (s.length() > 200 ? s.substring(0, 200) + "…" : s);
    }
}
