package dev.hg.etchlog.cli;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import dev.hg.etchlog.cli.io.CliOutput;
import dev.hg.etchlog.core.hash.MerkleHash;
import dev.hg.etchlog.core.proof.ConsistencyProof;
import dev.hg.etchlog.core.proof.InclusionProof;
import dev.hg.etchlog.core.sth.Ed25519SthSigner;
import dev.hg.etchlog.core.tree.MerkleTreeHash;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

/**
 * Drives the CLI's online ({@code --url}) mode against an in-process HTTP stub that speaks the
 * Etchlog REST contract. This proves the "thin HTTP client" deliverable end-to-end without standing
 * up the Spring server — and, crucially, that fetching confers <em>no trust</em>: when the stub
 * serves a tampered proof, verification still FAILS.
 */
class CliHttpVerifierTest {

    private static final long TS = 1_700_000_000_000L;

    @TempDir Path dir;

    private final Base64.Encoder b64 = Base64.getEncoder();
    private List<byte[]> leafHashes;
    private List<byte[]> leafData;
    private Ed25519SthSigner signer;
    private Path pubkeyPem;
    private StubServer server;

    @BeforeEach
    void setUp() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        signer = new Ed25519SthSigner(kp.getPrivate());
        pubkeyPem = writePublicKeyPem(kp.getPublic().getEncoded());

        leafData = new ArrayList<>();
        leafHashes = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            byte[] d = ("entry-" + i).getBytes(StandardCharsets.UTF_8);
            leafData.add(d);
            leafHashes.add(MerkleHash.hashLeaf(d));
        }

        server = new StubServer();
        // Default genuine state: current tree size 7.
        server.set("/api/v1/log/sth", sthJson(7));
        server.set("/api/v1/log/proofs/inclusion", inclusionJson(3, 7));
        server.set("/api/v1/log/proofs/consistency", consistencyJson(4, 7));
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    void verifySth_viaUrl_passes() {
        Result r =
                run("verify", "sth", "--url", server.baseUrl(), "--pubkey", pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.OK);
        assertThat(r.out).contains("VERIFIED");
    }

    @Test
    void verifyInclusion_viaUrl_passes() {
        Result r =
                run(
                        "verify", "inclusion",
                        "--url", server.baseUrl(),
                        "--leaf", "entry-3",
                        "--leaf-index", "3",
                        "--pubkey", pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.OK);
        assertThat(r.out).contains("VERIFIED");
    }

    @Test
    void verifyInclusion_viaUrl_failsWhenServerServesTamperedProof() {
        // A malicious server corrupts the audit path: fetching ≠ trusting, so this must FAIL.
        List<byte[]> path = InclusionProof.generate(leafHashes.subList(0, 7), 3, 7);
        path.get(0)[0] ^= 0x01;
        server.set("/api/v1/log/proofs/inclusion", inclusionJson(3, 7, path));

        Result r =
                run(
                        "verify", "inclusion",
                        "--url", server.baseUrl(),
                        "--leaf", "entry-3",
                        "--leaf-index", "3",
                        "--pubkey", pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.VERIFY_FAILED);
        assertThat(r.out).contains("FAILED");
    }

    @Test
    void verifyConsistency_viaUrl_monitoringPasses() throws Exception {
        // The cron use-case: a saved size-4 STH, the server now at size 7.
        Path oldSth = write("old-sth.json", sthJson(4));

        Result r =
                run(
                        "verify", "consistency",
                        "--url", server.baseUrl(),
                        "--old-sth", oldSth.toString(),
                        "--pubkey", pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.OK);
        assertThat(r.out).contains("VERIFIED");
    }

    @Test
    void verifyConsistency_viaUrl_failsWhenServerServesTamperedProof() throws Exception {
        Path oldSth = write("old-sth.json", sthJson(4));
        List<byte[]> nodes = ConsistencyProof.generate(leafHashes.subList(0, 7), 4, 7);
        nodes.get(0)[0] ^= 0x01; // forged/rewritten log: proof can't reconstruct both signed roots
        server.set("/api/v1/log/proofs/consistency", consistencyJson(4, 7, nodes));

        Result r =
                run(
                        "verify", "consistency",
                        "--url", server.baseUrl(),
                        "--old-sth", oldSth.toString(),
                        "--pubkey", pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.VERIFY_FAILED);
        assertThat(r.out).contains("FAILED");
    }

    @Test
    void verifyConsistency_viaUrl_noChangeSinceLastCheck_passes() throws Exception {
        // Last-seen STH equals the current size (7): no proof is fetched, roots must match.
        Path oldSth = write("old-sth.json", sthJson(7));

        Result r =
                run(
                        "verify", "consistency",
                        "--url", server.baseUrl(),
                        "--old-sth", oldSth.toString(),
                        "--pubkey", pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.OK);
        assertThat(r.out).contains("VERIFIED");
    }

    @Test
    void httpError_isInputError_notAVerdict() {
        server.setStatus("/api/v1/log/sth", 500, "{\"error\":\"boom\"}");

        Result r =
                run("verify", "sth", "--url", server.baseUrl(), "--pubkey", pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.INPUT_ERROR);
        assertThat(r.err).contains("HTTP 500");
    }

    // ---- helpers ------------------------------------------------------------------------------

    private record Result(int exit, String out, String err) {}

    private Result run(String... args) {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();
        CommandLine cmd = new CommandLine(new EtchlogCli());
        cmd.setOut(new PrintWriter(out));
        cmd.setErr(new PrintWriter(err));
        int exit = cmd.execute(args);
        return new Result(exit, out.toString(), err.toString());
    }

    private String sthJson(long n) {
        byte[] root = MerkleTreeHash.mth(leafHashes.subList(0, (int) n));
        byte[] sig = signer.sign(n, TS, root);
        return "{\"tree_size\":"
                + n
                + ",\"root_hash\":\""
                + b64.encodeToString(root)
                + "\",\"timestamp\":"
                + TS
                + ",\"ed25519_signature\":\""
                + b64.encodeToString(sig)
                + "\"}";
    }

    private String inclusionJson(long i, long n) {
        return inclusionJson(i, n, InclusionProof.generate(leafHashes.subList(0, (int) n), i, n));
    }

    private String inclusionJson(long i, long n, List<byte[]> auditPath) {
        return "{\"leaf_index\":"
                + i
                + ",\"tree_size\":"
                + n
                + ",\"audit_path\":"
                + arr(auditPath)
                + "}";
    }

    private String consistencyJson(long m, long n) {
        return consistencyJson(
                m, n, ConsistencyProof.generate(leafHashes.subList(0, (int) n), m, n));
    }

    private String consistencyJson(long m, long n, List<byte[]> nodes) {
        return "{\"first\":" + m + ",\"second\":" + n + ",\"proof\":" + arr(nodes) + "}";
    }

    private String arr(List<byte[]> hashes) {
        StringJoiner j = new StringJoiner(",", "[", "]");
        for (byte[] h : hashes) {
            j.add("\"" + b64.encodeToString(h) + "\"");
        }
        return j.toString();
    }

    private Path write(String name, String contents) throws Exception {
        Path p = dir.resolve(name);
        Files.writeString(p, contents);
        return p;
    }

    private Path writePublicKeyPem(byte[] spkiDer) throws Exception {
        String body =
                Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(spkiDer);
        String pem = "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n";
        Path p = dir.resolve("etchlog-public-key.pem");
        Files.writeString(p, pem);
        return p;
    }

    /** A minimal in-process HTTP server returning preset JSON bodies per path. */
    private static final class StubServer {
        private final HttpServer http;
        private final Map<String, int[]> status = new HashMap<>();
        private final Map<String, String> bodies = new HashMap<>();

        StubServer() {
            try {
                http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
            http.createContext(
                    "/",
                    exchange -> {
                        String path = exchange.getRequestURI().getPath();
                        String body = bodies.getOrDefault(path, "{\"error\":\"not found\"}");
                        int code = status.containsKey(path) ? status.get(path)[0] : 200;
                        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "application/json");
                        exchange.sendResponseHeaders(code, bytes.length);
                        exchange.getResponseBody().write(bytes);
                        exchange.close();
                    });
            http.start();
        }

        void set(String path, String body) {
            bodies.put(path, body);
            status.remove(path);
        }

        void setStatus(String path, int code, String body) {
            bodies.put(path, body);
            status.put(path, new int[] {code});
        }

        String baseUrl() {
            return "http://127.0.0.1:" + http.getAddress().getPort();
        }

        void stop() {
            http.stop(0);
        }
    }
}
