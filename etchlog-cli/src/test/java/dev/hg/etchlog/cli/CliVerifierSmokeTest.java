package dev.hg.etchlog.cli;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.etchlog.cli.io.CliOutput;
import dev.hg.etchlog.core.hash.MerkleHash;
import dev.hg.etchlog.core.proof.ConsistencyProof;
import dev.hg.etchlog.core.proof.InclusionProof;
import dev.hg.etchlog.core.sth.Ed25519SthSigner;
import dev.hg.etchlog.core.tree.MerkleTreeHash;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.StringJoiner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

/**
 * End-to-end smoke tests for the offline verifier CLI: each command verifies real {@code
 * etchlog-core} proofs over server-shaped JSON (standard Base64, snake_case), then the same input
 * tampered to confirm a failure is detected and signalled by a non-zero exit code.
 *
 * <p>This is the M5 "verify-pass and verify-fail-after-tamper" deliverable. Correctness here is the
 * product: the CLI is the trust anchor, so a passing verdict on tampered data would be a false
 * security claim.
 */
class CliVerifierSmokeTest {

    private static final long TS = 1_700_000_000_000L;

    @TempDir Path dir;

    private final Base64.Encoder b64 = Base64.getEncoder();
    private List<byte[]> leafHashes;
    private List<byte[]> leafData;
    private Ed25519SthSigner signer;
    private Path pubkeyPem;

    @BeforeEach
    void setUp() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        signer = new Ed25519SthSigner(kp.getPrivate());
        pubkeyPem = writePublicKeyPem(kp.getPublic().getEncoded());

        // A small log: leaves "entry-0" .. "entry-6".
        leafData = new ArrayList<>();
        leafHashes = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            byte[] d = ("entry-" + i).getBytes(StandardCharsets.UTF_8);
            leafData.add(d);
            leafHashes.add(MerkleHash.hashLeaf(d));
        }
    }

    // ---- verify sth -------------------------------------------------------------------------

    @Test
    void verifySth_passes_forAGenuineSignature() throws Exception {
        Path sth = writeSth(7);
        Result r = run("verify", "sth", "--sth", sth.toString(), "--pubkey", pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.OK);
        assertThat(r.out).contains("VERIFIED");
    }

    @Test
    void verifySth_failsAfterTamperingTheRoot() throws Exception {
        long n = 7;
        byte[] root = MerkleTreeHash.mth(leafHashes.subList(0, (int) n));
        byte[] sig = signer.sign(n, TS, root);
        byte[] tamperedRoot = root.clone();
        tamperedRoot[0] ^= 0x01; // signature no longer matches the (mutated) root
        Path sth = write("sth.json", sthJson(n, tamperedRoot, TS, sig));

        Result r = run("verify", "sth", "--sth", sth.toString(), "--pubkey", pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.VERIFY_FAILED);
        assertThat(r.out).contains("FAILED");
    }

    // ---- verify inclusion -------------------------------------------------------------------

    @Test
    void verifyInclusion_passes_forACommittedLeaf() throws Exception {
        long n = 7;
        long i = 3;
        Path sth = writeSth(n);
        Path proof = writeInclusion(i, n);

        Result r =
                run(
                        "verify",
                        "inclusion",
                        "--leaf",
                        new String(leafData.get((int) i), StandardCharsets.UTF_8),
                        "--audit-path",
                        proof.toString(),
                        "--sth",
                        sth.toString(),
                        "--pubkey",
                        pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.OK);
        assertThat(r.out).contains("VERIFIED");
    }

    @Test
    void verifyInclusion_failsAfterTamperingTheLeafData() throws Exception {
        long n = 7;
        long i = 3;
        Path sth = writeSth(n);
        Path proof = writeInclusion(i, n);

        // Same index and proof, but the operator claims a DIFFERENT leaf value — tamper detected.
        Result r =
                run(
                        "verify",
                        "inclusion",
                        "--leaf",
                        "entry-3-TAMPERED",
                        "--audit-path",
                        proof.toString(),
                        "--sth",
                        sth.toString(),
                        "--pubkey",
                        pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.VERIFY_FAILED);
        assertThat(r.out).contains("FAILED");
    }

    // ---- verify consistency -----------------------------------------------------------------

    @Test
    void verifyConsistency_passes_forAnAppendOnlyPrefix() throws Exception {
        Path oldSth = writeSth("old-sth.json", 4);
        Path newSth = writeSth("new-sth.json", 7);
        Path proof = writeConsistency(4, 7);

        Result r =
                run(
                        "verify",
                        "consistency",
                        "--proof",
                        proof.toString(),
                        "--old-sth",
                        oldSth.toString(),
                        "--new-sth",
                        newSth.toString(),
                        "--pubkey",
                        pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.OK);
        assertThat(r.out).contains("VERIFIED");
    }

    @Test
    void verifyConsistency_failsAfterTamperingAProofNode() throws Exception {
        Path oldSth = writeSth("old-sth.json", 4);
        Path newSth = writeSth("new-sth.json", 7);

        List<byte[]> nodes = ConsistencyProof.generate(leafHashes.subList(0, 7), 4, 7);
        nodes.get(0)[0] ^= 0x01; // corrupt one node: roots can no longer both reconstruct
        Path proof = write("consistency.json", consistencyJson(4, 7, nodes));

        Result r =
                run(
                        "verify",
                        "consistency",
                        "--proof",
                        proof.toString(),
                        "--old-sth",
                        oldSth.toString(),
                        "--new-sth",
                        newSth.toString(),
                        "--pubkey",
                        pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.VERIFY_FAILED);
        assertThat(r.out).contains("FAILED");
    }

    // ---- input/usage --------------------------------------------------------------------------

    @Test
    void missingFile_isAnInputError_notAVerdict() {
        Result r =
                run(
                        "verify",
                        "sth",
                        "--sth",
                        dir.resolve("does-not-exist.json").toString(),
                        "--pubkey",
                        pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.INPUT_ERROR);
        assertThat(r.err).contains("error:");
    }

    @Test
    void version_isReported() {
        Result r = run("--version");
        assertThat(r.exit).isEqualTo(CliOutput.OK);
        assertThat(r.out).contains("etchlog");
    }

    // ---- alternative leaf-input modes (--leaf-file, --leaf-hash) ------------------------------

    @Test
    void verifyInclusion_passes_withLeafFile() throws Exception {
        long n = 7;
        long i = 3;
        Path sth = writeSth(n);
        Path proof = writeInclusion(i, n);
        Path leafBin = write("leaf.bin", new String(leafData.get((int) i), StandardCharsets.UTF_8));

        Result r =
                run(
                        "verify", "inclusion",
                        "--leaf-file", leafBin.toString(),
                        "--audit-path", proof.toString(),
                        "--sth", sth.toString(),
                        "--pubkey", pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.OK);
        assertThat(r.out).contains("VERIFIED");
    }

    @Test
    void verifyInclusion_failsWithLeafFile_afterTamper() throws Exception {
        long n = 7;
        long i = 3;
        Path sth = writeSth(n);
        Path proof = writeInclusion(i, n);
        Path leafBin = write("leaf.bin", "entry-3-TAMPERED");

        Result r =
                run(
                        "verify", "inclusion",
                        "--leaf-file", leafBin.toString(),
                        "--audit-path", proof.toString(),
                        "--sth", sth.toString(),
                        "--pubkey", pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.VERIFY_FAILED);
        assertThat(r.out).contains("FAILED");
    }

    @Test
    void verifyInclusion_passes_withPrecomputedLeafHash() throws Exception {
        long n = 7;
        long i = 3;
        Path sth = writeSth(n);
        Path proof = writeInclusion(i, n);
        String leafHashB64 = b64.encodeToString(leafHashes.get((int) i));

        Result r =
                run(
                        "verify", "inclusion",
                        "--leaf-hash", leafHashB64,
                        "--audit-path", proof.toString(),
                        "--sth", sth.toString(),
                        "--pubkey", pubkeyPem.toString());
        assertThat(r.exit).isEqualTo(CliOutput.OK);
        assertThat(r.out).contains("VERIFIED");
    }

    // ---- raw-root modes (--root, --old-root/--new-root; no STH signature) ---------------------

    @Test
    void verifyInclusion_passes_withRawRoot() throws Exception {
        long n = 7;
        long i = 3;
        Path proof = writeInclusion(i, n);

        Result r =
                run(
                        "verify", "inclusion",
                        "--leaf", leafStr(i),
                        "--audit-path", proof.toString(),
                        "--root", b64.encodeToString(rootAt(n)));
        assertThat(r.exit).isEqualTo(CliOutput.OK);
        assertThat(r.out).contains("supplied root");
    }

    @Test
    void verifyInclusion_failsWithRawRoot_afterTamper() throws Exception {
        long n = 7;
        long i = 3;
        Path proof = writeInclusion(i, n);

        // Correct root, but the operator presents a different leaf value.
        Result r =
                run(
                        "verify",
                        "inclusion",
                        "--leaf",
                        "entry-3-FORGED",
                        "--audit-path",
                        proof.toString(),
                        "--root",
                        b64.encodeToString(rootAt(n)));
        assertThat(r.exit).isEqualTo(CliOutput.VERIFY_FAILED);
        assertThat(r.out).contains("FAILED");
    }

    @Test
    void verifyConsistency_passes_withRawRoots() throws Exception {
        Path proof = writeConsistency(4, 7);

        Result r =
                run(
                        "verify", "consistency",
                        "--proof", proof.toString(),
                        "--old-root", b64.encodeToString(rootAt(4)),
                        "--new-root", b64.encodeToString(rootAt(7)));
        assertThat(r.exit).isEqualTo(CliOutput.OK);
        assertThat(r.out).contains("supplied roots");
    }

    @Test
    void verifyConsistency_failsWithRawRoots_afterTamper() throws Exception {
        // Valid (4 -> 7) proof, but the old root claimed is the size-5 root — not the prefix.
        Path proof = writeConsistency(4, 7);

        Result r =
                run(
                        "verify", "consistency",
                        "--proof", proof.toString(),
                        "--old-root", b64.encodeToString(rootAt(5)),
                        "--new-root", b64.encodeToString(rootAt(7)));
        assertThat(r.exit).isEqualTo(CliOutput.VERIFY_FAILED);
        assertThat(r.out).contains("FAILED");
    }

    // ---- trust ordering: STH signed by the wrong key must be rejected before its root is used --

    @Test
    void verifyInclusion_failsWhenSthSignedByWrongKey() throws Exception {
        long n = 7;
        long i = 3;
        Path sth = writeSth(n); // signed by the genuine key
        Path proof = writeInclusion(i, n);
        Path foreignPub = writeForeignPublicKeyPem(); // an unrelated public key

        Result r =
                run(
                        "verify", "inclusion",
                        "--leaf", leafStr(i),
                        "--audit-path", proof.toString(),
                        "--sth", sth.toString(),
                        "--pubkey", foreignPub.toString());
        assertThat(r.exit).isEqualTo(CliOutput.VERIFY_FAILED);
        assertThat(r.out).contains("FAILED");
        assertThat(r.out).containsIgnoringCase("untrusted");
    }

    @Test
    void verifyConsistency_failsWhenSthSignedByWrongKey() throws Exception {
        Path oldSth = writeSth("old-sth.json", 4);
        Path newSth = writeSth("new-sth.json", 7);
        Path proof = writeConsistency(4, 7);
        Path foreignPub = writeForeignPublicKeyPem();

        Result r =
                run(
                        "verify", "consistency",
                        "--proof", proof.toString(),
                        "--old-sth", oldSth.toString(),
                        "--new-sth", newSth.toString(),
                        "--pubkey", foreignPub.toString());
        assertThat(r.exit).isEqualTo(CliOutput.VERIFY_FAILED);
        assertThat(r.out).contains("FAILED");
        assertThat(r.out).containsIgnoringCase("untrusted");
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

    private Path writeSth(long n) throws Exception {
        return writeSth("sth.json", n);
    }

    private Path writeSth(String name, long n) throws Exception {
        byte[] root = MerkleTreeHash.mth(leafHashes.subList(0, (int) n));
        byte[] sig = signer.sign(n, TS, root);
        return write(name, sthJson(n, root, TS, sig));
    }

    private Path writeInclusion(long i, long n) throws Exception {
        List<byte[]> path = InclusionProof.generate(leafHashes.subList(0, (int) n), i, n);
        return write("inclusion.json", inclusionJson(i, n, path));
    }

    private Path writeConsistency(long m, long n) throws Exception {
        List<byte[]> nodes = ConsistencyProof.generate(leafHashes.subList(0, (int) n), m, n);
        return write("consistency.json", consistencyJson(m, n, nodes));
    }

    private String sthJson(long treeSize, byte[] root, long ts, byte[] sig) {
        return "{\"tree_size\":"
                + treeSize
                + ",\"root_hash\":\""
                + b64.encodeToString(root)
                + "\",\"timestamp\":"
                + ts
                + ",\"ed25519_signature\":\""
                + b64.encodeToString(sig)
                + "\"}";
    }

    private String inclusionJson(long leafIndex, long treeSize, List<byte[]> auditPath) {
        return "{\"leaf_index\":"
                + leafIndex
                + ",\"tree_size\":"
                + treeSize
                + ",\"audit_path\":"
                + b64Array(auditPath)
                + "}";
    }

    private String consistencyJson(long first, long second, List<byte[]> proof) {
        return "{\"first\":"
                + first
                + ",\"second\":"
                + second
                + ",\"proof\":"
                + b64Array(proof)
                + "}";
    }

    private String b64Array(List<byte[]> hashes) {
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
        return writePublicKeyPem("etchlog-public-key.pem", spkiDer);
    }

    private Path writePublicKeyPem(String name, byte[] spkiDer) throws Exception {
        String body =
                Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(spkiDer);
        String pem = "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n";
        Path p = dir.resolve(name);
        Files.writeString(p, pem);
        return p;
    }

    /** A public-key PEM for a DIFFERENT, unrelated Ed25519 key — used to fail signature checks. */
    private Path writeForeignPublicKeyPem() throws Exception {
        KeyPair foreign = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        return writePublicKeyPem("foreign-public-key.pem", foreign.getPublic().getEncoded());
    }

    private String leafStr(long i) {
        return new String(leafData.get((int) i), StandardCharsets.UTF_8);
    }

    private byte[] rootAt(long n) {
        return MerkleTreeHash.mth(leafHashes.subList(0, (int) n));
    }
}
