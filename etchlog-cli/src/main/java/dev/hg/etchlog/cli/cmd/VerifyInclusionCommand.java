package dev.hg.etchlog.cli.cmd;

import dev.hg.etchlog.cli.io.CliOutput;
import dev.hg.etchlog.cli.io.HttpLogClient;
import dev.hg.etchlog.cli.io.PemPublicKey;
import dev.hg.etchlog.cli.io.ProofJson;
import dev.hg.etchlog.core.hash.MerkleHash;
import dev.hg.etchlog.core.proof.InclusionVerifier;
import dev.hg.etchlog.core.sth.SthVerifier;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

/**
 * {@code etchlog verify inclusion} — prove a leaf is committed at a given index in a size-{@code N}
 * tree, using only the audit path and a trusted root.
 *
 * <p>Two ways to obtain the proof + root:
 *
 * <ul>
 *   <li><b>Offline</b>: pass {@code --audit-path} (the proof JSON) and a trusted root via {@code
 *       --sth}+{@code --pubkey} (signature checked) or a raw {@code --root}.
 *   <li><b>Online</b>: pass {@code --url}+{@code --pubkey}+{@code --leaf-index} and the CLI fetches
 *       the current STH and the inclusion proof from the server, then verifies the leaf is in the
 *       <em>current</em> tree. The fetched STH's signature is checked before its root is trusted.
 * </ul>
 *
 * <p>The leaf is always supplied locally ({@code --leaf}/{@code --leaf-file} for raw data the CLI
 * hashes, or {@code --leaf-hash} for a precomputed leaf hash).
 */
@Command(
        name = "inclusion",
        description = "Verify an inclusion (audit) proof for a leaf against a signed root.")
public final class VerifyInclusionCommand implements Callable<Integer> {

    @Spec private CommandSpec spec;

    @Option(
            names = "--leaf",
            paramLabel = "<string>",
            description =
                    "Raw leaf data as a UTF-8 string; the CLI computes its RFC 6962 leaf hash.")
    private String leaf;

    @Option(
            names = "--leaf-file",
            paramLabel = "<file>",
            description = "Raw leaf data read from a file; the CLI computes its leaf hash.")
    private Path leafFile;

    @Option(
            names = "--leaf-hash",
            paramLabel = "<base64|hex>",
            description = "Precomputed 32-byte leaf hash (skip local hashing).")
    private String leafHash;

    @Option(
            names = "--audit-path",
            paramLabel = "<file>",
            description = "Inclusion proof JSON {leaf_index, tree_size, audit_path} (- for stdin).")
    private Path auditPathFile;

    @Option(
            names = "--url",
            paramLabel = "<baseUrl>",
            description =
                    "Fetch the current STH + inclusion proof from a server (requires --pubkey and"
                            + " --leaf-index); verifies against the current tree.")
    private String url;

    @Option(
            names = "--sth",
            paramLabel = "<file>",
            description = "STH JSON providing the trusted root (requires --pubkey).")
    private Path sthFile;

    @Option(
            names = "--pubkey",
            paramLabel = "<file>",
            description = "Log's Ed25519 public-key PEM (verifies --sth/--url before trusting it).")
    private Path pubkeyFile;

    @Option(
            names = "--root",
            paramLabel = "<base64|hex>",
            description =
                    "Trusted root hash directly, instead of --sth/--url. Must be the root at the"
                            + " proof's tree_size (a mismatch fails safely, never a false positive).")
    private String root;

    @Option(
            names = "--leaf-index",
            paramLabel = "<i>",
            description = "Leaf index. Required with --url; otherwise cross-checks the proof.")
    private Long leafIndexOpt;

    @Option(
            names = "--tree-size",
            paramLabel = "<N>",
            description = "Optional: cross-check the proof's tree_size equals this value.")
    private Long treeSizeOpt;

    @Override
    public Integer call() {
        PrintWriter out = spec.commandLine().getOut();
        PrintWriter err = spec.commandLine().getErr();

        byte[] leafHashBytes;
        ProofJson.Inclusion proof;
        byte[] expectedRoot;
        boolean rootSignatureChecked;
        try {
            leafHashBytes = resolveLeafHash();

            Acquired acquired = (url != null) ? acquireOnline() : acquireOffline();
            // A bad STH signature means an untrusted root — report it as a verification failure.
            if (acquired.signatureFailed()) {
                return CliOutput.failed(
                        out,
                        "leaf "
                                + acquired.proof().leafIndex()
                                + " — STH signature does NOT match --pubkey; root is untrusted.");
            }
            proof = acquired.proof();
            expectedRoot = acquired.root();
            rootSignatureChecked = acquired.signatureChecked();

            if (leafIndexOpt != null && leafIndexOpt != proof.leafIndex()) {
                return CliOutput.inputError(
                        err,
                        "--leaf-index "
                                + leafIndexOpt
                                + " does not match proof leaf_index "
                                + proof.leafIndex());
            }
            if (treeSizeOpt != null && treeSizeOpt != proof.treeSize()) {
                return CliOutput.inputError(
                        err,
                        "--tree-size "
                                + treeSizeOpt
                                + " does not match proof tree_size "
                                + proof.treeSize());
            }
        } catch (Exception e) {
            return CliOutput.inputError(err, e);
        }

        boolean ok =
                InclusionVerifier.verify(
                        leafHashBytes,
                        proof.leafIndex(),
                        proof.treeSize(),
                        proof.auditPath(),
                        expectedRoot);

        String anchor = rootSignatureChecked ? "signed root" : "supplied root";
        String summary =
                "leaf "
                        + proof.leafIndex()
                        + " in tree_size="
                        + proof.treeSize()
                        + " ("
                        + anchor
                        + ")";
        return ok
                ? CliOutput.verified(out, summary)
                : CliOutput.failed(
                        out,
                        summary
                                + " — audit path does NOT reconstruct the root. The leaf is not"
                                + " committed at this index, or the data was altered.");
    }

    /** Offline: proof from --audit-path, root from --sth (signature-checked) or raw --root. */
    private Acquired acquireOffline() throws Exception {
        if (auditPathFile == null) {
            throw new IllegalArgumentException("provide --audit-path (a proof file) or --url");
        }
        ProofJson.Inclusion proof = ProofJson.readInclusion(auditPathFile);
        boolean haveSth = sthFile != null;
        boolean haveRoot = root != null;
        if (haveSth == haveRoot) {
            throw new IllegalArgumentException(
                    "provide a trusted root via either --sth (with --pubkey) or --root");
        }
        if (haveRoot) {
            return new Acquired(proof, PemPublicKey.decodeHash(root), false, false);
        }
        if (pubkeyFile == null) {
            throw new IllegalArgumentException("--sth requires --pubkey to verify its signature");
        }
        PublicKey publicKey = PemPublicKey.load(pubkeyFile);
        ProofJson.Sth sth = ProofJson.readSth(sthFile);
        if (sth.treeSize() != proof.treeSize()) {
            throw new IllegalArgumentException(
                    "STH tree_size "
                            + sth.treeSize()
                            + " does not match proof tree_size "
                            + proof.treeSize()
                            + " (fetch the inclusion proof and STH at the same tree size)");
        }
        boolean sigOk =
                SthVerifier.verify(
                        publicKey,
                        sth.treeSize(),
                        sth.timestamp(),
                        sth.rootHash(),
                        sth.signature());
        return new Acquired(sth, proof, true, !sigOk);
    }

    /** Online: fetch the current STH and the inclusion proof at the current tree size. */
    private Acquired acquireOnline() throws Exception {
        if (leafIndexOpt == null) {
            throw new IllegalArgumentException("--url requires --leaf-index");
        }
        if (pubkeyFile == null) {
            throw new IllegalArgumentException("--url requires --pubkey to verify the fetched STH");
        }
        if (sthFile != null || root != null || auditPathFile != null) {
            throw new IllegalArgumentException(
                    "--url fetches the STH and proof itself; do not combine it with --sth/--root/--audit-path");
        }
        PublicKey publicKey = PemPublicKey.load(pubkeyFile);
        HttpLogClient client = new HttpLogClient(url);
        ProofJson.Sth sth = client.fetchSth();
        long n = sth.treeSize();
        if (treeSizeOpt != null && treeSizeOpt != n) {
            throw new IllegalArgumentException(
                    "--tree-size "
                            + treeSizeOpt
                            + " != current tree_size "
                            + n
                            + "; --url verifies against the current STH (omit --tree-size, or use"
                            + " --audit-path + --root for a historical size)");
        }
        boolean sigOk =
                SthVerifier.verify(
                        publicKey,
                        sth.treeSize(),
                        sth.timestamp(),
                        sth.rootHash(),
                        sth.signature());
        ProofJson.Inclusion proof = client.fetchInclusion(leafIndexOpt, n);
        return new Acquired(sth, proof, true, !sigOk);
    }

    /** Computes (or accepts) the 32-byte leaf hash from exactly one leaf source. */
    private byte[] resolveLeafHash() throws Exception {
        int sources =
                (leaf != null ? 1 : 0) + (leafFile != null ? 1 : 0) + (leafHash != null ? 1 : 0);
        if (sources != 1) {
            throw new IllegalArgumentException(
                    "provide exactly one of --leaf, --leaf-file, or --leaf-hash");
        }
        if (leafHash != null) {
            return PemPublicKey.decodeHash(leafHash);
        }
        byte[] data =
                leaf != null ? leaf.getBytes(StandardCharsets.UTF_8) : Files.readAllBytes(leafFile);
        return MerkleHash.hashLeaf(data);
    }

    /** The proof plus the trusted root and how it was established. */
    private record Acquired(
            ProofJson.Inclusion proof,
            byte[] root,
            boolean signatureChecked,
            boolean signatureFailed) {

        Acquired(
                ProofJson.Sth sth,
                ProofJson.Inclusion proof,
                boolean signatureChecked,
                boolean signatureFailed) {
            this(proof, sth.rootHash(), signatureChecked, signatureFailed);
        }
    }
}
