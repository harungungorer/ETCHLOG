package dev.hg.etchlog.cli.cmd;

import dev.hg.etchlog.cli.io.CliOutput;
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
 * <p>The root is trusted in one of two ways: pass {@code --sth} + {@code --pubkey} and the STH
 * signature is checked first (recommended — anchors the whole proof to the log's key), or pass a
 * raw {@code --root} you already trust. The leaf is supplied locally ({@code --leaf}/{@code
 * --leaf-file} for raw data the CLI hashes, or {@code --leaf-hash} for a precomputed leaf hash).
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
            required = true,
            paramLabel = "<file>",
            description = "Inclusion proof JSON {leaf_index, tree_size, audit_path} (- for stdin).")
    private Path auditPathFile;

    @Option(
            names = "--sth",
            paramLabel = "<file>",
            description = "STH JSON providing the trusted root (requires --pubkey).")
    private Path sthFile;

    @Option(
            names = "--pubkey",
            paramLabel = "<file>",
            description = "Log's Ed25519 public-key PEM (verifies --sth before trusting its root).")
    private Path pubkeyFile;

    @Option(
            names = "--root",
            paramLabel = "<base64|hex>",
            description = "Trusted root hash directly, as an alternative to --sth/--pubkey.")
    private String root;

    @Option(
            names = "--leaf-index",
            paramLabel = "<i>",
            description = "Optional: cross-check the proof's leaf_index equals this value.")
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
            proof = ProofJson.readInclusion(auditPathFile);

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

            RootSource src = resolveRoot(proof.treeSize());
            // STH signature is itself a verification step: if it fails the root is untrusted, so
            // the
            // inclusion result is a failure, not merely an input error.
            if (src.signatureFailed()) {
                return CliOutput.failed(
                        out,
                        "leaf "
                                + proof.leafIndex()
                                + " — STH signature does NOT match --pubkey; root is untrusted.");
            }
            expectedRoot = src.root();
            rootSignatureChecked = src.signatureChecked();
        } catch (Exception e) {
            return CliOutput.inputError(err, e.getMessage());
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

    /** Resolves the trusted root from --sth/--pubkey or --root (exactly one source). */
    private RootSource resolveRoot(long proofTreeSize) throws Exception {
        boolean haveSth = sthFile != null;
        boolean haveRoot = root != null;
        if (haveSth == haveRoot) {
            throw new IllegalArgumentException(
                    "provide a trusted root via either --sth (with --pubkey) or --root");
        }
        if (haveRoot) {
            return new RootSource(PemPublicKey.decodeHash(root), false, false);
        }
        if (pubkeyFile == null) {
            throw new IllegalArgumentException("--sth requires --pubkey to verify its signature");
        }
        PublicKey publicKey = PemPublicKey.load(pubkeyFile);
        ProofJson.Sth sth = ProofJson.readSth(sthFile);
        if (sth.treeSize() != proofTreeSize) {
            throw new IllegalArgumentException(
                    "STH tree_size "
                            + sth.treeSize()
                            + " does not match proof tree_size "
                            + proofTreeSize
                            + " (fetch the inclusion proof and STH at the same tree size)");
        }
        boolean sigOk =
                SthVerifier.verify(
                        publicKey,
                        sth.treeSize(),
                        sth.timestamp(),
                        sth.rootHash(),
                        sth.signature());
        return new RootSource(sth.rootHash(), true, !sigOk);
    }

    /** The trusted root plus how it was established. */
    private record RootSource(byte[] root, boolean signatureChecked, boolean signatureFailed) {}
}
