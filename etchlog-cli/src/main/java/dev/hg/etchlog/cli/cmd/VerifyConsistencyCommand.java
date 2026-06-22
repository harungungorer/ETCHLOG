package dev.hg.etchlog.cli.cmd;

import dev.hg.etchlog.cli.io.CliOutput;
import dev.hg.etchlog.cli.io.PemPublicKey;
import dev.hg.etchlog.cli.io.ProofJson;
import dev.hg.etchlog.core.proof.ConsistencyVerifier;
import dev.hg.etchlog.core.sth.SthVerifier;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

/**
 * {@code etchlog verify consistency} — prove the size-{@code M} log is an unmodified, append-only
 * prefix of the size-{@code N} log. Running this in a cron against your last-seen STH is exactly
 * how an external monitor detects a forked or rewritten log.
 *
 * <p>Each root is trusted either via a signed STH ({@code --old-sth}/{@code --new-sth} + {@code
 * --pubkey}, recommended) or supplied raw ({@code --old-root}/{@code --new-root}).
 */
@Command(
        name = "consistency",
        description =
                "Verify a consistency proof between two tree sizes against their signed roots.")
public final class VerifyConsistencyCommand implements Callable<Integer> {

    @Spec private CommandSpec spec;

    @Option(
            names = "--proof",
            required = true,
            paramLabel = "<file>",
            description = "Consistency proof JSON {first, second, proof} (- for stdin).")
    private Path proofFile;

    @Option(
            names = "--old-sth",
            paramLabel = "<file>",
            description = "Earlier STH JSON providing the old root (requires --pubkey).")
    private Path oldSthFile;

    @Option(
            names = "--new-sth",
            paramLabel = "<file>",
            description = "Later STH JSON providing the new root (requires --pubkey).")
    private Path newSthFile;

    @Option(
            names = "--pubkey",
            paramLabel = "<file>",
            description = "Log's Ed25519 public-key PEM (verifies the STH signatures).")
    private Path pubkeyFile;

    @Option(
            names = "--old-root",
            paramLabel = "<base64|hex>",
            description = "Old root hash directly, as an alternative to --old-sth.")
    private String oldRoot;

    @Option(
            names = "--new-root",
            paramLabel = "<base64|hex>",
            description = "New root hash directly, as an alternative to --new-sth.")
    private String newRoot;

    @Override
    public Integer call() {
        PrintWriter out = spec.commandLine().getOut();
        PrintWriter err = spec.commandLine().getErr();

        ProofJson.Consistency proof;
        Resolved old;
        Resolved fresh;
        try {
            proof = ProofJson.readConsistency(proofFile);
            PublicKey publicKey = pubkeyFile != null ? PemPublicKey.load(pubkeyFile) : null;
            old = resolve("old", oldSthFile, oldRoot, proof.first(), publicKey);
            fresh = resolve("new", newSthFile, newRoot, proof.second(), publicKey);
        } catch (Exception e) {
            return CliOutput.inputError(err, e.getMessage());
        }

        // A bad STH signature means an untrusted root — report it as a verification failure.
        if (old.signatureFailed() || fresh.signatureFailed()) {
            String which = old.signatureFailed() ? "old" : "new";
            return CliOutput.failed(
                    out,
                    proof.first()
                            + " -> "
                            + proof.second()
                            + " — "
                            + which
                            + " STH signature does NOT match --pubkey; root is untrusted.");
        }

        boolean ok =
                ConsistencyVerifier.verify(
                        proof.first(), proof.second(), old.root(), fresh.root(), proof.proof());

        boolean signed = old.signatureChecked() && fresh.signatureChecked();
        String summary =
                proof.first()
                        + " -> "
                        + proof.second()
                        + " ("
                        + (signed ? "signed roots" : "supplied roots")
                        + ")";
        return ok
                ? CliOutput.verified(out, summary)
                : CliOutput.failed(
                        out,
                        summary
                                + " — size-"
                                + proof.first()
                                + " log is NOT an append-only prefix of size-"
                                + proof.second()
                                + ". History was rewritten, reordered, or truncated.");
    }

    private Resolved resolve(
            String which, Path sthFile, String rawRoot, long expectedSize, PublicKey publicKey)
            throws Exception {
        boolean haveSth = sthFile != null;
        boolean haveRoot = rawRoot != null;
        if (haveSth == haveRoot) {
            throw new IllegalArgumentException(
                    "provide the "
                            + which
                            + " root via either --"
                            + which
                            + "-sth or --"
                            + which
                            + "-root");
        }
        if (haveRoot) {
            return new Resolved(PemPublicKey.decodeHash(rawRoot), false, false);
        }
        if (publicKey == null) {
            throw new IllegalArgumentException(
                    "--" + which + "-sth requires --pubkey to verify its signature");
        }
        ProofJson.Sth sth = ProofJson.readSth(sthFile);
        if (sth.treeSize() != expectedSize) {
            throw new IllegalArgumentException(
                    which
                            + " STH tree_size "
                            + sth.treeSize()
                            + " does not match proof "
                            + (which.equals("old") ? "first" : "second")
                            + " "
                            + expectedSize);
        }
        boolean sigOk =
                SthVerifier.verify(
                        publicKey,
                        sth.treeSize(),
                        sth.timestamp(),
                        sth.rootHash(),
                        sth.signature());
        return new Resolved(sth.rootHash(), true, !sigOk);
    }

    private record Resolved(byte[] root, boolean signatureChecked, boolean signatureFailed) {}
}
