package dev.hg.etchlog.cli.cmd;

import dev.hg.etchlog.cli.io.CliOutput;
import dev.hg.etchlog.cli.io.HttpLogClient;
import dev.hg.etchlog.cli.io.PemPublicKey;
import dev.hg.etchlog.cli.io.ProofJson;
import dev.hg.etchlog.core.proof.ConsistencyVerifier;
import dev.hg.etchlog.core.sth.SthVerifier;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.List;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

/**
 * {@code etchlog verify consistency} — prove the size-{@code M} log is an unmodified, append-only
 * prefix of the size-{@code N} log.
 *
 * <p>Two modes:
 *
 * <ul>
 *   <li><b>Offline</b>: pass {@code --proof} plus the two roots via {@code --old-sth}/{@code
 *       --new-sth} (signature-checked) or raw {@code --old-root}/{@code --new-root}.
 *   <li><b>Online monitoring</b>: pass {@code --url}+{@code --pubkey} and your last-seen STH via
 *       {@code --old-sth} (or {@code --old-root}+{@code --first}). The CLI fetches the current STH
 *       and the consistency proof and checks that history was not rewritten — exactly the cron that
 *       detects a forked or rewritten log.
 * </ul>
 */
@Command(
        name = "consistency",
        description =
                "Verify a consistency proof between two tree sizes against their signed roots.")
public final class VerifyConsistencyCommand implements Callable<Integer> {

    @Spec private CommandSpec spec;

    @Option(
            names = "--proof",
            paramLabel = "<file>",
            description =
                    "Consistency proof JSON {first, second, proof} (- for stdin). Or use --url.")
    private Path proofFile;

    @Option(
            names = "--url",
            paramLabel = "<baseUrl>",
            description =
                    "Fetch the current STH + consistency proof from a server (requires --pubkey and"
                            + " --old-sth, or --old-root with --first).")
    private String url;

    @Option(
            names = "--old-sth",
            paramLabel = "<file>",
            description = "Earlier STH JSON providing the old root (requires --pubkey).")
    private Path oldSthFile;

    @Option(
            names = "--new-sth",
            paramLabel = "<file>",
            description =
                    "Later STH JSON providing the new root (offline mode; requires --pubkey).")
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
            description = "New root hash directly, as an alternative to --new-sth (offline mode).")
    private String newRoot;

    @Option(
            names = "--first",
            paramLabel = "<M>",
            description =
                    "Old tree size M. Required with --url when the old root is given as --old-root.")
    private Long firstOpt;

    @Override
    public Integer call() {
        PrintWriter out = spec.commandLine().getOut();
        PrintWriter err = spec.commandLine().getErr();

        ProofJson.Consistency proof;
        Resolved old;
        Resolved fresh;
        try {
            if (url != null) {
                Online online = acquireOnline();
                proof = online.proof();
                old = online.old();
                fresh = online.fresh();
            } else {
                if (proofFile == null) {
                    throw new IllegalArgumentException("provide --proof (a proof file) or --url");
                }
                proof = ProofJson.readConsistency(proofFile);
                PublicKey publicKey = pubkeyFile != null ? PemPublicKey.load(pubkeyFile) : null;
                old = resolve("old", oldSthFile, oldRoot, proof.first(), publicKey);
                fresh = resolve("new", newSthFile, newRoot, proof.second(), publicKey);
            }
        } catch (Exception e) {
            return CliOutput.inputError(err, e);
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

    /** Online monitoring: fetch the current STH (new root) and the consistency proof from M. */
    private Online acquireOnline() throws Exception {
        if (pubkeyFile == null) {
            throw new IllegalArgumentException("--url requires --pubkey to verify the fetched STH");
        }
        if (newSthFile != null || newRoot != null) {
            throw new IllegalArgumentException(
                    "--url fetches the current STH as the new root; do not pass --new-sth/--new-root");
        }
        PublicKey publicKey = PemPublicKey.load(pubkeyFile);
        HttpLogClient client = new HttpLogClient(url);

        ProofJson.Sth newSth = client.fetchSth();
        long second = newSth.treeSize();
        boolean newSigOk =
                SthVerifier.verify(
                        publicKey,
                        newSth.treeSize(),
                        newSth.timestamp(),
                        newSth.rootHash(),
                        newSth.signature());
        Resolved fresh = new Resolved(newSth.rootHash(), true, !newSigOk);

        long first;
        Resolved old;
        if (oldSthFile != null && oldRoot == null) {
            ProofJson.Sth oldSth = ProofJson.readSth(oldSthFile);
            first = oldSth.treeSize();
            if (firstOpt != null && firstOpt != first) {
                throw new IllegalArgumentException(
                        "--first " + firstOpt + " does not match --old-sth tree_size " + first);
            }
            boolean oldSigOk =
                    SthVerifier.verify(
                            publicKey,
                            oldSth.treeSize(),
                            oldSth.timestamp(),
                            oldSth.rootHash(),
                            oldSth.signature());
            old = new Resolved(oldSth.rootHash(), true, !oldSigOk);
        } else if (oldRoot != null && oldSthFile == null) {
            if (firstOpt == null) {
                throw new IllegalArgumentException(
                        "with --old-root and --url, also provide --first <M> (the old tree size)");
            }
            first = firstOpt;
            old = new Resolved(PemPublicKey.decodeHash(oldRoot), false, false);
        } else {
            throw new IllegalArgumentException(
                    "in --url mode provide the old root via --old-sth or (--old-root + --first)");
        }

        if (first <= 0 || first > second) {
            throw new IllegalArgumentException(
                    "old size " + first + " must be in (0, current size " + second + "]");
        }

        // first == second: nothing appended since last check — no proof needed, roots must match.
        ProofJson.Consistency proof =
                (first == second)
                        ? new ProofJson.Consistency(first, second, List.of())
                        : client.fetchConsistency(first, second);
        return new Online(proof, old, fresh);
    }

    /** Offline root resolution from an STH file (signature-checked) or a raw root. */
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

    private record Online(ProofJson.Consistency proof, Resolved old, Resolved fresh) {}
}
