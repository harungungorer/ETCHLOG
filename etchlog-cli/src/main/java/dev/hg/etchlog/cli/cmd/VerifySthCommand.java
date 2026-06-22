package dev.hg.etchlog.cli.cmd;

import dev.hg.etchlog.cli.io.CliOutput;
import dev.hg.etchlog.cli.io.HttpLogClient;
import dev.hg.etchlog.cli.io.PemPublicKey;
import dev.hg.etchlog.cli.io.ProofJson;
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
 * {@code etchlog verify sth} — check that an STH's Ed25519 signature was produced by the log's
 * public key. Establishes that a {@code root_hash} is genuinely the log's commitment before it is
 * used to anchor an inclusion or consistency check.
 */
@Command(
        name = "sth",
        description = "Verify a Signed Tree Head's Ed25519 signature against the log's public key.")
public final class VerifySthCommand implements Callable<Integer> {

    @Spec private CommandSpec spec;

    @Option(
            names = "--sth",
            paramLabel = "<file>",
            description = "STH JSON file (use - for stdin). Alternative to --url.")
    private Path sthFile;

    @Option(
            names = "--url",
            paramLabel = "<baseUrl>",
            description =
                    "Fetch the current STH from a running server, e.g. http://localhost:8080.")
    private String url;

    @Option(
            names = "--pubkey",
            required = true,
            paramLabel = "<file>",
            description = "Log's Ed25519 public key, X.509/SPKI PEM ('PUBLIC KEY' block).")
    private Path pubkeyFile;

    @Override
    public Integer call() {
        PrintWriter out = spec.commandLine().getOut();
        PrintWriter err = spec.commandLine().getErr();

        PublicKey publicKey;
        ProofJson.Sth sth;
        try {
            if ((sthFile != null) == (url != null)) {
                throw new IllegalArgumentException("provide exactly one of --sth or --url");
            }
            publicKey = PemPublicKey.load(pubkeyFile);
            sth = (url != null) ? new HttpLogClient(url).fetchSth() : ProofJson.readSth(sthFile);
        } catch (Exception e) {
            return CliOutput.inputError(err, e);
        }

        boolean ok =
                SthVerifier.verify(
                        publicKey,
                        sth.treeSize(),
                        sth.timestamp(),
                        sth.rootHash(),
                        sth.signature());
        String summary = "STH at tree_size=" + sth.treeSize() + " (signature)";
        return ok
                ? CliOutput.verified(out, summary)
                : CliOutput.failed(
                        out,
                        summary
                                + " — signature does NOT match this public key. The STH was not"
                                + " signed by this log, or a signed field was altered.");
    }
}
