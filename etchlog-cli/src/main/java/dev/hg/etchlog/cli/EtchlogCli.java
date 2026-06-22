package dev.hg.etchlog.cli;

import dev.hg.etchlog.cli.cmd.VerifyCommand;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.IVersionProvider;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

/**
 * {@code etchlog} — the offline verifier CLI. It wraps {@code etchlog-core} so anyone can validate
 * inclusion proofs, consistency proofs, and STH signatures from a terminal, a CI job, or a cron
 * monitor with <em>no server trust</em>: the only input that confers trust is the log's Ed25519
 * public key.
 *
 * <p>Exit codes: {@code 0} verified, {@code 1} verification FAILED (alert), {@code 2} bad input.
 */
@Command(
        name = "etchlog",
        mixinStandardHelpOptions = true,
        versionProvider = EtchlogCli.ManifestVersion.class,
        description = "Etchlog offline verifier — don't trust the log, verify it.",
        subcommands = {VerifyCommand.class})
public final class EtchlogCli implements Runnable {

    @Spec private CommandSpec spec;

    @Override
    public void run() {
        // No subcommand given: show usage and exit non-zero (nothing was verified).
        throw new ParameterException(spec.commandLine(), "Specify a command, e.g. 'verify'.");
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new EtchlogCli()).execute(args));
    }

    /**
     * Reports the build version from the jar manifest, falling back when run from the classpath.
     */
    public static final class ManifestVersion implements IVersionProvider {
        @Override
        public String[] getVersion() {
            String v = EtchlogCli.class.getPackage().getImplementationVersion();
            return new String[] {"etchlog " + (v != null ? v : "0.1.0-SNAPSHOT")};
        }
    }
}
