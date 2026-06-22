package dev.hg.etchlog.cli.cmd;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

/**
 * {@code etchlog verify} — parent for the three offline verification subcommands. Running {@code
 * verify} with no subcommand prints usage and exits with an error (nothing was verified).
 */
@Command(
        name = "verify",
        description = "Verify inclusion proofs, consistency proofs, and STH signatures offline.",
        subcommands = {
            VerifyInclusionCommand.class,
            VerifyConsistencyCommand.class,
            VerifySthCommand.class
        })
public final class VerifyCommand implements Runnable {

    @Spec private CommandSpec spec;

    @Override
    public void run() {
        throw new ParameterException(
                spec.commandLine(), "Specify a subcommand: inclusion, consistency, or sth.");
    }
}
