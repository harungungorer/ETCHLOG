package dev.hg.etchlog.cli.io;

import java.io.PrintWriter;

/**
 * Human-readable verdict printing and the CLI's exit-code contract.
 *
 * <p>The exit code is the part a monitoring cron actually reads:
 *
 * <ul>
 *   <li>{@link #OK} (0) — cryptographically verified.
 *   <li>{@link #VERIFY_FAILED} (1) — proof/signature did <em>not</em> verify. This is the alert
 *       case: the log may have been forked, rewritten, or the data tampered.
 *   <li>{@link #INPUT_ERROR} (2) — bad input (missing file, malformed JSON/PEM, wrong sizes). Not a
 *       verification result; nothing was proven either way.
 * </ul>
 */
public final class CliOutput {

    public static final int OK = 0;
    public static final int VERIFY_FAILED = 1;
    public static final int INPUT_ERROR = 2;

    private CliOutput() {}

    /** Prints a passing verdict to stdout and returns {@link #OK}. */
    public static int verified(PrintWriter out, String message) {
        out.println("✔ VERIFIED  " + message);
        return OK;
    }

    /** Prints a failing verdict to stdout and returns {@link #VERIFY_FAILED}. */
    public static int failed(PrintWriter out, String message) {
        out.println("✘ FAILED    " + message);
        return VERIFY_FAILED;
    }

    /** Prints an input/usage error to stderr and returns {@link #INPUT_ERROR}. */
    public static int inputError(PrintWriter err, String message) {
        err.println("error: " + message);
        return INPUT_ERROR;
    }

    /**
     * Prints an input/usage error from an exception, falling back to the exception type when its
     * message is {@code null} (e.g. a bare {@code ConnectException}) so the user never sees "error:
     * null".
     */
    public static int inputError(PrintWriter err, Throwable e) {
        String message = e.getMessage();
        return inputError(err, message != null ? message : e.getClass().getSimpleName());
    }
}
