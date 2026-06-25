package dev.hg.etchlog.server.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for {@link SecretFileEnvironmentPostProcessor#resolveSecretFiles(Map)} — the {@code
 * *_FILE} secret resolution that lets the distroless container source secrets (notably the DB
 * password) from file-mounted Docker secrets.
 */
class SecretFileEnvironmentPostProcessorTest {

    @TempDir Path tmp;

    @Test
    void resolvesNameFileEntryToTrimmedFileContents() throws IOException {
        Path secret = tmp.resolve("db_password");
        Files.writeString(secret, "s3cr3t-pw\n"); // trailing newline must be stripped

        Map<String, Object> resolved =
                SecretFileEnvironmentPostProcessor.resolveSecretFiles(
                        Map.of("PGPASSWORD_FILE", secret.toString()));

        assertThat(resolved).containsExactly(Map.entry("PGPASSWORD", "s3cr3t-pw"));
    }

    @Test
    void ignoresNonFileSuffixedVariables() {
        Map<String, Object> resolved =
                SecretFileEnvironmentPostProcessor.resolveSecretFiles(
                        Map.of("PGPASSWORD", "literal", "PATH", "/usr/bin"));

        assertThat(resolved).isEmpty();
    }

    @Test
    void skipsUnreadableSecretPathsInsteadOfFailing() {
        Map<String, Object> resolved =
                SecretFileEnvironmentPostProcessor.resolveSecretFiles(
                        Map.of("PGPASSWORD_FILE", tmp.resolve("does-not-exist").toString()));

        assertThat(resolved).isEmpty();
    }

    @Test
    void ignoresBareSuffixAndBlankValues() {
        Map<String, Object> resolved =
                SecretFileEnvironmentPostProcessor.resolveSecretFiles(
                        Map.of("_FILE", "/whatever", "EMPTY_FILE", "  "));

        assertThat(resolved).isEmpty();
    }
}
