package dev.hg.etchlog.server.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

/**
 * Resolves Docker/Kubernetes-style {@code *_FILE} secrets into ordinary properties at startup.
 *
 * <p>For every environment variable named {@code SOMETHING_FILE} whose value points at a readable
 * file, this contributes a property {@code SOMETHING} holding the file's (trimmed) contents. It
 * lets the production container keep secrets — the database password in particular — in
 * file-mounted Docker secrets rather than in environment values that surface in {@code docker
 * inspect}. The distroless runtime image has no shell to load secrets into env vars itself, so this
 * in-process resolution is the mechanism that makes the documented secret model work (see {@code
 * docker-compose.yml} and {@code docs/deployment/DOCKER_SETUP.md}).
 *
 * <p>Example: {@code PGPASSWORD_FILE=/run/secrets/db_password} makes {@code ${PGPASSWORD}} resolve
 * to the file contents, which the {@code postgres} profile's datasource then consumes.
 *
 * <p>Registered via {@code META-INF/spring.factories}; runs before the application context (and
 * therefore before the datasource) is built.
 */
public class SecretFileEnvironmentPostProcessor implements EnvironmentPostProcessor {

    private static final Logger log =
            LoggerFactory.getLogger(SecretFileEnvironmentPostProcessor.class);

    private static final String SUFFIX = "_FILE";
    private static final String SOURCE_NAME = "etchlogSecretFiles";

    @Override
    public void postProcessEnvironment(
            ConfigurableEnvironment environment, SpringApplication application) {
        Map<String, Object> resolved = resolveSecretFiles(System.getenv());
        if (!resolved.isEmpty()) {
            // addFirst: the file-backed secret must win over the same-named (placeholder default)
            // value so ${PGPASSWORD:etchlog} and relaxed-bound properties pick up the real secret.
            environment.getPropertySources().addFirst(new MapPropertySource(SOURCE_NAME, resolved));
        }
    }

    /**
     * Maps each {@code NAME_FILE} entry whose value is a readable file to {@code NAME -> trimmed
     * file contents}. Package-private for testing; pure function of the supplied environment.
     */
    static Map<String, Object> resolveSecretFiles(Map<String, String> env) {
        Map<String, Object> resolved = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : env.entrySet()) {
            String name = entry.getKey();
            String value = entry.getValue();
            if (!name.endsWith(SUFFIX) || name.length() == SUFFIX.length() || isBlank(value)) {
                continue;
            }
            Path path = Path.of(value);
            if (!Files.isReadable(path)) {
                // Fail soft: an unreadable secret path is a deployment error, but surfacing it as a
                // startup property would be worse. Warn and let the consuming component fail with a
                // clear "missing password/key" message instead.
                log.warn("Secret file referenced by {} is not readable: {}", name, value);
                continue;
            }
            String baseName = name.substring(0, name.length() - SUFFIX.length());
            try {
                resolved.put(baseName, Files.readString(path).strip());
                log.info("Loaded secret for {} from {}", baseName, value);
            } catch (IOException e) {
                log.warn("Failed to read secret file referenced by {}: {}", name, e.getMessage());
            }
        }
        return resolved;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
