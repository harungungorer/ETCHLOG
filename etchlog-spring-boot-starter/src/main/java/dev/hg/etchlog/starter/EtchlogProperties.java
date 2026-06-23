package dev.hg.etchlog.starter;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.convert.DurationUnit;

/**
 * Configuration properties for the Etchlog Spring Boot Starter.
 *
 * <p>All properties are bound under the {@code etchlog} prefix. Example:
 *
 * <pre>{@code
 * etchlog:
 *   base-url: https://log.internal:8443
 *   api-key: ${ETCHLOG_API_KEY}
 *   connect-timeout: 2s
 *   read-timeout: 5s
 *   append:
 *     mode: SYNC
 *     fail-open: false
 *     retry:
 *       max-attempts: 3
 *       backoff: 200ms
 * }</pre>
 */
@ConfigurationProperties(prefix = "etchlog")
public class EtchlogProperties {

    /** Master switch — set {@code false} to disable all auto-configuration. */
    private boolean enabled = true;

    /** Base URL of the running {@code etchlog-server}. Required. */
    private String baseUrl;

    /** Appender API key, sent as {@code X-Api-Key} on every request. */
    private String apiKey;

    /** TCP connect timeout. Accepts Spring duration format (e.g., {@code 2s}). */
    @DurationUnit(ChronoUnit.SECONDS)
    private Duration connectTimeout = Duration.ofSeconds(2);

    /** Response read timeout. Accepts Spring duration format (e.g., {@code 5s}). */
    @DurationUnit(ChronoUnit.SECONDS)
    private Duration readTimeout = Duration.ofSeconds(5);

    private final Append append = new Append();

    /** Append mode: blocking ({@code SYNC}) or non-blocking ({@code ASYNC}). */
    public enum Mode {
        SYNC,
        ASYNC
    }

    /** Nested append configuration. */
    public static class Append {
        private Mode mode = Mode.SYNC;
        private boolean failOpen = false;
        private final Retry retry = new Retry();

        public Mode getMode() {
            return mode;
        }

        public void setMode(Mode mode) {
            this.mode = mode;
        }

        public boolean isFailOpen() {
            return failOpen;
        }

        public void setFailOpen(boolean failOpen) {
            this.failOpen = failOpen;
        }

        public Retry getRetry() {
            return retry;
        }
    }

    /** Retry policy for transient append failures. */
    public static class Retry {
        private int maxAttempts = 3;
        private Duration backoff = Duration.ofMillis(200);

        public int getMaxAttempts() {
            return maxAttempts;
        }

        public void setMaxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
        }

        public Duration getBackoff() {
            return backoff;
        }

        public void setBackoff(Duration backoff) {
            this.backoff = backoff;
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(Duration connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public Duration getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(Duration readTimeout) {
        this.readTimeout = readTimeout;
    }

    public Append getAppend() {
        return append;
    }
}
