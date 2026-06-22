package dev.hg.etchlog.server.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit coverage for the appender-auth primitives: deterministic SHA-256 hashing of keys and the
 * fail-closed / demo-detection behaviour of {@link ApiKeyProperties}. Pure JUnit (no Spring) so the
 * security-critical logic is pinned independently of the filter chain.
 */
class ApiKeySecurityTest {

    /** RFC test vector: SHA-256 of the empty input. */
    private static final String SHA256_EMPTY =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    @Test
    void hasherMatchesKnownVectorAndIsDeterministic() {
        assertThat(ApiKeyHasher.sha256Hex("")).isEqualTo(SHA256_EMPTY);
        assertThat(ApiKeyHasher.sha256Hex("a-key")).hasSize(64).matches("[0-9a-f]{64}");
        assertThat(ApiKeyHasher.sha256Hex("a-key")).isEqualTo(ApiKeyHasher.sha256Hex("a-key"));
        assertThat(ApiKeyHasher.sha256Hex("a-key")).isNotEqualTo(ApiKeyHasher.sha256Hex("b-key"));
    }

    @Test
    void resolvedHashesHashEachKeyAndDropBlanks() {
        var props = new ApiKeyProperties(List.of("key-one", " ", "key-two"));
        assertThat(props.resolvedKeyHashes())
                .containsExactlyInAnyOrder(
                        ApiKeyHasher.sha256Hex("key-one"), ApiKeyHasher.sha256Hex("key-two"));
    }

    @Test
    void resolvedHashesTrimSurroundingWhitespace() {
        var props = new ApiKeyProperties(List.of("  spaced-key  "));
        assertThat(props.resolvedKeyHashes()).containsExactly(ApiKeyHasher.sha256Hex("spaced-key"));
    }

    @Test
    void emptyOrNullKeysFailClosed() {
        assertThatThrownBy(() -> new ApiKeyProperties(null).resolvedKeyHashes())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("api-keys");
        assertThatThrownBy(() -> new ApiKeyProperties(List.of()).resolvedKeyHashes())
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new ApiKeyProperties(List.of("", "  ")).resolvedKeyHashes())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void demoKeyIsDetected() {
        assertThat(new ApiKeyProperties(List.of(ApiKeyProperties.DEMO_API_KEY)).usesDemoKey())
                .isTrue();
        assertThat(
                        new ApiKeyProperties(List.of("  " + ApiKeyProperties.DEMO_API_KEY + " "))
                                .usesDemoKey())
                .isTrue();
        assertThat(new ApiKeyProperties(List.of("a-real-key")).usesDemoKey()).isFalse();
        assertThat(new ApiKeyProperties(null).usesDemoKey()).isFalse();
    }
}
