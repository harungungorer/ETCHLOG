package dev.hg.etchlog.starter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.queryParam;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import dev.hg.etchlog.core.sth.SignedTreeHead;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class EtchlogAutoConfigurationTest {

    /**
     * 64 zero bytes in standard Base64 — a stand-in STH signature of the correct Ed25519 length.
     * {@link SignedTreeHead} enforces the 64-byte length, so wire-deserialization tests must supply
     * a real-length signature even though these tests only exercise the JSON/Base64 plumbing.
     */
    private static final String SIG_64_B64 =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner()
                    .withConfiguration(AutoConfigurations.of(EtchlogAutoConfiguration.class));

    // -------------------------------------------------------------------------
    // 1. With base-url set: context has EtchlogClient and EtchlogProperties.
    // -------------------------------------------------------------------------

    @Test
    void contextLoadsWithBaseUrl() {
        contextRunner
                .withPropertyValues(
                        "etchlog.base-url=http://localhost:8080", "etchlog.api-key=test-key")
                .run(
                        ctx -> {
                            assertThat(ctx).hasSingleBean(EtchlogClient.class);
                            assertThat(ctx).hasSingleBean(EtchlogProperties.class);

                            EtchlogProperties props = ctx.getBean(EtchlogProperties.class);
                            assertThat(props.getBaseUrl()).isEqualTo("http://localhost:8080");
                            assertThat(props.getApiKey()).isEqualTo("test-key");
                        });
    }

    // -------------------------------------------------------------------------
    // 2. With etchlog.enabled=false: auto-config backs off, no EtchlogClient.
    // -------------------------------------------------------------------------

    @Test
    void backOffWhenDisabled() {
        contextRunner
                .withPropertyValues(
                        "etchlog.enabled=false", "etchlog.base-url=http://localhost:8080")
                .run(ctx -> assertThat(ctx).doesNotHaveBean(EtchlogClient.class));
    }

    // -------------------------------------------------------------------------
    // 3. User-defined EtchlogClient overrides the auto-configured one.
    // -------------------------------------------------------------------------

    @Test
    void userDefinedBeanOverridesAutoConfigured() {
        contextRunner
                .withPropertyValues("etchlog.base-url=http://localhost:8080")
                .withUserConfiguration(CustomClientConfig.class)
                .run(
                        ctx -> {
                            assertThat(ctx).hasSingleBean(EtchlogClient.class);
                            assertThat(ctx.getBean(EtchlogClient.class))
                                    .isInstanceOf(StubEtchlogClient.class);
                        });
    }

    @Configuration
    static class CustomClientConfig {
        @Bean
        EtchlogClient etchlogClient() {
            return new StubEtchlogClient();
        }
    }

    static class StubEtchlogClient implements EtchlogClient {
        @Override
        public AppendResult append(byte[] data) {
            return null;
        }

        @Override
        public java.util.concurrent.CompletableFuture<AppendResult> appendAsync(byte[] data) {
            return null;
        }

        @Override
        public InclusionProofResponse inclusionProof(long leafIndex, long treeSize) {
            return null;
        }

        @Override
        public dev.hg.etchlog.core.sth.SignedTreeHead signedTreeHead() {
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // 4. Append round-trip: snake_case + Base64 deserialization works end-to-end.
    // -------------------------------------------------------------------------

    @Test
    void appendRoundTripDeserializesSnakeCaseAndBase64() {
        // 32 zero bytes in standard Base64.
        final String rootHashB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        // 64 zero bytes — a valid Ed25519 signature length (SignedTreeHead enforces it).
        final String sigB64 = SIG_64_B64;

        String responseJson =
                """
                {"leaf_index":0,"sth":{"tree_size":1,"root_hash":"%s","timestamp":123,"ed25519_signature":"%s"}}
                """
                        .formatted(rootHashB64, sigB64)
                        .strip();

        // Build a RestClient.Builder and bind a MockRestServiceServer to it.
        RestClient.Builder builder =
                RestClient.builder()
                        .baseUrl("http://mock-server")
                        .messageConverters(
                                converters -> {
                                    converters.removeIf(
                                            c -> c instanceof MappingJackson2HttpMessageConverter);
                                    converters.add(
                                            new MappingJackson2HttpMessageConverter(
                                                    EtchlogAutoConfiguration
                                                            .snakeCaseObjectMapper()));
                                });

        MockRestServiceServer mockServer = MockRestServiceServer.bindTo(builder).build();

        mockServer
                .expect(requestTo("http://mock-server/api/v1/log/entries"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(responseJson, MediaType.APPLICATION_JSON));

        // Build the DefaultEtchlogClient directly.
        EtchlogProperties props = new EtchlogProperties();
        props.setBaseUrl("http://mock-server");

        DefaultEtchlogClient client = new DefaultEtchlogClient(builder.build(), props);

        AppendResult result = client.append("hello");

        assertThat(result.leafIndex()).isEqualTo(0L);
        assertThat(result.sth().treeSize()).isEqualTo(1L);
        assertThat(result.sth().rootHash()).hasSize(32);
        assertThat(result.sth().rootHash()).containsOnly((byte) 0);
        assertThat(result.sth().timestamp()).isEqualTo(123L);

        mockServer.verify();
    }

    // -------------------------------------------------------------------------
    // 5. Missing base-url: auto-config context fails with IllegalStateException.
    // -------------------------------------------------------------------------

    @Test
    void failsWhenBaseUrlMissing() {
        contextRunner.run(ctx -> assertThat(ctx).hasFailed());
    }

    // -------------------------------------------------------------------------
    // 6. A 4xx response is non-transient: fail fast, NO retry.
    // -------------------------------------------------------------------------

    @Test
    void clientErrorIsNotRetried() {
        RestClient.Builder builder = mockReadyBuilder();
        MockRestServiceServer mockServer = MockRestServiceServer.bindTo(builder).build();

        // Exactly ONE expectation: if the client retried, a second request would arrive and
        // MockRestServiceServer would fail the call — so verify() proves there was no retry.
        mockServer
                .expect(requestTo("http://mock-server/api/v1/log/entries"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withStatus(HttpStatus.CONFLICT));

        EtchlogProperties props = new EtchlogProperties();
        props.setBaseUrl("http://mock-server");
        // Three attempts allowed — but a 4xx must still fail on the first.
        props.getAppend().getRetry().setMaxAttempts(3);

        DefaultEtchlogClient client = new DefaultEtchlogClient(builder.build(), props);

        assertThatThrownBy(() -> client.append("dup"))
                .isInstanceOf(EtchlogAppendException.class)
                .hasMessageContaining("409");

        mockServer.verify();
    }

    // -------------------------------------------------------------------------
    // 7. fail-open: a transient 5xx is swallowed and a sentinel result returned.
    // -------------------------------------------------------------------------

    @Test
    void failOpenSwallowsTransientFailureAndReturnsSentinel() {
        RestClient.Builder builder = mockReadyBuilder();
        MockRestServiceServer mockServer = MockRestServiceServer.bindTo(builder).build();

        mockServer
                .expect(requestTo("http://mock-server/api/v1/log/entries"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));

        EtchlogProperties props = new EtchlogProperties();
        props.setBaseUrl("http://mock-server");
        props.getAppend().setFailOpen(true);
        props.getAppend().getRetry().setMaxAttempts(1); // one shot, no backoff

        DefaultEtchlogClient client = new DefaultEtchlogClient(builder.build(), props);

        AppendResult result = client.append("event");

        // Sentinel: leafIndex -1 signals a swallowed failure; the record was NOT etched.
        assertThat(result.leafIndex()).isEqualTo(-1L);
        assertThat(result.sth().treeSize()).isEqualTo(0L);

        mockServer.verify();
    }

    // -------------------------------------------------------------------------
    // 8. inclusionProof: exact snake_case query params + Base64 audit-path bytes.
    // -------------------------------------------------------------------------

    @Test
    void inclusionProofUsesSnakeCaseQueryParamsAndDecodesAuditPath() {
        // 32 zero bytes in standard Base64 — a stand-in audit-path node hash.
        final String hashB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        String json =
                """
                {"leaf_index":2,"tree_size":5,"audit_path":["%s","%s"]}"""
                        .formatted(hashB64, hashB64);

        RestClient.Builder builder = mockReadyBuilder();
        MockRestServiceServer mockServer = MockRestServiceServer.bindTo(builder).build();

        // Assert the EXACT snake_case query-param names — a camelCase regression here would
        // produce a runtime 400 with no compile-time warning, so it must be locked down.
        mockServer
                .expect(requestTo(startsWith("http://mock-server/api/v1/log/proofs/inclusion")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(queryParam("leaf_index", "2"))
                .andExpect(queryParam("tree_size", "5"))
                .andRespond(withSuccess(json, MediaType.APPLICATION_JSON));

        EtchlogProperties props = new EtchlogProperties();
        props.setBaseUrl("http://mock-server");
        DefaultEtchlogClient client = new DefaultEtchlogClient(builder.build(), props);

        InclusionProofResponse proof = client.inclusionProof(2L, 5L);

        assertThat(proof.leafIndex()).isEqualTo(2L);
        assertThat(proof.treeSize()).isEqualTo(5L);
        assertThat(proof.auditPath()).hasSize(2);
        assertThat(proof.auditPath().get(0)).hasSize(32);

        mockServer.verify();
    }

    // -------------------------------------------------------------------------
    // 9. signedTreeHead: snake_case + Base64 deserialization to core SignedTreeHead.
    // -------------------------------------------------------------------------

    @Test
    void signedTreeHeadDeserializesToCoreType() {
        final String rootHashB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        final String sigB64 = SIG_64_B64;
        String json =
                """
                {"tree_size":5,"root_hash":"%s","timestamp":999,"ed25519_signature":"%s"}"""
                        .formatted(rootHashB64, sigB64);

        RestClient.Builder builder = mockReadyBuilder();
        MockRestServiceServer mockServer = MockRestServiceServer.bindTo(builder).build();
        mockServer
                .expect(requestTo("http://mock-server/api/v1/log/sth"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(json, MediaType.APPLICATION_JSON));

        EtchlogProperties props = new EtchlogProperties();
        props.setBaseUrl("http://mock-server");
        DefaultEtchlogClient client = new DefaultEtchlogClient(builder.build(), props);

        SignedTreeHead sth = client.signedTreeHead();

        assertThat(sth.treeSize()).isEqualTo(5L);
        assertThat(sth.rootHash()).hasSize(32);
        assertThat(sth.timestamp()).isEqualTo(999L);
        assertThat(sth.signature()).hasSize(64);

        mockServer.verify();
    }

    /** A RestClient.Builder wired with the same snake_case converter the auto-config uses. */
    private static RestClient.Builder mockReadyBuilder() {
        return RestClient.builder()
                .baseUrl("http://mock-server")
                .messageConverters(
                        converters -> {
                            converters.removeIf(
                                    c -> c instanceof MappingJackson2HttpMessageConverter);
                            converters.add(
                                    new MappingJackson2HttpMessageConverter(
                                            EtchlogAutoConfiguration.snakeCaseObjectMapper()));
                        });
    }
}
