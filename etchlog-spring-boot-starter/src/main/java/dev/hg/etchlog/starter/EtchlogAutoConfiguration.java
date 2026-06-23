package dev.hg.etchlog.starter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestClient;

/**
 * Auto-configuration for the Etchlog Spring Boot Starter.
 *
 * <p>Activates when {@code etchlog.enabled=true} (the default). Backs off entirely if {@code
 * etchlog.enabled=false}.
 *
 * <p>Both {@code etchlogRestClient} and {@code etchlogClient} beans are
 * {@code @ConditionalOnMissingBean}, so users can override either by declaring their own bean.
 */
@AutoConfiguration
@EnableConfigurationProperties(EtchlogProperties.class)
@ConditionalOnProperty(
        prefix = "etchlog",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
public class EtchlogAutoConfiguration {

    /**
     * Build a {@link RestClient} pre-configured with the Etchlog server base URL, API-key header,
     * connect/read timeouts, and a snake_case JSON converter that handles the server's wire format.
     *
     * <p>If an application overrides this bean (it is {@code @ConditionalOnMissingBean} by name),
     * the replacement <strong>must</strong> retain a Jackson converter using {@link
     * PropertyNamingStrategies#SNAKE_CASE} — the server speaks snake_case, so a default camelCase
     * mapper would silently fail to deserialize STHs and proofs. See {@link
     * #snakeCaseObjectMapper()}.
     *
     * @param props bound configuration properties
     * @return a fully configured RestClient
     * @throws IllegalStateException if {@code etchlog.base-url} is blank
     */
    @Bean
    @ConditionalOnMissingBean(name = "etchlogRestClient")
    public RestClient etchlogRestClient(EtchlogProperties props) {
        String baseUrl = props.getBaseUrl();
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException("etchlog.base-url must be set");
        }

        var requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout((int) props.getConnectTimeout().toMillis());
        requestFactory.setReadTimeout((int) props.getReadTimeout().toMillis());

        RestClient.Builder builder =
                RestClient.builder()
                        .baseUrl(baseUrl)
                        .requestFactory(requestFactory)
                        .messageConverters(
                                converters -> {
                                    converters.removeIf(
                                            c -> c instanceof MappingJackson2HttpMessageConverter);
                                    converters.add(
                                            new MappingJackson2HttpMessageConverter(
                                                    snakeCaseObjectMapper()));
                                });

        if (props.getApiKey() != null && !props.getApiKey().isBlank()) {
            builder = builder.defaultHeader("X-Api-Key", props.getApiKey());
        }

        return builder.build();
    }

    /**
     * Create the default {@link EtchlogClient} bean backed by the auto-configured {@link
     * RestClient}.
     *
     * @param etchlogRestClient the pre-configured RestClient
     * @param props bound configuration properties
     * @return a DefaultEtchlogClient
     */
    @Bean
    @ConditionalOnMissingBean
    public EtchlogClient etchlogClient(RestClient etchlogRestClient, EtchlogProperties props) {
        return new DefaultEtchlogClient(etchlogRestClient, props);
    }

    /**
     * Returns an {@link ObjectMapper} configured with snake_case naming to match the server's wire
     * format. Byte arrays are serialized/deserialized as standard Base64 (Jackson default).
     *
     * <p>This is package-private so tests can reuse it when wiring a mock-based RestClient.
     *
     * @return a snake_case ObjectMapper
     */
    static ObjectMapper snakeCaseObjectMapper() {
        return new ObjectMapper().setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
    }
}
