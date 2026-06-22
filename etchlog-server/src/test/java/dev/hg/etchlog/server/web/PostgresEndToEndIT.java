package dev.hg.etchlog.server.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.etchlog.core.hash.MerkleHash;
import dev.hg.etchlog.core.proof.ConsistencyVerifier;
import dev.hg.etchlog.core.proof.InclusionVerifier;
import dev.hg.etchlog.core.sth.SthVerifier;
import dev.hg.etchlog.core.tree.MerkleTreeHash;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Full append → prove → verify end-to-end test over the entire HTTP stack against a real
 * <strong>PostgreSQL</strong> (the production store) via Testcontainers — the cross-cutting M3 test
 * deliverable. It drives the public REST API exactly as a client would and then checks, with the
 * standalone {@code etchlog-core} verifiers, that every emitted proof and the signed tree head
 * reconstruct the independently-computed roots. A subtly-wrong proof here would be a false security
 * claim, so this is the headline correctness gate for the server on its primary backend.
 *
 * <p>Requires a running Docker daemon. Named {@code *IT} so it runs under Failsafe (CI), not the
 * unit phase.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("postgres")
@Testcontainers
class PostgresEndToEndIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired PublicKey logPublicKey;

    private static final int N = 7;

    @Test
    void appendProveVerifyAgainstRealPostgres() throws Exception {
        List<byte[]> leafHashes = new ArrayList<>();
        JsonNode lastAppend = null;
        for (int i = 0; i < N; i++) {
            byte[] payload = ("pg-e2e-" + i).getBytes();
            lastAppend =
                    json.readTree(
                            mvc.perform(
                                            post("/api/v1/log/entries")
                                                    .header("X-Api-Key", "test-api-key")
                                                    .contentType(MediaType.APPLICATION_JSON)
                                                    .content(
                                                            "{\"leaf_data\":\""
                                                                    + b64(payload)
                                                                    + "\"}"))
                                    .andExpect(status().isCreated())
                                    .andReturn()
                                    .getResponse()
                                    .getContentAsString());
            leafHashes.add(MerkleHash.hashLeaf(payload));
        }
        byte[] rootN = MerkleTreeHash.mth(leafHashes);

        // The STH returned by the final append must verify under the published log key.
        JsonNode sth = lastAppend.get("sth");
        assertThat(sth.get("tree_size").asLong()).isEqualTo((long) N);
        assertThat(
                        SthVerifier.verify(
                                logPublicKey,
                                N,
                                sth.get("timestamp").asLong(),
                                Base64.getDecoder().decode(sth.get("root_hash").asText()),
                                Base64.getDecoder().decode(sth.get("ed25519_signature").asText())))
                .isTrue();

        // Every leaf's inclusion proof, fetched over HTTP, reconstructs the size-N root.
        for (int i = 0; i < N; i++) {
            JsonNode body =
                    json.readTree(
                            mvc.perform(
                                            get("/api/v1/log/proofs/inclusion")
                                                    .param("leaf_index", Integer.toString(i))
                                                    .param("tree_size", Integer.toString(N)))
                                    .andExpect(status().isOk())
                                    .andReturn()
                                    .getResponse()
                                    .getContentAsString());
            assertThat(
                            InclusionVerifier.verify(
                                    leafHashes.get(i),
                                    i,
                                    N,
                                    decodeArray(body.get("audit_path")),
                                    rootN))
                    .as("inclusion proof for leaf %d", i)
                    .isTrue();
        }

        // Consistency proofs between earlier sizes and N verify against both roots.
        for (int m : new int[] {1, 2, 4, 6}) {
            byte[] rootM = MerkleTreeHash.mth(leafHashes.subList(0, m));
            JsonNode body =
                    json.readTree(
                            mvc.perform(
                                            get("/api/v1/log/proofs/consistency")
                                                    .param("first", Integer.toString(m))
                                                    .param("second", Integer.toString(N)))
                                    .andExpect(status().isOk())
                                    .andReturn()
                                    .getResponse()
                                    .getContentAsString());
            assertThat(
                            ConsistencyVerifier.verify(
                                    m, N, rootM, rootN, decodeArray(body.get("proof"))))
                    .as("consistency proof %d->%d", m, N)
                    .isTrue();
        }

        // Read-back paths: by index and by Base64URL hash return the stored leaf.
        byte[] leaf0Hash = leafHashes.get(0);
        mvc.perform(get("/api/v1/log/entries/0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.leaf_index").value(0));
        String urlHash = Base64.getUrlEncoder().withoutPadding().encodeToString(leaf0Hash);
        mvc.perform(get("/api/v1/log/entries").param("hash", urlHash))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.leaf_index").value(0));
    }

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    private static List<byte[]> decodeArray(JsonNode array) {
        List<byte[]> out = new ArrayList<>();
        for (JsonNode n : array) {
            out.add(Base64.getDecoder().decode(n.asText()));
        }
        return out;
    }
}
