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
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * End-to-end correctness test for the proof and STH endpoints over the full Spring stack. The point
 * is not just response shape but that the proofs the server emits actually <em>verify</em> with the
 * standalone {@code etchlog-core} verifiers against the committed roots — a subtly-wrong proof
 * would be a false security claim. Runs against a real embedded SQLite database.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ProofAndSthControllerTest {

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void sqliteDatasource(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url",
                () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-proofs.db"));
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired PublicKey logPublicKey;

    private static final int N = 8;

    @Test
    void inclusionAndConsistencyProofsVerifyAndSthIsSigned() throws Exception {
        // Append N records and remember their leaf hashes so we can recompute reference roots.
        List<byte[]> leafHashes = new ArrayList<>();
        for (int i = 0; i < N; i++) {
            byte[] payload = ("proof-entry-" + i).getBytes();
            mvc.perform(
                            post("/api/v1/log/entries")
                                    .header("X-Api-Key", "test-api-key")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content("{\"leaf_data\":\"" + b64(payload) + "\"}"))
                    .andExpect(status().isCreated());
            leafHashes.add(MerkleHash.hashLeaf(payload));
        }
        byte[] rootN = MerkleTreeHash.mth(leafHashes);

        // Every leaf's inclusion proof must verify against the size-N root.
        for (int i = 0; i < N; i++) {
            JsonNode body =
                    json.readTree(
                            mvc.perform(
                                            get("/api/v1/log/proofs/inclusion")
                                                    .param("leaf_index", Integer.toString(i))
                                                    .param("tree_size", Integer.toString(N)))
                                    .andExpect(status().isOk())
                                    .andExpect(jsonPath("$.leaf_index").value(i))
                                    .andExpect(jsonPath("$.tree_size").value(N))
                                    .andReturn()
                                    .getResponse()
                                    .getContentAsString());
            List<byte[]> auditPath = decodeArray(body.get("audit_path"));
            assertThat(InclusionVerifier.verify(leafHashes.get(i), i, N, auditPath, rootN))
                    .as("inclusion proof for leaf %d must verify", i)
                    .isTrue();
        }

        // Consistency proofs between several prior sizes and N must verify against both roots.
        for (int m : new int[] {1, 3, 5, 8}) {
            byte[] rootM = MerkleTreeHash.mth(leafHashes.subList(0, m));
            JsonNode body =
                    json.readTree(
                            mvc.perform(
                                            get("/api/v1/log/proofs/consistency")
                                                    .param("first", Integer.toString(m))
                                                    .param("second", Integer.toString(N)))
                                    .andExpect(status().isOk())
                                    .andExpect(jsonPath("$.first").value(m))
                                    .andExpect(jsonPath("$.second").value(N))
                                    .andReturn()
                                    .getResponse()
                                    .getContentAsString());
            List<byte[]> proof = decodeArray(body.get("proof"));
            assertThat(ConsistencyVerifier.verify(m, N, rootM, rootN, proof))
                    .as("consistency proof %d->%d must verify", m, N)
                    .isTrue();
        }

        // GET /sth returns the latest head, which verifies under the log key and matches the root.
        JsonNode sth =
                json.readTree(
                        mvc.perform(get("/api/v1/log/sth"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.tree_size").value(N))
                                .andReturn()
                                .getResponse()
                                .getContentAsString());
        byte[] sthRoot = Base64.getDecoder().decode(sth.get("root_hash").asText());
        byte[] sig = Base64.getDecoder().decode(sth.get("ed25519_signature").asText());
        assertThat(sthRoot).isEqualTo(rootN);
        assertThat(SthVerifier.verify(logPublicKey, N, sth.get("timestamp").asLong(), sthRoot, sig))
                .isTrue();

        // Error behaviours (current size is N here).
        mvc.perform(
                        get("/api/v1/log/proofs/inclusion")
                                .param("leaf_index", "0")
                                .param("tree_size", Integer.toString(N + 1)))
                .andExpect(status().isNotFound()); // tree_size exceeds current log
        mvc.perform(
                        get("/api/v1/log/proofs/inclusion")
                                .param("leaf_index", Integer.toString(N))
                                .param("tree_size", Integer.toString(N)))
                .andExpect(status().isBadRequest()); // leaf_index >= tree_size
        mvc.perform(get("/api/v1/log/proofs/inclusion").param("leaf_index", "0"))
                .andExpect(status().isBadRequest()); // missing tree_size
        mvc.perform(
                        get("/api/v1/log/proofs/consistency")
                                .param("first", "1")
                                .param("second", Integer.toString(N + 1)))
                .andExpect(status().isNotFound()); // second exceeds current log
        mvc.perform(get("/api/v1/log/proofs/consistency").param("first", "5").param("second", "3"))
                .andExpect(status().isBadRequest()); // first > second
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
