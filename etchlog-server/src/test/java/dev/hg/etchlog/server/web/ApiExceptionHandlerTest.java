package dev.hg.etchlog.server.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Unit-level contract test for {@link ApiExceptionHandler}, wired over a tiny throwing controller
 * with standalone MockMvc. It pins the two information-disclosure guarantees that are awkward to
 * trigger through the full stack:
 *
 * <ul>
 *   <li>a parameter type mismatch (400) names the parameter and expected type but never reflects
 *       the client-supplied raw value back into the body; and
 *   <li>an internal {@link IllegalStateException} (store-corruption invariant) maps to a fixed,
 *       generic 500 that leaks none of the internal coordinates carried by its message.
 * </ul>
 */
class ApiExceptionHandlerTest {

    /** The exact internal message a corrupted store would produce in {@code LogService}. */
    private static final String LEAKY_INTERNAL_MESSAGE =
            "missing materialized node (5, 12) while generating a proof";

    /** A secret-bearing message an unanticipated bug might carry; must never reach the client. */
    private static final String LEAKY_RUNTIME_MESSAGE =
            "secret datasource postgres://user:p4ssw0rd@db.internal/etchlog";

    @RestController
    static class ThrowingController {
        @GetMapping("/typed/{n}")
        String typed(@PathVariable("n") long n) {
            return Long.toString(n);
        }

        @GetMapping("/boom")
        String boom() {
            throw new IllegalStateException(LEAKY_INTERNAL_MESSAGE);
        }

        @GetMapping("/explode")
        String explode() {
            // Not an IllegalState/IllegalArgument/etc. — only the Exception.class catch-all
            // matches.
            throw new RuntimeException(LEAKY_RUNTIME_MESSAGE);
        }
    }

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc =
                MockMvcBuilders.standaloneSetup(new ThrowingController())
                        .setControllerAdvice(new ApiExceptionHandler())
                        .build();
    }

    @Test
    void typeMismatchReturns400WithoutEchoingTheRawValue() throws Exception {
        // The detail names the parameter and its expected type (both fixed by the controller
        // signature) but must never reflect the client-supplied raw value. (The RFC 9457 `instance`
        // field is the request URI itself — the client's own path — so the value legitimately
        // appears there; the guarantee is specifically about the message we generate, `detail`.)
        mvc.perform(get("/typed/not-a-number"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.detail").value("Parameter 'n' must be a valid long."))
                .andExpect(jsonPath("$.detail", not(containsString("not-a-number"))));
    }

    @Test
    void illegalStateReturnsGeneric500WithNoInternalLeak() throws Exception {
        MvcResult res =
                mvc.perform(get("/boom"))
                        .andExpect(status().isInternalServerError())
                        .andExpect(jsonPath("$.status").value(500))
                        .andExpect(
                                jsonPath("$.detail")
                                        .value(
                                                "The request could not be completed due to an"
                                                        + " internal error."))
                        .andReturn();

        // None of the internal coordinates (node level/index, the word "materialized") may surface.
        String body = res.getResponse().getContentAsString();
        assertThat(body).doesNotContain("materialized").doesNotContain("(5, 12)");
    }

    @Test
    void unanticipatedExceptionReturnsGeneric500WithNoLeak() throws Exception {
        // A bare RuntimeException has no specific handler, so the Exception.class catch-all fires.
        // It must log server-side and return the same fixed, generic 500 — leaking nothing.
        MvcResult res =
                mvc.perform(get("/explode"))
                        .andExpect(status().isInternalServerError())
                        .andExpect(jsonPath("$.status").value(500))
                        .andExpect(
                                jsonPath("$.detail")
                                        .value(
                                                "The request could not be completed due to an"
                                                        + " internal error."))
                        .andReturn();

        // The exception message (host, credentials, scheme) must not surface. Note "://" alone is
        // not checked — the RFC 9457 `type` field is legitimately a URI — so assert the secret
        // tokens themselves.
        String body = res.getResponse().getContentAsString();
        assertThat(body)
                .doesNotContain("secret")
                .doesNotContain("p4ssw0rd")
                .doesNotContain("postgres");
    }

    @Test
    void frameworkMethodNotSupportedIsPreservedAs405NotMaskedAs500() throws Exception {
        // POST to a GET-only mapping raises HttpRequestMethodNotSupportedException, which
        // implements
        // ErrorResponse. The catch-all must pass it through with its real 405 status rather than
        // collapsing every framework exception into a generic 500.
        mvc.perform(post("/typed/5")).andExpect(status().isMethodNotAllowed());
    }
}
