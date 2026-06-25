package dev.hg.etchlog.server.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
}
