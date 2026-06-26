package dev.hg.etchlog.server.web;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.etchlog.server.log.ClientSafeMessage;
import dev.hg.etchlog.server.log.InvalidRequestException;
import dev.hg.etchlog.server.log.ProofNotAvailableException;
import org.junit.jupiter.api.Test;

/**
 * Pins the {@link ClientSafeMessage} allow-list: every exception whose message {@link
 * ApiExceptionHandler} forwards verbatim into the problem {@code detail} must carry the marker. If
 * someone adds a new verbatim-echoed type or drops the marker from an existing one, this test
 * fails, keeping the set of client-visible error messages a curated, reviewed contract rather than
 * letting it drift per throw site.
 */
class ClientSafeMessageContractTest {

    @Test
    void invalidRequestExceptionIsClientSafe() {
        assertThat(ClientSafeMessage.class).isAssignableFrom(InvalidRequestException.class);
    }

    @Test
    void proofNotAvailableExceptionIsClientSafe() {
        assertThat(ClientSafeMessage.class).isAssignableFrom(ProofNotAvailableException.class);
    }

    @Test
    void leafNotFoundExceptionIsClientSafe() {
        assertThat(ClientSafeMessage.class).isAssignableFrom(LeafNotFoundException.class);
    }
}
