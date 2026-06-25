package dev.hg.etchlog.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Etchlog server entry point.
 *
 * <p>Spring Boot REST service hosting the append sequencer, JPA persistence, and proof endpoints.
 * The cryptographic core ({@code etchlog-core}) is framework-free; this module is the only place
 * Spring, JPA, and the web layer live.
 */
@SpringBootApplication
public class EtchlogServerApplication {

    public static void main(String[] args) {
        // `etchlog --healthcheck` is a short-lived readiness probe for the distroless runtime image
        // (no shell/curl to probe HTTP). It must run before Spring starts and exit immediately.
        for (String arg : args) {
            if ("--healthcheck".equals(arg)) {
                System.exit(Healthcheck.run());
            }
        }
        SpringApplication.run(EtchlogServerApplication.class, args);
    }
}
