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
        SpringApplication.run(EtchlogServerApplication.class, args);
    }
}
