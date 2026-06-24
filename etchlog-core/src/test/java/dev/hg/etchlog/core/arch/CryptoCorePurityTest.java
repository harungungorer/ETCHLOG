package dev.hg.etchlog.core.arch;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.Test;

/**
 * Enforces the non-negotiable boundary: {@code etchlog-core} is pure Java and must never depend on
 * Spring, JPA/Jakarta persistence, the servlet/web stack, BouncyCastle, or observability libraries
 * (Micrometer / the Prometheus client). The same code has to run unchanged in the server, the CLI,
 * and as the reference for the browser verifier — any framework import here breaks that and fails
 * the build. Metrics are instrumented in {@code etchlog-server} by wrapping core calls, never inside
 * core itself (see {@code docs/operations/MONITORING_LOGGING.md}).
 */
public class CryptoCorePurityTest {

    private static final JavaClasses CORE =
            new ClassFileImporter()
                    .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                    .importPackages("dev.hg.etchlog.core");

    @Test
    void coreHasNoSpringDependency() {
        ArchRule rule =
                noClasses()
                        .should()
                        .dependOnClassesThat()
                        .resideInAnyPackage("org.springframework..")
                        .as("etchlog-core must not depend on Spring");
        rule.check(CORE);
    }

    @Test
    void coreHasNoPersistenceOrWebDependency() {
        ArchRule rule =
                noClasses()
                        .should()
                        .dependOnClassesThat()
                        .resideInAnyPackage(
                                "jakarta.persistence..",
                                "jakarta.servlet..",
                                "jakarta.ws.rs..",
                                "javax.persistence..",
                                "org.hibernate..")
                        .as("etchlog-core must not depend on JPA or the web/servlet/JAX-RS stack");
        rule.check(CORE);
    }

    @Test
    void coreUsesOnlyTheJdkCryptoProvider() {
        ArchRule rule =
                noClasses()
                        .should()
                        .dependOnClassesThat()
                        .resideInAnyPackage("org.bouncycastle..")
                        .as(
                                "etchlog-core uses the JDK 21 built-in Ed25519 provider, not BouncyCastle");
        rule.check(CORE);
    }

    @Test
    void coreHasNoObservabilityDependency() {
        ArchRule rule =
                noClasses()
                        .should()
                        .dependOnClassesThat()
                        .resideInAnyPackage("io.micrometer..", "io.prometheus..")
                        .as(
                                "etchlog-core must not depend on Micrometer / Prometheus —"
                                    + " observability is instrumented in etchlog-server by wrapping"
                                    + " core calls, never inside core");
        rule.check(CORE);
    }
}
