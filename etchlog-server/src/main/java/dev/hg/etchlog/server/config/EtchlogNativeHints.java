package dev.hg.etchlog.server.config;

import java.util.ServiceLoader;
import org.flywaydb.core.extensibility.Plugin;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;

/**
 * GraalVM native-image reachability hints for the things whole-program analysis cannot discover on
 * its own (Milestone 9).
 *
 * <p>These hints live in the server module deliberately: {@code etchlog-core} stays free of any
 * framework type (the ArchUnit boundary), and the cryptographic core needs no hints — it signs with
 * the JDK's built-in EdDSA provider, which GraalVM registers automatically because it is reachable.
 * What native-image <em>cannot</em> infer are the runtime-resolved resource paths and
 * reflectively-named classes below.
 */
@Configuration(proxyBeanMethods = false)
@ImportRuntimeHints(EtchlogNativeHints.Registrar.class)
public class EtchlogNativeHints {

    static final class Registrar implements RuntimeHintsRegistrar {

        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            // Flyway resolves classpath:db/migration/{vendor} at runtime: {vendor} becomes
            // "sqlite" or "postgresql" from the JDBC URL. Because the placeholder is unknown at
            // AOT time, Spring's Flyway hints register the unresolved location and miss these
            // concrete directories — so the migration SQL would not be embedded in the binary and
            // Flyway would find zero migrations at startup. Register both vendors explicitly.
            hints.resources().registerPattern("db/migration/postgresql/*.sql");
            hints.resources().registerPattern("db/migration/sqlite/*.sql");

            // Hibernate instantiates the dialect reflectively from the class name configured in
            // spring.jpa.properties.hibernate.dialect. The SQLite community dialect is a runtime
            // dependency (no compile-time reference), so register it by name for construction.
            hints.reflection()
                    .registerTypeIfPresent(
                            classLoader,
                            "org.hibernate.community.dialect.SQLiteDialect",
                            MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                            MemberCategory.INVOKE_PUBLIC_METHODS);

            // JDBC drivers are loaded by class name (Hikari driver-class-name / DriverManager).
            // The reachability-metadata repository covers most of each driver, but pin the entry
            // points so driver registration works in both the SQLite (default) and PostgreSQL
            // (prod) profiles.
            hints.reflection()
                    .registerTypeIfPresent(
                            classLoader,
                            "org.sqlite.JDBC",
                            MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                            MemberCategory.INVOKE_PUBLIC_METHODS);
            hints.reflection()
                    .registerTypeIfPresent(
                            classLoader,
                            "org.postgresql.Driver",
                            MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                            MemberCategory.INVOKE_PUBLIC_METHODS);

            // Flyway loads its plugins (including every ConfigurationExtension) via
            // ServiceLoader on the Plugin SPI, then reflectively invokes their getters/setters to
            // bind and copy flyway.* configuration (e.g.
            // PublishingConfigurationExtension.isCheckDriftOnMigrate(), reached from
            // ConfigurationExtension.copy()). Spring's Flyway hints do not cover all of them, so
            // the
            // context fails at startup in native with a MissingReflectionRegistrationError.
            // Enumerate the Plugin implementations on the classpath (Provider.type() does not
            // instantiate them) and register their members.
            ServiceLoader.load(Plugin.class, classLoader).stream()
                    .map(ServiceLoader.Provider::type)
                    .forEach(
                            type ->
                                    hints.reflection()
                                            .registerType(
                                                    type,
                                                    MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                                                    MemberCategory.INVOKE_DECLARED_METHODS,
                                                    MemberCategory.INVOKE_PUBLIC_METHODS));
        }
    }
}
