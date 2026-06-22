package dev.hg.etchlog.server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the log's Ed25519 signing keypair (prefix {@code etchlog.signing}).
 *
 * <p>The private key is the single most sensitive secret in the system: whoever holds it can mint
 * Signed Tree Heads every verifier will trust. Provide it via a PEM file outside the application
 * bundle, kept in a secret manager / restricted-permission path. The public key is published so any
 * verifier (CLI, dashboard, monitor) can check STH signatures.
 *
 * <p>When no private key is configured the server generates an <em>ephemeral</em> demo keypair at
 * startup and logs a loud warning — convenient for the single-binary demo, never for production
 * (every restart mints a new key, so previously issued STHs no longer verify).
 *
 * @param privateKeyPath path to a PKCS#8 PEM file (a {@code PRIVATE KEY} armored block)
 * @param publicKeyPath path to the matching X.509/SPKI PEM file (a {@code PUBLIC KEY} armored
 *     block); required whenever {@code privateKeyPath} is set
 */
@ConfigurationProperties(prefix = "etchlog.signing")
public record SigningProperties(String privateKeyPath, String publicKeyPath) {}
