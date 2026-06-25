package dev.hg.etchlog.core.sth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.etchlog.core.CryptoTestSupport;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.junit.jupiter.api.Test;

/**
 * Guard / failure-path coverage for STH encoding, signing, and verification. The happy-path
 * round-trips live in {@link SthSigningTest}; this class pins the defensive branches that reject
 * malformed input or a wrong key type — none of which may ever produce a verifying STH.
 */
class SthGuardTest {

    private static KeyPair ed25519() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    // ---- SthEncoding ---------------------------------------------------------------------------

    @Test
    void encodingRejectsNullRoot() {
        assertThatThrownBy(() -> SthEncoding.bytesToSign(1, 1, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void encodingRejectsWrongLengthRoot() {
        assertThatThrownBy(() -> SthEncoding.bytesToSign(1, 1, new byte[31]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ---- Ed25519SthSigner ----------------------------------------------------------------------

    @Test
    void signerRejectsNullPrivateKey() {
        assertThatThrownBy(() -> new Ed25519SthSigner(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void signerWrapsSigningFailureForWrongKeyType() throws Exception {
        // A non-Ed25519 private key makes Signature.initSign throw a GeneralSecurityException,
        // which the signer surfaces as IllegalStateException rather than a checked exception.
        Ed25519SthSigner signer = new Ed25519SthSigner(rsa().getPrivate());
        byte[] root = CryptoTestSupport.randomLeafHashes(1, 11L).get(0);
        assertThatThrownBy(() -> signer.sign(1, 1, root)).isInstanceOf(IllegalStateException.class);
    }

    // ---- SthVerifier ---------------------------------------------------------------------------

    @Test
    void verifierRejectsNullArguments() throws Exception {
        KeyPair kp = ed25519();
        byte[] root = CryptoTestSupport.randomLeafHashes(1, 12L).get(0);
        byte[] sig = new Ed25519SthSigner(kp.getPrivate()).sign(1, 1, root);
        assertThat(SthVerifier.verify(null, 1, 1, root, sig)).isFalse();
        assertThat(SthVerifier.verify(kp.getPublic(), 1, 1, null, sig)).isFalse();
        assertThat(SthVerifier.verify(kp.getPublic(), 1, 1, root, null)).isFalse();
    }

    @Test
    void verifierRejectsNullSth() throws Exception {
        assertThat(SthVerifier.verify(ed25519().getPublic(), null)).isFalse();
    }

    @Test
    void verifierReturnsFalseForWrongKeyType() throws Exception {
        // An RSA public key makes Signature.initVerify throw; the verifier maps that to false
        // rather than propagating, so a caller never crashes on a malformed key.
        KeyPair signing = ed25519();
        byte[] root = CryptoTestSupport.randomLeafHashes(1, 13L).get(0);
        byte[] sig = new Ed25519SthSigner(signing.getPrivate()).sign(1, 1, root);
        assertThat(SthVerifier.verify(rsa().getPublic(), 1, 1, root, sig)).isFalse();
    }

    // ---- SignedTreeHead ------------------------------------------------------------------------

    @Test
    void sthRejectsNegativeTreeSize() {
        byte[] root = CryptoTestSupport.randomLeafHashes(1, 14L).get(0);
        assertThatThrownBy(() -> new SignedTreeHead(-1, root, 0, new byte[64]))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
