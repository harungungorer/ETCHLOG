package dev.hg.etchlog.core.sth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.etchlog.core.CryptoTestSupport;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.LongRange;
import org.junit.jupiter.api.Test;

class SthSigningTest {

    private static KeyPair ed25519() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    @Test
    void signThenVerifyRoundTrips() throws Exception {
        KeyPair kp = ed25519();
        Ed25519SthSigner signer = new Ed25519SthSigner(kp.getPrivate());
        byte[] root = CryptoTestSupport.randomLeafHashes(1, 1L).get(0);

        SignedTreeHead sth = signer.signSth(5, 1750521600000L, root);

        assertThat(SthVerifier.verify(kp.getPublic(), sth)).isTrue();
        assertThat(SthVerifier.verify(kp.getPublic(), 5, 1750521600000L, root, sth.signature()))
                .isTrue();
    }

    @Test
    void verificationFailsWithWrongKey() throws Exception {
        KeyPair signing = ed25519();
        KeyPair other = ed25519();
        byte[] root = CryptoTestSupport.randomLeafHashes(1, 2L).get(0);
        SignedTreeHead sth = new Ed25519SthSigner(signing.getPrivate()).signSth(9, 1L, root);

        assertThat(SthVerifier.verify(other.getPublic(), sth)).isFalse();
    }

    @Test
    void verificationFailsWhenAnySignedFieldIsAltered() throws Exception {
        KeyPair kp = ed25519();
        byte[] root = CryptoTestSupport.randomLeafHashes(1, 3L).get(0);
        SignedTreeHead sth = new Ed25519SthSigner(kp.getPrivate()).signSth(9, 1000L, root);

        assertThat(
                        SthVerifier.verify(
                                kp.getPublic(),
                                sth.treeSize() + 1,
                                sth.timestamp(),
                                sth.rootHash(),
                                sth.signature()))
                .isFalse();
        assertThat(
                        SthVerifier.verify(
                                kp.getPublic(),
                                sth.treeSize(),
                                sth.timestamp() + 1,
                                sth.rootHash(),
                                sth.signature()))
                .isFalse();
        byte[] tamperedRoot = CryptoTestSupport.flipOneBit(sth.rootHash(), 3);
        assertThat(
                        SthVerifier.verify(
                                kp.getPublic(),
                                sth.treeSize(),
                                sth.timestamp(),
                                tamperedRoot,
                                sth.signature()))
                .isFalse();
    }

    /** INVARIANT 4: STH sign -> verify round-trips for any fields; a wrong key always fails. */
    @Property(tries = 200)
    void sthSignVerifyRoundTripsAndWrongKeyFails(
            @ForAll @IntRange(min = 0, max = Integer.MAX_VALUE) int treeSize,
            @ForAll @LongRange(min = 0, max = Long.MAX_VALUE) long ts,
            @ForAll @LongRange(min = 0, max = Long.MAX_VALUE) long seed)
            throws Exception {
        KeyPair kp = ed25519();
        KeyPair wrong = ed25519();
        byte[] root = CryptoTestSupport.randomLeafHashes(1, seed).get(0);
        SignedTreeHead sth = new Ed25519SthSigner(kp.getPrivate()).signSth(treeSize, ts, root);

        assertThat(SthVerifier.verify(kp.getPublic(), sth)).isTrue();
        assertThat(SthVerifier.verify(wrong.getPublic(), sth)).isFalse();
    }

    @Test
    void encodingIsFixedWidthAndVersionTagged() {
        byte[] root = CryptoTestSupport.randomLeafHashes(1, 4L).get(0);
        byte[] signed = SthEncoding.bytesToSign(1, 2, root);
        assertThat(signed).hasSize(SthEncoding.SIGNED_LENGTH);
        assertThat(signed[0]).isEqualTo(SthEncoding.STH_VERSION);
    }

    @Test
    void sthRejectsNon32ByteRoot() {
        assertThatThrownBy(() -> new SignedTreeHead(1, new byte[31], 0, new byte[64]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void sthDefensivelyCopiesMutableFields() {
        byte[] root = CryptoTestSupport.randomLeafHashes(1, 6L).get(0);
        byte[] sig = new byte[64];
        SignedTreeHead sth = new SignedTreeHead(1, root, 0, sig);
        root[0] ^= 0xFF; // mutate caller's array after construction
        sig[0] ^= 0xFF;
        assertThat(sth.rootHash()).isNotEqualTo(root);
        assertThat(sth.signature()[0]).isEqualTo((byte) 0);
    }
}
