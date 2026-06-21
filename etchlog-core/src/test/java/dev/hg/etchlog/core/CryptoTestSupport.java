package dev.hg.etchlog.core;

import dev.hg.etchlog.core.hash.MerkleHash;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/** Deterministic helpers shared by the crypto-core test suites. */
public final class CryptoTestSupport {

    private CryptoTestSupport() {}

    /** Produces {@code n} distinct, deterministic leaf hashes derived from a seed. */
    public static List<byte[]> randomLeafHashes(int n, long seed) {
        Random rnd = new Random(seed);
        List<byte[]> leaves = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            byte[] data = new byte[1 + rnd.nextInt(24)];
            rnd.nextBytes(data);
            leaves.add(MerkleHash.hashLeaf(data));
        }
        return leaves;
    }

    /** Flips a single bit of a copy of {@code hash} so it differs from the original. */
    public static byte[] flipOneBit(byte[] hash, int bitIndex) {
        byte[] copy = hash.clone();
        int idx = Math.floorMod(bitIndex, copy.length * 8);
        copy[idx / 8] ^= (byte) (1 << (idx % 8));
        return copy;
    }
}
