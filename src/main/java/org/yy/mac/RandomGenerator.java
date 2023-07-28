package org.yy.mac;

import java.security.SecureRandom;

/**
 * Random Data Generator.
 * <p>
 * Created by YaoYuan on 2020/11/13.
 */
public class RandomGenerator {
    private final SecureRandom random;

    public RandomGenerator() {
        random = new SecureRandom();
    }

    public RandomGenerator(SecureRandom random) {
        this.random = random;
    }

    /**
     * Generate random data with the specific length。
     *
     * @param length specific length of random data
     * @return random data
     */
    public byte[] nextBytes(int length) {
        if (length <= 0)
            return new byte[0];

        byte[] data = new byte[length];
        random.nextBytes(data);
        return data;
    }
}
