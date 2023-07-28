package org.yy.mac;

import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;

/**
 * Symmetric Algorithm.
 *
 * Created by YaoYuan on 2020/11/13.
 */
public enum AlgSymm {
    AES128("AES"),
    AES192("AES"),
    AES256("AES"),
    DES("DES"),
    DESede("DESede"),
    DESede3("DESede"),
    SM4("SM4");

    private final String name;

    AlgSymm(String name) {
        this.name = name;
    }

    public String getName() { return name; }

    /**
     * Create AlgSymm object from name.
     *
     * @param name string name of Symmetric algorithm
     * @return AlgSymm
     * @throws NoSuchAlgorithmException throw exception if not support this symmetric algorithm
     */
    public static AlgSymm fromName(String name) throws NoSuchAlgorithmException {
        try {
            return AlgSymm.valueOf(name);
        } catch (InvalidParameterException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        }
    }

    @Override
    public String toString() {
        return name;
    }
}
