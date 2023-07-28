package org.yy.mac;

/**
 * Cipher Utils.
 * <p>
 * Created by YaoYuan on 2020/11/13.
 */
public class SymmUtils {
    private SymmUtils() {
    }

    /**
     * Get symmetric algorithm key length.
     *
     * @param algSymm symmetric algorithm
     * @return key length in bytes.
     */
    public static int getSymmKeyLength(AlgSymm algSymm) {
        switch (algSymm) {
            case DES:
                return 8;
            case DESede:
            case SM4:
            case AES128:
                return 16;
            case DESede3:
            case AES192:
                return 24;
            case AES256:
                return 32;
            default: //should not goto here
                throw new IllegalArgumentException("Not support this symmetric algorithm");
        }
    }

    /**
     * Get symmetric algorithm block length.
     *
     * @param algSymm symmetric algorithm
     * @return block length of group in bytes.
     */
    public static int getSymmBlockLength(AlgSymm algSymm) {
        switch (algSymm) {
            case DES:
            case DESede:
            case DESede3:
                return 8;
            case AES128:
            case AES192:
            case AES256:
            case SM4:
                return 16;
            default: //should not goto here
                throw new IllegalArgumentException("Not support this symmetric algorithm");
        }
    }

}
