package org.yy.mac;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.CMacWithIV;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Pack;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * CMAC。
 *
 * @author YaoYuan
 * @since 2022/11/2
 */
public class CMacTool {
    /**
     * OMAC算法。
     * <p>
     * BC库的OMAC。
     *
     * @param algSymm 算法
     * @param key     密钥
     * @param data    数据
     * @return CMAC值
     * @throws YCryptoException throw all crypto exception to here
     */
    public static byte[] omac(AlgSymm algSymm, byte[] key, byte[] data) throws YCryptoException {
        try {
            String algCMac = algSymm.toString() + "CMAC";
            if (algSymm == AlgSymm.SM4)
                algCMac = algSymm.toString() + "-CMAC";
            Mac mac = Mac.getInstance(algCMac, BCProvider.getProvider());
            SecretKey secretKey = new SecretKeySpec(key, algCMac);

            mac.init(secretKey, null);
            return mac.doFinal(data);
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new YCryptoException(e);
        }
    }


    /**
     * OMAC算法。
     * <p>
     * BC库的OMAC，支持设置IV。
     *
     * @param algSymm 算法
     * @param key     密钥
     * @param iv      向量
     * @param data    数据
     * @return CMAC值
     */
    public static byte[] omac(AlgSymm algSymm, byte[] key, byte[] iv, byte[] data) {
        CMac mac = new CMacWithIV(getBlockCipher(algSymm));
        CipherParameters parameters;
        if (iv != null)
            parameters = new ParametersWithIV(new KeyParameter(key), iv);
        else
            parameters = new KeyParameter(key);
        mac.init(parameters);
        mac.update(data, 0, data.length);
        byte[] output = new byte[mac.getMacSize()];
        mac.doFinal(output, 0);

        return output;
    }

    /**
     * CMAC。
     * <p>
     * 内部为《GBT 15852.1-2020》的算法5和填充4。和BC库的 CMac一致。
     *
     * @param algSymm 对称算法
     * @param key     密钥
     * @param iv      [in|out] 向量
     * @param data    数据
     * @return CMAC值
     */
    public static byte[] yomac(AlgSymm algSymm, byte[] key, byte[] iv, byte[] data) {
        YCMac mac = new YCMac(getBlockCipher(algSymm));
        ParametersWithPadding parameters = new ParametersWithPadding(key, null, iv, 5, 4, 0);
        mac.init(parameters);
        mac.update(data, 0, data.length);
        byte[] output = new byte[mac.getMacSize()];
        mac.doFinal(output, 0);
        return output;
    }

    /**
     * 根据算法获取 BlockCipher 对象。
     *
     * @param algSymm 对称算法
     * @return BlockCipher 对象
     */
    public static BlockCipher getBlockCipher(AlgSymm algSymm) {
        String temp = algSymm.toString();
        if (temp.contains("AES"))
            return new AESEngine();
        else if (temp.contains("DESede"))
            return new DESedeEngine();
        else if (temp.contains("DES"))
            return new DESEngine();
        else if (temp.contains("SM4"))
            return new SM4Engine();
        else
            throw new RuntimeException("Not support symmetric algorithm " + temp + " for CMAC");
    }

    /**
     * CMAC。
     * <p>
     * 支持update模式，内部为《GBT 15852.1》的算法1和填充1。
     * <p>
     * 在update过程中，最后一个数据块可以不完整，但是前面的所有数据块必须是分组长度的整数倍。
     *
     * @param algSymm 对称算法
     * @param key     密钥
     * @param iv      [in|out] 向量
     * @param data    数据
     * @return CMAC值
     */
    public static byte[] cmac(AlgSymm algSymm, byte[] key, byte[] iv, byte[] data) {
        YCMac mac = new YCMac(getBlockCipher(algSymm));

        ParametersWithPadding parameters = new ParametersWithPadding(key, null, iv, 1, 1, 0);
        mac.init(parameters);
        mac.update(data, 0, data.length);
        byte[] output = new byte[mac.getMacSize()];
        mac.doFinal(output, 0);

        int blockSize = SymmUtils.getSymmBlockLength(algSymm);
        if(iv!=null)
            System.arraycopy(output, output.length - blockSize, iv, 0, blockSize);

        return output;
    }

    /**
     * 《GBT 15852.1》填充1。
     *
     * 仅在外部作数据显示时使用，在内部的算法实现时使用其他方法进行填充。
     *
     * @param data 数据
     * @param blockSize 分组长度
     * @return 填充后的数据
     */
    public static byte[] padding1(byte[] data, int blockSize) {
        if (data.length % blockSize == 0)
            return data;

        int length = (data.length + blockSize - 1) / blockSize * blockSize;
        byte[] result = new byte[length];
        System.arraycopy(data, 0, result, 0, data.length);
        return result;
    }

    /**
     * 《GBT 15852.1》填充2。
     *
     * 仅在外部作数据显示时使用，在内部的算法实现时使用其他方法进行填充。
     *
     * @param data 数据
     * @param blockSize 分组长度
     * @return 填充后的数据
     */
    public static byte[] padding2(byte[] data, int blockSize) {
        int length = (data.length + blockSize) / blockSize * blockSize;
        byte[] result = new byte[length];
        System.arraycopy(data, 0, result, 0, data.length);
        result[data.length] = (byte) 0x80;
        return result;
    }

    /**
     * 《GBT 15852.1》填充3。
     *
     * 仅在外部作数据显示时使用，在内部的算法实现时使用其他方法进行填充。
     *
     * @param data 数据
     * @param blockSize 分组长度
     * @return 填充后的数据
     */
    public static byte[] padding3(byte[] data, int blockSize) {
        byte[] temp = padding1(data, blockSize);
        byte[] result = new byte[temp.length + blockSize];
        System.arraycopy(temp, 0, result, blockSize, temp.length);

        byte[] bLen = Pack.intToBigEndian(data.length * 8);
        System.arraycopy(bLen, 0, result, blockSize - bLen.length, bLen.length);

        return result;
    }

    /**
     * 《GBT 15852.1-2020》填充4。
     * <p>
     * 仅在外部作数据显示时使用，在内部的算法实现时使用其他方法进行填充。
     *
     * @param data      数据
     * @param blockSize 分组长度
     * @return 填充后的数据
     */
    public static byte[] padding4(byte[] data, int blockSize) {
        if (data.length % blockSize == 0)
            return data;
        else
            return padding2(data, blockSize);
    }
}
