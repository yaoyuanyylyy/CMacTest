package org.yy.mac;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;


/**
 * 《GBT 15852.1-2008 信息技术 安全技术 消息鉴别码 第1部分：采用分组密码的机制》算法5~6。
 *
 * @author YaoYuan
 * @since 2022/11/2
 */
public class CMac56 implements Mac {
    private final YCMac mac1;
    private final YCMac mac2;

    public CMac56(BlockCipher cipher1, BlockCipher cipher2) {
        mac1 = new YCMac(cipher1);
        mac2 = new YCMac(cipher2);
    }

    public CMac56(BlockCipher cipher1, BlockCipher cipher2, int macSizeInBits) {
        mac1 = new YCMac(cipher1, macSizeInBits);
        mac2 = new YCMac(cipher2, macSizeInBits);
    }

    @Override
    public void init(CipherParameters params) throws IllegalArgumentException {
        validate(params);

        ParametersWithPadding parameters = (ParametersWithPadding) params;
        if (parameters.typeAlg == 5) {
            byte[] key1 = genKey2(parameters.key1);
            mac1.init(new ParametersWithPadding(parameters.key1, null, parameters.iv, 1, parameters.typePad, parameters.length));
            mac2.init(new ParametersWithPadding(key1, null, parameters.iv, 1, parameters.typePad, parameters.length));
        } else {
            byte[] key1 = genKey3(parameters.key1);
            byte[] key2 = genKey3(parameters.key2);
            mac1.init(new ParametersWithPadding(parameters.key1, parameters.key2, parameters.iv, 4, parameters.typePad, parameters.length));
            mac2.init(new ParametersWithPadding(key1, key2, parameters.iv, 4, parameters.typePad, parameters.length));
        }
    }

    void validate(CipherParameters params) {
        if (!(params instanceof ParametersWithPadding))
            throw new IllegalArgumentException("CMac mode only permits parameters type of ParametersWithPadding.");
    }

    @Override
    public String getAlgorithmName() {
        return mac1.getAlgorithmName();
    }

    @Override
    public int getMacSize() {
        return mac1.getMacSize();
    }

    @Override
    public void update(byte in) throws IllegalStateException {
        mac1.update(in);
        mac2.update(in);
    }

    @Override
    public void update(byte[] in, int inOff, int len) throws DataLengthException, IllegalStateException {
        mac1.update(in, inOff, len);
        mac2.update(in, inOff, len);
    }

    @Override
    public int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        byte[] output1 = new byte[getMacSize()];
        byte[] output2 = new byte[getMacSize()];

        mac1.doFinal(output1, 0);
        int result = mac2.doFinal(output2, 0);

        for (int i = 0; i < output1.length; i++)
            out[i + outOff] = (byte) (output1[i] ^ output2[i]);

        return result;
    }

    @Override
    public void reset() {
        mac1.reset();
        mac2.reset();
    }

    /**
     * 《GBT 15852.1-2008》子密钥生成。
     *
     * 根据附录A的算法5的子密钥推导出的子密钥生成算法。
     *
     * @param key 密钥
     * @return 子密钥
     */
    public static byte[] genKey2(byte[] key) {
        byte[] result = key.clone();
        for (int i = 0; i < result.length; i++)
            result[i] = (byte) ((~result[i] & 0xF0) ^ (~result[i] & 0x0F));
        return result;
    }

    /**
     * 《GBT 15852.1-2008》子密钥生成。
     *
     * 根据附录A的算法6的子密钥推导出的子密钥生成算法。
     *
     * @param key 密钥
     * @return 子密钥
     */
    public static byte[] genKey3(byte[] key) {
        byte[] result = key.clone();
        for (int i = 0; i < result.length; i += 2)
            result[i] = (byte) ((~result[i] & 0xF0) ^ (~result[i] & 0x0F));
        return result;
    }
}
