package org.yy.mac;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Pack;

import java.util.Arrays;

/**
 * 《GBT 15852.1-2020 信息技术 安全技术 消息鉴别码 第1部分：采用分组密码的机制》算法1~8。
 *
 * @author YaoYuan
 * @since 2022/11/2
 */
public class YCMac implements Mac {
    private final byte[] mac; //mac值
    private final int macSize; //所需的Mac大小

    private final byte[] buf; //内部缓冲区
    private int bufOff; //缓冲区当前数据长度

    private byte[] K1; //用在初始变换2或最终迭代3中的密钥
    private byte[] K2; //用在最终迭代2/3中的密钥

    private final BlockCipher cipher; //底层对称算法对象
    ParametersWithPadding parameters; //算法参数

    public YCMac(BlockCipher cipher) {
        this(cipher, cipher.getBlockSize() * 8);
    }

    public YCMac(BlockCipher cipher, int macSizeInBits) {
        if ((macSizeInBits % 8) != 0) {
            throw new IllegalArgumentException("MAC size must be multiple of 8");
        }

        if (macSizeInBits > (cipher.getBlockSize() * 8)) {
            throw new IllegalArgumentException("MAC size must be less or equal to " + (cipher.getBlockSize() * 8));
        }

        this.cipher = new CBCBlockCipher(cipher);
        this.macSize = macSizeInBits / 8;

        mac = new byte[cipher.getBlockSize()];
        buf = new byte[cipher.getBlockSize()];
        bufOff = 0;
    }

    public String getAlgorithmName() {
        return cipher.getAlgorithmName();
    }

    public void init(CipherParameters params) {
        validate(params);

        cipher.init(true, parameters.getParameters());
        keyInduce(); //1.密钥诱导
        reset();

        //填充方式3：处理在开头添加的填充块
        if (parameters.typePad == 3) {
            byte[] temp = new byte[cipher.getBlockSize()];
            byte[] bLen = Pack.intToBigEndian(parameters.length * 8);
            System.arraycopy(bLen, 0, temp, temp.length - bLen.length, bLen.length);
            update(temp, 0, temp.length);
        }
    }

    void validate(CipherParameters params) {
        if (params instanceof ParametersWithPadding)
            parameters = (ParametersWithPadding) params;
        else
            throw new IllegalArgumentException("CMac mode only permits parameters type of ParametersWithPadding.");
    }

    public int getMacSize() {
        return macSize;
    }

    public void update(byte in) {
        if (bufOff == buf.length) {
            cipher.processBlock(buf, 0, mac, 0);
            bufOff = 0;
        }

        buf[bufOff++] = in;
    }

    public void update(byte[] in, int inOff, int len) {
        if (len < 0) {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }

        int blockSize = cipher.getBlockSize();
        int gapLen = blockSize - bufOff;

        if (len > gapLen) {
            System.arraycopy(in, inOff, buf, bufOff, gapLen);

            initTransform(parameters.transformInit); //4.初始变换

            bufOff = 0;
            len -= gapLen;
            inOff += gapLen;

            //5.迭代应用分组密码
            while (len > blockSize) {
                cipher.processBlock(in, inOff, mac, 0);
                len -= blockSize;
                inOff += blockSize;
            }
        }

        System.arraycopy(in, inOff, buf, bufOff, len);
        bufOff += len;
    }

    public int doFinal(byte[] out, int outOff) {
        int msgLen = bufOff;

        paddingTransform(parameters.typePad); //2.消息填充。填充最后一个分组
        lastIteration(parameters.lastIteration, msgLen); //6.最终迭代
        outTransform(parameters.transformOut); //7.输出变换
        truncate(parameters.truncate, out, outOff, msgLen); //8.截断操作

        reset();
        return macSize;
    }

    /**
     * 密钥诱导。
     */
    void keyInduce() {
        KeyInduce keyInduce = new KeyInduce(cipher);

        if (parameters.typeAlg == 2) {
            //如果没有提供key2，则需要生成。
            //为了兼容2008，通过keyInduce参数决定密钥生成方式。0表示使用2008标准中的密钥诱导；1表示使用2020标准中的密钥诱导1。
            if (parameters.key2 == null) {
                if(parameters.keyInduce==0)
                    parameters.key2 = keyInduce.induce0(parameters.key1);
                else {
                    keyInduce.induce1(parameters.key1.length);
                    parameters.key1 = keyInduce.K1;
                    parameters.key2 = keyInduce.K2;
                }
            }
        } else if (parameters.typeAlg == 4) {
            //需要生成初始变换2的密钥K1：如果提供了key2，则用2008标准中的密钥诱导生成K1；
            //如果没有提供key2，则需用密钥诱导1生成K1，以及要在输出变换2中使用的密钥key2
            if (parameters.key2 != null)
                K1 = keyInduce.induce0(parameters.key2);
            else {
                keyInduce.induce1(parameters.key1.length);
                parameters.key2 = keyInduce.K1;
                K1 = keyInduce.K2;
            }
        } else if (parameters.typeAlg == 5) {
            //最终迭代3中的两个密钥用密钥诱导2生成；分别放在K1和K2中
            keyInduce.induce2();
            K1 = keyInduce.K1;
            K2 = keyInduce.K2;
        } else if (parameters.typeAlg == 6) {
            //当只提供一个密钥时，需用密钥诱导1生成所需的两个密钥。用于最终迭代2的密钥放在K2中
            if (parameters.key2 == null) {
                keyInduce.induce1(parameters.key1.length);
                parameters.key1 = keyInduce.K1;
                K2 = keyInduce.K2; //用于最终迭代2，故不设置key2
                cipher.init(true, parameters.getParameters()); //使用密钥诱导生成了key1，需要重新初始化cipher
            } else
                K2 = parameters.key2;
        }
    }

    /**
     * 填充。
     *
     * @param type 填充方式
     */
    void paddingTransform(int type) {
        int blockSize = cipher.getBlockSize();
        if (type == 1 || type == 3) {
            if (bufOff != blockSize)
                new ZeroBytePadding().addPadding(buf, bufOff);
        } else if (type == 2) {
            if (bufOff == blockSize) {
                cipher.processBlock(buf, 0, mac, 0);
                bufOff = 0;
            }
            new ISO7816d4Padding().addPadding(buf, bufOff);
        } else if (type == 4) {
            if (bufOff != blockSize)
                new ISO7816d4Padding().addPadding(buf, bufOff);
        }
    }

    /**
     * 初始变换。
     *
     * @param type 初始变换方式
     */
    void initTransform(int type) {
        cipher.processBlock(buf, 0, mac, 0);

        if (type == 2) {
            //初始变换2：使用子密钥加密后再使用原密钥进行后续加密
            reset();
            cipher.init(true, new KeyParameter(K1));
            cipher.processBlock(mac, 0, mac, 0);
            cipher.init(true, new ParametersWithIV(parameters.getParameters(), mac));
        } else if (type == 3) {
            cipher.reset();
            byte[] zeroes = new byte[cipher.getBlockSize()];
            cipher.processBlock(zeroes, 0, mac, 0);
            xor(buf, mac);
            cipher.reset();
            cipher.processBlock(buf, 0, mac, 0);
        }
    }

    /**
     * 输出变换。
     *
     * @param type 输出变换方式
     */
    void outTransform(int type) {
        if (type == 2) {
            //使用子密钥再加密一次
            reset();
            //这里需要使用全0的IV进行初始化，因为在算法4的“初始化变换”中使用了非0的IV，如果只是reset，则IV不是全0，会导致结果有误
            cipher.init(true, new ParametersWithIV(new KeyParameter(parameters.key2), new byte[cipher.getBlockSize()]));
            cipher.processBlock(mac, 0, mac, 0);
        } else if (type == 3) {
            //使用子密钥解密后再使用原密钥加密
            cipher.init(false, new KeyParameter(parameters.key2));
            cipher.processBlock(mac, 0, mac, 0);

            reset();
            cipher.init(true, parameters.getParameters());
            cipher.processBlock(mac, 0, mac, 0);
        }
    }


    /**
     * 最终迭代。
     *
     * @param type   迭代类型
     * @param msgLen 最后的消息长度
     */
    void lastIteration(int type, int msgLen) {
        if (type == 1)
            cipher.processBlock(buf, 0, mac, 0);
        if (type == 2) {
            xor(mac, buf);
            reset();
            cipher.init(true, new ParametersWithIV(new KeyParameter(K2), new byte[cipher.getBlockSize()]));
            cipher.processBlock(mac, 0, mac, 0);
        } else if (type == 3) {
            if (msgLen % cipher.getBlockSize() == 0)
                xor(buf, K1);
            else
                xor(buf, K2);
            cipher.processBlock(buf, 0, mac, 0);
        } else if (type == 4) {
            byte[] temp = new byte[cipher.getBlockSize()];
            xor(mac, buf);
            if (msgLen % cipher.getBlockSize() == 0)
                shiftRight(mac, temp);
            else
                shiftLeft(mac, temp);
            System.arraycopy(temp, 0, mac, 0, temp.length);

            reset();
            cipher.init(true, parameters.getParameters());
            cipher.processBlock(mac, 0, mac, 0);
        }
    }

    /**
     * 截断操作。
     *
     * @param type   截断类型
     * @param out    输出缓冲
     * @param outOff 输出偏移
     * @param msgLen 最后的消息长度
     */
    void truncate(int type, byte[] out, int outOff, int msgLen) {
        if (type == 2 && msgLen % cipher.getBlockSize() != 0)
            System.arraycopy(mac, mac.length - macSize, out, outOff, macSize);
        else
            System.arraycopy(mac, 0, out, outOff, macSize);
    }

    public void reset() {
        //clean the buffer.
        Arrays.fill(buf, (byte) 0);
        bufOff = 0;

        //reset the underlying cipher.
        cipher.reset();
    }


    static void xor(byte[] a, byte[] b) {
        for (int i = 0; i < a.length; i++)
            a[i] ^= b[i];
    }

    /**
     * 循环左移。
     */
    private static int shiftLeft(byte[] input, byte[] output) {
        int i = input.length;
        int bit = 0;
        while (--i >= 0) {
            int b = input[i] & 0xff;
            output[i] = (byte) ((b << 1) | bit);
            bit = (b >>> 7) & 1;
        }
        return bit;
    }

    /**
     * 循环右移。
     */
    private static int shiftRight(byte[] input, byte[] output) {
        int i = 0;
        int bit = 0;
        while (i < input.length) {
            int b = input[i] & 0xff;
            output[i] = (byte) ((b >>> 1) | bit);
            bit = (b << 7) & 0x80;
            i++;
        }

        output[0] |= bit;

        return bit;
    }

    /**
     * 密钥诱导。
     */
    static class KeyInduce {
        final BlockCipher cipher;
        byte[] K1;
        byte[] K2;

        KeyInduce(BlockCipher blockCipher) {
            this.cipher = blockCipher;
        }

        /**
         * 密钥诱导1.
         *
         * @param keyLength 分组密钥密钥长度k
         */
        void induce1(int keyLength) {
            int t = keyLength / cipher.getBlockSize();
            K1 = genKey(0, t);
            cipher.reset();
            K2 = genKey(t, 2 * t);
        }

        /**
         * 密钥诱导2.
         */
        void induce2() {
            byte[] zeroes = new byte[cipher.getBlockSize()];
            byte[] L = new byte[zeroes.length];
            cipher.processBlock(zeroes, 0, L, 0);
            K1 = multx(L);
            K2 = multx(K1);
        }

        /**
         * 《GBT 15852.1-2008》密钥诱导。
         * <p>
         * 用在算法2和算法4中。
         * <p>
         * 过程：对K从第1个4比特组开始，每隔4比特交替取补和不变
         *
         * @param key 密钥
         * @return 子密钥
         */
        public byte[] induce0(byte[] key) {
            byte[] result = key.clone();
            for (int i = 0; i < result.length; i++)
                result[i] = (byte) ((~result[i] & 0xF0) ^ (result[i] & 0x0F));
            return result;
        }

        byte[] genKey(int start, int end) {
            int blockSize = cipher.getBlockSize();
            int len = end - start;

            byte[] S = new byte[len * blockSize];
            for (int i = start; i < end; i++) {
                byte[] ct = new byte[blockSize];
                byte[] temp = Pack.intToBigEndian(i + 1);
                System.arraycopy(temp, 0, ct, ct.length - temp.length, temp.length);
                cipher.processBlock(ct, 0, S, (i - start) * blockSize);
            }

            return Arrays.copyOfRange(S, (len - 1) * blockSize, S.length);
        }

        /**
         * multx(CMac.doubleLu).
         *
         * @param in 比特串T
         * @see CMac
         */
        byte[] multx(byte[] in) {
            byte[] ret = new byte[in.length];
            int carry = shiftLeft(in, ret);

            byte[] poly = lookupPoly(cipher.getBlockSize());

            int mask = (-carry) & 0xff;
            ret[in.length - 3] ^= poly[1] & mask;
            ret[in.length - 2] ^= poly[2] & mask;
            ret[in.length - 1] ^= poly[3] & mask;

            return ret;
        }

        /**
         * lookup.
         *
         * @see CMac
         */
        static byte[] lookupPoly(int blockSizeLength) {
            int xor = 0;
            switch (blockSizeLength * 8) {
                case 64:
                    xor = 0x1B;
                    break;
                case 128:
                    xor = 0x87;
                    break;
            }

            return Pack.intToBigEndian(xor);
        }
    }
}
