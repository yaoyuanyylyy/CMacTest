package org.yy.mac;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * 《GBT 15852.1》各种MAC算法的参数。
 * <p>
 * 增加了IV设置，默认的IV为全0。
 *
 * @author YaoYuan
 * @since 2022/11/2
 */
public class ParametersWithPadding implements CipherParameters {
    int typeAlg; //算法类型：1~6
    int typePad; //填充类型：1、2、3、4
    int length; //仅 typePad=3 时有效，表示输入数据的总长度
    int transformInit; //初始变换：1、2、3
    int transformOut; //输出变换：1、2、3
    int lastIteration; //最终迭代：1、2、3、4
    int truncate; //截断操作：1、2
    int keyInduce = 1; //密钥诱导方式：0、1；仅用于算法2中。
    byte[] key1;
    byte[] key2;
    byte[] iv;

    public ParametersWithPadding(
            byte[] key1, byte[] key2,
            int typeAlg, int typePad) {
        this(key1, key2, typeAlg, typePad, 0);
    }

    public ParametersWithPadding(
            byte[] key1, byte[] key2, byte[] iv,
            int typeAlg, int typePad) {
        this(key1, key2, iv, typeAlg, typePad, 0);
    }

    public ParametersWithPadding(
            byte[] key1, byte[] key2,
            int typeAlg, int typePad, int length) {
        this(key1, key2, null, typeAlg, typePad, length);
    }

    public ParametersWithPadding(
            byte[] key1, byte[] key2, byte[] iv,
            int typeAlg, int typePad, int length) {
        this.key1 = key1;
        this.key2 = key2;
        this.iv = iv;
        this.typeAlg = typeAlg;
        this.typePad = typePad;
        this.length = length;

        transformInit = 1;
        transformOut = 1;
        lastIteration = 1;
        truncate = 1;

        switch (typeAlg) {
            case 2:
                transformOut = 2;
                break;
            case 3:
                transformOut = 3;
                //算法3的两个密钥应独立选取；当key2为null时为避免错误，这里将其设置为key1，此时算法3和算法1一致
                if (this.key2 == null)
                    this.key2 = key1;
                break;
            case 4:
                transformInit = 2;
                transformOut = 2;
                break;
            case 5:
                lastIteration = 3;
                break;
            case 6:
                lastIteration = 2;
                break;
            case 7:
                truncate = 2;
                break;
            case 8:
                transformInit = 3;
                lastIteration = 4;
                break;
        }
    }

    /**
     * 密钥诱导方式，仅用于算法2中。
     * <p>
     * 默认为1。为了兼容2008标准或验证2008标准的附录测试，需要手动设置为0.
     *
     * @param keyInduce 0表示使用2008标准中的密钥诱导；在2008标准中定义，并在附录测试中用到；<br>
     *                  1表示使用2020标准中的密钥诱导1。在2020标准中定义，但附录测试中提供了2个密钥，未用到。
     */
    public void setKeyInduce(int keyInduce) {
        this.keyInduce = keyInduce;
    }

    public CipherParameters getParameters() {
        if (iv == null)
            return new KeyParameter(key1);
        else
            return new ParametersWithIV(new KeyParameter(key1), iv);
    }
}
