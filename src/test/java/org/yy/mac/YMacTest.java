package org.yy.mac;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

/**
 * @author YaoYuan
 * @since 2022/11/2
 */
public class YMacTest {

    private static void showMsg() {
        System.out.println();
    }

    private static void showMsg(String msg) {
        System.out.println(msg);
    }

    private static void showData(byte[] data, int blockSize) {
        for (int i = 0; i < data.length; i++) {
            if ((i) % blockSize == 0)
                System.out.printf("D%d | ", i / blockSize + 1);
            System.out.printf("%02X ", data[i]);
            if ((i + 1) % blockSize == 0)
                System.out.println();
        }
        System.out.println();
    }

    private static void showMac(byte[] mac) {
        System.out.print("MAC= ");
        for (int i = 0; i < mac.length; i++)
            System.out.printf("%02X ", mac[i]);
        System.out.println();
    }

    void showDataAndPadding(byte[] data, int blockSize) {
        byte[] msg1Padding1 = CMacTool.padding1(data, blockSize);
        showMsg("填充方式1：");
        showData(msg1Padding1, blockSize);
        byte[] msg1Padding2 = CMacTool.padding2(data, blockSize);
        showMsg("填充方式2：");
        showData(msg1Padding2, blockSize);
        byte[] msg1Padding3 = CMacTool.padding3(data, blockSize);
        showMsg("填充方式3：");
        showData(msg1Padding3, blockSize);
        showMsg();
    }

    void showDataAndPadding_GBT_2020(byte[] data, int blockSize) {
        showDataAndPadding(data, blockSize);
        byte[] msg1Padding4 = CMacTool.padding4(data, blockSize);
        showMsg("填充方式4：");
        showData(msg1Padding4, blockSize);
        showMsg();
    }

    /**
     * OMAC测试，包括AES128/192/256和DESede。
     * <p>
     * 测试数据取自于NIST文档"SP800-38B"。但其中关于DES的数据有两处和测试结果不一致。
     */
    @Test
    public void test_omac1() throws YCryptoException {
        showMsg("cmac test: ");
        for (TestData2 testData : TestData2.testData2) {
            showMsg("====================================================================");
            showMsg("algorithm : " + testData.algSymm.name());
            showMsg("key: " + Hex.toHexString(testData.key));
            showMsg("msg: " + Hex.toHexString(testData.msg));
            byte[] cmac = CMacTool.omac(testData.algSymm, testData.key, testData.msg);
            showMsg("mac: " + Hex.toHexString(cmac));
            Assert.assertArrayEquals(testData.mac, cmac);
        }
    }

    /**
     * CMAC/OMAC 测试。
     * <p>
     * 使用BC库中的CMac测试。对应到《GBT 15852.1-2020》的算法5
     */
    @Test
    public void test_omac2() throws YCryptoException {
        RandomGenerator randomGenerator = new RandomGenerator();
        int length = 171;
        byte[] data = randomGenerator.nextBytes(length);
        byte[] keySrc = randomGenerator.nextBytes(32);

        showMsg("cmac test: ");
        showMsg("data: " + Hex.toHexString(data));
        for (AlgSymm algSymm : AlgSymm.values()) {
            showMsg("====================================================================");
            byte[] key = Arrays.copyOfRange(keySrc, 0, SymmUtils.getSymmKeyLength(algSymm));

            showMsg("algorithm : " + algSymm.name());
            showMsg("key: " + Hex.toHexString(key));

            showMsg("--------------------------------------------------------------------");
            byte[] cmac = CMacTool.omac(algSymm, key, data);
            showMsg("omac: " + Hex.toHexString(cmac));

            byte[] cmac2 = CMacTool.yomac(algSymm, key, null, data);
            showMsg("ycmac: " + Hex.toHexString(cmac2));

            Assert.assertArrayEquals(cmac, cmac2);
        }
    }


    /**
     * 《GBT 15852.1-2008》-附录 测试验证。
     */
    @Test
    public void test_GBT15852_2008() {
        int blockSize = SymmUtils.getSymmBlockLength(TestData1.defaultAlgSymm);

        showMsg("CMAC测试： 《GBT 15852.1-2008 信息技术 安全技术 消息鉴别码 第1部分：采用分组密码的机制》-附录A");
        showMsg();

        showMsg("消息1：" + TestData1.msg1);
        showMsg("Hex: " + Hex.toHexString(TestData1.msg1.getBytes()));
        showDataAndPadding(TestData1.msg1.getBytes(), blockSize);
        showMsg("消息2：" + TestData1.msg2);
        showMsg("hex: " + Hex.toHexString(TestData1.msg2.getBytes()));
        showDataAndPadding(TestData1.msg2.getBytes(), blockSize);
        showMsg();

        showMsg("mac算法测试：");
        for (TestData1 testData1 : TestData1.testData1) {
            showMsg("--------------------------------------------------");
            showMsg("消息: " + Hex.toHexString(testData1.msg));
            showMsg("MAC算法" + testData1.typeAlg + ": ");
            showMsg("填充方法" + testData1.typePad + ": ");

            int macSize = testData1.mac.length;
            Mac mac;

            if (testData1.typeAlg == 5 || testData1.typeAlg == 6)
                mac = new CMac56(CMacTool.getBlockCipher(testData1.algSymm), CMacTool.getBlockCipher(testData1.algSymm), macSize * 8);
            else
                mac = new YCMac(CMacTool.getBlockCipher(testData1.algSymm), macSize * 8);

            ParametersWithPadding parameters = new ParametersWithPadding(
                    testData1.key1, testData1.key2, testData1.typeAlg, testData1.typePad, testData1.msg.length
            );

            if (testData1.typeAlg == 2)
                parameters.setKeyInduce(0);

            byte[] macValue = new byte[macSize];
            mac.init(parameters);
            mac.update(testData1.msg, 0, testData1.msg.length);
            mac.doFinal(macValue, 0);
            showMac(macValue);
            showMsg();
            Assert.assertArrayEquals(testData1.mac, macValue);
        }
    }


    /**
     * 《GBT 15852.1-2020》-附录 测试验证。
     */
    @Test
    public void test_GBT15852_2020() {
        int blockSize = SymmUtils.getSymmBlockLength(TestData4.defaultAlgSymm);

        showMsg("CMAC测试： 《GBT 15852.1-2020 信息技术 安全技术 消息鉴别码 第1部分：采用分组密码的机制》-附录B");
        showMsg();

        showMsg("消息1：" + TestData4.msg1);
        showMsg("Hex: " + Hex.toHexString(TestData4.msg1.getBytes()));
        showDataAndPadding_GBT_2020(TestData4.msg1.getBytes(), blockSize);
        showMsg("消息2：" + TestData4.msg2);
        showMsg("hex: " + Hex.toHexString(TestData4.msg2.getBytes()));
        showDataAndPadding_GBT_2020(TestData4.msg2.getBytes(), blockSize);
        showMsg();

        showMsg("mac算法测试：");
        for (TestData4 testData : TestData4.testData4) {
            showMsg("--------------------------------------------------");
            showMsg("消息: " + Hex.toHexString(testData.msg));
            showMsg("MAC算法" + testData.typeAlg + ": ");
            showMsg("填充方法" + testData.typePad + ": ");

            int macSize = testData.mac.length;
            Mac mac = new YCMac(CMacTool.getBlockCipher(testData.algSymm), macSize * 8);

            ParametersWithPadding parameters = new ParametersWithPadding(
                    testData.key1, testData.key2, testData.typeAlg, testData.typePad, testData.msg.length
            );

            byte[] macValue = new byte[macSize];
            mac.init(parameters);
            mac.update(testData.msg, 0, testData.msg.length);
            mac.doFinal(macValue, 0);
            showMac(macValue);
            showMsg();
            Assert.assertArrayEquals(testData.mac, macValue);
        }
    }

    /**
     * CMAC-update 测试。
     * <p>
     * 使用《GBT 15852.1》的算法1和填充1进行CMAC的update模式测试。
     */
    @Test
    public void test_cmac_update() {
        RandomGenerator randomGenerator = new RandomGenerator();
        int length = 171;
        byte[] data = randomGenerator.nextBytes(length);
        byte[] keySrc = randomGenerator.nextBytes(32);

        for (AlgSymm algSymm : AlgSymm.values()) {
            showMsg("====================================================================");
            byte[] key = Arrays.copyOfRange(keySrc, 0, SymmUtils.getSymmKeyLength(algSymm));
            byte[] iv = Arrays.copyOfRange(keySrc, 0, SymmUtils.getSymmBlockLength(algSymm));

            showMsg("algorithm : " + algSymm.name());
            showMsg("data: " + Hex.toHexString(data));
            showMsg("key: " + Hex.toHexString(key));
            showMsg("iv: " + Hex.toHexString(iv));

            showMsg("--------------------------------------------------------------------");
            byte[] iv0 = iv.clone();
            byte[] mac = CMacTool.cmac(algSymm, key, iv0, data);
            showMsg("cmac: " + Hex.toHexString(mac));

            int blockSize = SymmUtils.getSymmBlockLength(algSymm);
            iv0 = iv.clone();
            int times = length / blockSize;
            int remain = length % blockSize;
            byte[] cmac = new byte[0];
            for (int i = 0; i < times; i++) {
                cmac = Arrays.copyOfRange(data, i * blockSize, i * blockSize + blockSize);
                cmac = CMacTool.cmac(algSymm, key, iv0, cmac);
            }
            if (remain > 0) {
                cmac = Arrays.copyOfRange(data, times * blockSize, data.length);
                cmac = CMacTool.cmac(algSymm, key, iv0, cmac);
            }

            showMsg("cmac: " + Hex.toHexString(cmac));
            Assert.assertArrayEquals(mac, cmac);
        }
    }

    /**
     * XX中心提供的测试数据，CMAC，SM4，IV
     * <p>
     * 使用《GBT 15852.1》的算法1和填充1进行CMAC
     */
    @Test
    public void test_cmac2() {
        for (TestData3 testData : TestData3.testData3) {
            AlgSymm algSymm = AlgSymm.SM4;
            showMsg("--------------------------------------------------------------------");
            showMsg("algorithm : " + algSymm.name());
            showMsg("key: " + Hex.toHexString(testData.key));
            if (testData.iv != null)
                showMsg("iv: " + Hex.toHexString(testData.iv));
            showMsg("mac: " + Hex.toHexString(testData.mac));

            byte[] cmac = CMacTool.cmac(algSymm, testData.key, testData.iv, testData.pt);
            showMsg("cmac: " + Hex.toHexString(cmac));
            Assert.assertArrayEquals(testData.mac, cmac);
        }
    }


    static class TestData3 {
        public String desc;
        public String alg;
        public int mode;
        public byte[] key;
        public byte[] iv;
        public byte[] pt;
        public byte[] ct;
        public byte[] mac;

        public TestData3(String desc, String alg, int mode, String key, String iv, String pt, String ct, String mac) {
            this.desc = desc;
            this.alg = alg;
            this.mode = mode;

            this.key = Hex.decode(key);
            if (iv != null)
                this.iv = Hex.decode(iv);
            this.pt = Hex.decode(pt);
            if (ct != null)
                this.ct = Hex.decode(ct);
            this.mac = Hex.decode(mac);
        }

        private static final int CBC_MAC_PAD_0000 = 0;
        private static final String SM4 = "SM4";

        //XX中心提供的测试数据，CMAC，SM4，IV
        static TestData3[] testData3 = {
                new TestData3(
                        "XX中心提供", SM4, CBC_MAC_PAD_0000,
                        "EEF3C9888129755F2C769DBC459448CE",
                        "FBD7B7AB0793F814B28A970F9E859C05",
                        "99C9D02D03F2CD394A680DC51B112322",
                        null,
                        "530EDF0605A302F30096AE46BD6316AF"
                ),
                new TestData3(
                        "XX中心提供", SM4, CBC_MAC_PAD_0000,
                        "973270DF92EFF5EC1E170A1566098CB3",
                        "2C2A98AF53A684F19DF3C39B721FA27E",
                        "AADA15E99FE95171B6F15FD3E427976E" +
                                "B1B595FCA82A23AC00C7AC7CEF9DDED7",
                        null,
                        "CF505945E5C135BC2BB4588D17E404D4"
                ),
                new TestData3(
                        "XX中心提供", SM4, CBC_MAC_PAD_0000,
                        "F82B569F5D3DCB61D0BE8778BF05D1B0",
                        "791004096432F985F7BE6B5CDAC79EB8",
                        "F76C0ADA8374F1D0C4B7EC5CC5047E03" +
                                "CF83B7A9ECE3777CFAEEC940ECE815CA" +
                                "E2FAA69EFAAC61A142C882CCC772E653",
                        null,
                        "651AF0AA9D73D2C6460DAEC83738AE3C"
                ),
                new TestData3(
                        "XX中心提供", SM4, CBC_MAC_PAD_0000,
                        "ABC854B48BD5811E22DDBB513313C858",
                        "500D6DD1001962FE4727C117ACDE2C4E",
                        "E0D1F45DB6C3DB00F954062DB748162F" +
                                "5FF589645686F61592A98574334BE914" +
                                "42B8BCDB331887D7D3873EDB63EFA4E4" +
                                "1FA3BC66BA9BDBD9F02A6CF6D6116044",
                        null,
                        "AA54E04FC85B56C2CEB1D58E122ADB79"
                ),
                new TestData3(
                        "中心提供", SM4, CBC_MAC_PAD_0000,
                        "3CA7EF836755B8D4A1F981A596DB17E8",
                        "607B652B1E129F6900FDF21D833AED4B",
                        "DF8C24D34145C12B335852E9F23468A9" +
                                "EA01C3A356FD07017F55706BF403D4A4" +
                                "B1C0E4C9448D18F62FFEB58DACC857F2" +
                                "73ABFC4C064E05B4B2DBA149E1CBA7DE" +
                                "C6A3809AD916306C48A5F564B1378356",
                        null,
                        "C5C98AC7CD492D4192706C7CCC6C9F79"
                )
        };
    }

    /**
     * 《GBT 15852.1-2008》-附录 测试数据。
     */
    static class TestData1 {
        AlgSymm algSymm;
        int typeAlg;
        int typePad;
        byte[] key1;
        byte[] key2;
        byte[] msg;
        byte[] mac;

        public TestData1(int typeAlg, int typePad, String hexKey1, String hexKey2, String hexMsg, String hexMac) {
            this.algSymm = defaultAlgSymm;
            this.typeAlg = typeAlg;
            this.typePad = typePad;

            this.key1 = Hex.decode(hexKey1);
            if (hexKey2 != null)
                this.key2 = Hex.decode(hexKey2);
            else
                this.key2 = null;

            this.msg = Hex.decode(hexMsg);
            this.mac = Hex.decode(hexMac);
        }

        static AlgSymm defaultAlgSymm = AlgSymm.DES;
        static String hexKey1 = "0123456789ABCDEF";
        static String hexKey2 = "FEDCBA9876543210";
        static final String msg1 = "Now is the time for all ";
        static final String msg2 = "Now is the time for it";
        static final String hexMsg1 = "4e6f77206973207468652074696d6520666f7220616c6c20";
        static final String hexMsg2 = "4e6f77206973207468652074696d6520666f72206974";

        static TestData1[] testData1 = {
                new TestData1(1, 1, hexKey1, null, hexMsg1, "70A30640"),
                new TestData1(1, 2, hexKey1, null, hexMsg1, "10E1F0F1"),
                new TestData1(1, 3, hexKey1, null, hexMsg1, "2C58FB8F"),
                new TestData1(1, 1, hexKey1, null, hexMsg2, "E45B3AD2"),
                new TestData1(1, 2, hexKey1, null, hexMsg2, "A924C721"),
                new TestData1(1, 3, hexKey1, null, hexMsg2, "B1ECD6FC"),

                new TestData1(2, 1, hexKey1, null, hexMsg1, "10F9BC67"),
                new TestData1(2, 2, hexKey1, null, hexMsg1, "BE7C2AB7"),
                new TestData1(2, 3, hexKey1, null, hexMsg1, "8EFC8BC7"),
                new TestData1(2, 1, hexKey1, null, hexMsg2, "215E9CE6"),
                new TestData1(2, 2, hexKey1, null, hexMsg2, "1736AC1A"),
                new TestData1(2, 3, hexKey1, null, hexMsg2, "05382696"),

                new TestData1(3, 1, hexKey1, hexKey2, hexMsg1, "A1C72E74"),
                new TestData1(3, 2, hexKey1, hexKey2, hexMsg1, "E9086230"),
                new TestData1(3, 3, hexKey1, hexKey2, hexMsg1, "AB059463"),
                new TestData1(3, 1, hexKey1, hexKey2, hexMsg2, "2E2B1428"),
                new TestData1(3, 2, hexKey1, hexKey2, hexMsg2, "5A692CE6"),
                new TestData1(3, 3, hexKey1, hexKey2, hexMsg2, "C59F7EED"),

                new TestData1(4, 1, hexKey1, hexKey2, hexMsg1, "AD3502B7"),
                new TestData1(4, 2, hexKey1, hexKey2, hexMsg1, "61C333E3"),
                new TestData1(4, 3, hexKey1, hexKey2, hexMsg1, "952AF838"),
                new TestData1(4, 1, hexKey1, hexKey2, hexMsg2, "05F1084C"),
                new TestData1(4, 2, hexKey1, hexKey2, hexMsg2, "A1BC0931"),
                new TestData1(4, 3, hexKey1, hexKey2, hexMsg2, "AFDEE0F9"),

                new TestData1(5, 1, hexKey1, null, hexMsg1, "F4E402B6B72C1317"),
                new TestData1(5, 2, hexKey1, null, hexMsg1, "70F05EC9E4F72F99"),
                new TestData1(5, 3, hexKey1, null, hexMsg1, "D61F51F2EA2A2D63"),
                new TestData1(5, 1, hexKey1, null, hexMsg2, "0F24BDA4AC220F4F"),
                new TestData1(5, 2, hexKey1, null, hexMsg2, "E00413419AFC160B"),
                new TestData1(5, 3, hexKey1, null, hexMsg2, "DDDF5ED30F18EBFC"),

                new TestData1(6, 1, hexKey1, hexKey2, hexMsg1, "577EF22118CE5DBA"),
                new TestData1(6, 2, hexKey1, hexKey2, hexMsg1, "607460B8D8C0FDFA"),
                new TestData1(6, 3, hexKey1, hexKey2, hexMsg1, "FD3DBB6EF1650754"),
                new TestData1(6, 1, hexKey1, hexKey2, hexMsg2, "10F747D14F72C229"),
                new TestData1(6, 2, hexKey1, hexKey2, hexMsg2, "B29B9A76DD1C3912"),
                new TestData1(6, 3, hexKey1, hexKey2, hexMsg2, "F645FB7D4D4A42B4"),
        };
    }

    /**
     * SP800-38B 测试数据。
     */
    static class TestData2 {
        AlgSymm algSymm;
        byte[] key;
        byte[] msg;
        byte[] mac;

        public TestData2(AlgSymm algSymm, String hexKey, String hexMsg, String hexMac) {
            this.algSymm = algSymm;
            this.key = Hex.decode(hexKey);
            this.msg = Hex.decode(hexMsg);
            this.mac = Hex.decode(hexMac);
        }


        //SP800-38B 测试数据。
        static TestData2[] testData2 = {
                new TestData2(
                        AlgSymm.AES128,
                        "2b7e151628aed2a6abf7158809cf4f3c",
                        "",
                        "bb1d6929e95937287fa37d129b756746"
                ),

                new TestData2(
                        AlgSymm.AES128,
                        "2b7e151628aed2a6abf7158809cf4f3c",
                        "6bc1bee22e409f96e93d7e117393172a",
                        "070a16b46b4d4144f79bdd9dd04a287c"
                ),

                new TestData2(
                        AlgSymm.AES128,
                        "2b7e151628aed2a6abf7158809cf4f3c",
                        "6bc1bee22e409f96e93d7e117393172a" +
                                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                                "30c81c46a35ce411",
                        "dfa66747de9ae63030ca32611497c827"
                ),

                new TestData2(
                        AlgSymm.AES128,
                        "2b7e151628aed2a6abf7158809cf4f3c",
                        "6bc1bee22e409f96e93d7e117393172a" +
                                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                                "30c81c46a35ce411e5fbc1191a0a52ef" +
                                "f69f2445df4f9b17ad2b417be66c3710",
                        "51f0bebf7e3b9d92fc49741779363cfe"
                ),

                new TestData2(
                        AlgSymm.AES192,
                        "8e73b0f7da0e6452c810f32b809079e5" +
                                "62f8ead2522c6b7b",
                        "",
                        "d17ddf46adaacde531cac483de7a9367"
                ),

                new TestData2(
                        AlgSymm.AES192,
                        "8e73b0f7da0e6452c810f32b809079e5" +
                                "62f8ead2522c6b7b",
                        "6bc1bee22e409f96e93d7e117393172a",
                        "9e99a7bf31e710900662f65e617c5184"
                ),

                new TestData2(
                        AlgSymm.AES192,
                        "8e73b0f7da0e6452c810f32b809079e5" +
                                "62f8ead2522c6b7b",
                        "6bc1bee22e409f96e93d7e117393172a" +
                                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                                "30c81c46a35ce411",
                        "8a1de5be2eb31aad089a82e6ee908b0e"
                ),

                new TestData2(
                        AlgSymm.AES192,
                        "8e73b0f7da0e6452c810f32b809079e5" +
                                "62f8ead2522c6b7b",
                        "6bc1bee22e409f96e93d7e117393172a" +
                                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                                "30c81c46a35ce411e5fbc1191a0a52ef" +
                                "f69f2445df4f9b17ad2b417be66c3710",
                        "a1d5df0eed790f794d77589659f39a11"
                ),

                new TestData2(
                        AlgSymm.AES256,
                        "603deb1015ca71be2b73aef0857d7781" +
                                "1f352c073b6108d72d9810a30914dff4",
                        "",
                        "028962f61b7bf89efc6b551f4667d983"
                ),

                new TestData2(
                        AlgSymm.AES256,
                        "603deb1015ca71be2b73aef0857d7781" +
                                "1f352c073b6108d72d9810a30914dff4",
                        "6bc1bee22e409f96e93d7e117393172a",
                        "28a7023f452e8f82bd4bf28d8c37c35c"
                ),

                new TestData2(
                        AlgSymm.AES256,
                        "603deb1015ca71be2b73aef0857d7781" +
                                "1f352c073b6108d72d9810a30914dff4",
                        "6bc1bee22e409f96e93d7e117393172a" +
                                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                                "30c81c46a35ce411",
                        "aaf3d8f1de5640c232f5b169b9c911e6"
                ),

                new TestData2(
                        AlgSymm.AES256,
                        "603deb1015ca71be2b73aef0857d7781" +
                                "1f352c073b6108d72d9810a30914dff4",
                        "6bc1bee22e409f96e93d7e117393172a" +
                                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                                "30c81c46a35ce411e5fbc1191a0a52ef" +
                                "f69f2445df4f9b17ad2b417be66c3710",
                        "e1992190549f6ed5696a2c056c315410"
                ),

                new TestData2(
                        AlgSymm.DESede3,
                        "8aa83bf8cbda1062" +
                                "0bc1bf19fbb6cd58" +
                                "bc313d4a371ca8b5",
                        "",
                        "b7a688e122ffaf95"
                ),

                new TestData2(
                        AlgSymm.DESede3,
                        "8aa83bf8cbda1062" +
                                "0bc1bf19fbb6cd58" +
                                "bc313d4a371ca8b5",
                        "6bc1bee22e409f96",
                        "8e8f293136283797" //此处和文档中不一致，应该是文档数据错误，因为文档中的值和前一个空消息的MAC一样。
                ),

                new TestData2(
                        AlgSymm.DESede3,
                        "8aa83bf8cbda1062" +
                                "0bc1bf19fbb6cd58" +
                                "bc313d4a371ca8b5",
                        "6bc1bee22e409f96e93d7e117393172aae2d8a57",
                        "743ddbe0ce2dc2ed" //此处和文档中不一致，文档中为"d32bcebe43d23d80"
                ),

                new TestData2(
                        AlgSymm.DESede3,
                        "8aa83bf8cbda1062" +
                                "0bc1bf19fbb6cd58" +
                                "bc313d4a371ca8b5",
                        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
                        "33e6b1092400eae5"
                ),

                new TestData2(
                        AlgSymm.DESede,
                        "4cf15134a2850dd5" +
                                "8a3d10ba80570d38",
                        "",
                        "bd2ebf9a3ba00361"
                ),

                new TestData2(
                        AlgSymm.DESede,
                        "4cf15134a2850dd5" +
                                "8a3d10ba80570d38",
                        "6bc1bee22e409f96",
                        "4ff2ab813c53ce83" //此处和文档中不一致，应该是文档数据错误，因为文档中的值和前一个空消息的MAC一样。
                ),

                new TestData2(
                        AlgSymm.DESede,
                        "4cf15134a2850dd5" +
                                "8a3d10ba80570d38",
                        "6bc1bee22e409f96e93d7e117393172aae2d8a57",
                        "62dd1b471902bd4e" //此处和文档中不一致，文档中为"8ea92435b52660e0"
                ),

                new TestData2(
                        AlgSymm.DESede3,
                        "4cf15134a2850dd5" +
                                "8a3d10ba80570d38",
                        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
                        "31b1e431dabc4eb8"
                ),
        };
    }

    /**
     * 《GBT 15852.1-2020》-附录 测试数据。
     */
    static class TestData4 {
        AlgSymm algSymm;
        int typeAlg;
        int typePad;
        byte[] key1;
        byte[] key2;
        byte[] msg;
        byte[] mac;

        public TestData4(int typeAlg, int typePad, String hexKey1, String hexKey2, String hexMsg, String hexMac) {
            this.algSymm = defaultAlgSymm;
            this.typeAlg = typeAlg;
            this.typePad = typePad;

            this.key1 = Hex.decode(hexKey1);
            if (hexKey2 != null)
                this.key2 = Hex.decode(hexKey2);
            else
                this.key2 = null;

            this.msg = Hex.decode(hexMsg);
            this.mac = Hex.decode(hexMac);
        }

        static AlgSymm defaultAlgSymm = AlgSymm.SM4;
        static String hexKey1 = "0123456789ABCDEFFEDCBA9876543210";
        static String hexKey2 = "4149D2ADED9456681EC8B511D9E7EE04";
        static final String msg1 = "This is the test message for mac";
        static final String msg2 = "This is the test message ";
        static final String hexMsg1 = "54686973206973207468652074657374206d65737361676520666f72206d6163";
        static final String hexMsg2 = "54686973206973207468652074657374206d65737361676520";


        static TestData4[] testData4 = {
                new TestData4(1, 1, hexKey1, null, hexMsg1, "16E02904EFB765B7"),
                new TestData4(1, 2, hexKey1, null, hexMsg1, "4B6553AF3C4E2744"),
                new TestData4(1, 3, hexKey1, null, hexMsg1, "71AF7E4553404CBC"),
                new TestData4(1, 1, hexKey1, null, hexMsg2, "BA89E45FE8ABF242"),
                new TestData4(1, 2, hexKey1, null, hexMsg2, "421AD1690AA152E2"),
                new TestData4(1, 3, hexKey1, null, hexMsg2, "6A4A86F5B5E468DA"),
//
                new TestData4(2, 1, hexKey1, hexKey2, hexMsg1, "1E9A71D3BC92DFA7"),
                new TestData4(2, 2, hexKey1, hexKey2, hexMsg1, "E423E35599AFD948"),
                new TestData4(2, 3, hexKey1, hexKey2, hexMsg1, "4003BA1B6ADC53A8"),
                new TestData4(2, 1, hexKey1, hexKey2, hexMsg2, "4EC3C7FACFAAC607"),
                new TestData4(2, 2, hexKey1, hexKey2, hexMsg2, "F02625CEAD008D4E"),
                new TestData4(2, 3, hexKey1, hexKey2, hexMsg2, "FFD5F1F2E5EDA5CB"),

                new TestData4(3, 1, hexKey1, hexKey2, hexMsg1, "2763211B2BCAF719"),
                new TestData4(3, 2, hexKey1, hexKey2, hexMsg1, "51E9928C2238330C"),
                new TestData4(3, 3, hexKey1, hexKey2, hexMsg1, "7CD48C4242E45575"),
                new TestData4(3, 1, hexKey1, hexKey2, hexMsg2, "E32D99A689C05259"),
                new TestData4(3, 2, hexKey1, hexKey2, hexMsg2, "197247229CE9D7B6"),
                new TestData4(3, 3, hexKey1, hexKey2, hexMsg2, "3C430F1EA43B540C"),

                new TestData4(4, 1, hexKey1, hexKey2, hexMsg1, "DD1052A7AFE8999B"),
                new TestData4(4, 2, hexKey1, hexKey2, hexMsg1, "7E1A9A5E0EF0947F"),
                new TestData4(4, 3, hexKey1, hexKey2, hexMsg1, "28A70D6BCCF74422"),
                new TestData4(4, 1, hexKey1, hexKey2, hexMsg2, "AA9DB3D9651F862B"),
                new TestData4(4, 2, hexKey1, hexKey2, hexMsg2, "949476D35F17261E"),
                new TestData4(4, 3, hexKey1, hexKey2, hexMsg2, "C9D34E16C49AB643"),

                new TestData4(5, 4, hexKey1, null, hexMsg1, "692C437100F3B5EE"),
                new TestData4(5, 4, hexKey1, null, hexMsg2, "4738A6C760B280FC"),

                new TestData4(6, 1, hexKey1, null, hexMsg1, "B38A96195BAA61FC"),
                new TestData4(6, 2, hexKey1, null, hexMsg1, "A0C465EE5896972F"),
                new TestData4(6, 3, hexKey1, null, hexMsg1, "43050D51C656AE60"),
                new TestData4(6, 1, hexKey1, null, hexMsg2, "8CF6E64314FEF417"),
                new TestData4(6, 2, hexKey1, null, hexMsg2, "60DD955ED0CA3D7A"),
                new TestData4(6, 3, hexKey1, null, hexMsg2, "61E00049E26962A3"),

                new TestData4(7, 4, hexKey1, null, hexMsg1, "16E02904EFB765B7"),
                new TestData4(7, 4, hexKey1, null, hexMsg2, "846FA2A5D83445A9"),

                new TestData4(8, 4, hexKey1, null, hexMsg1, "E40ED79C3149A1C9"),
                new TestData4(8, 4, hexKey1, null, hexMsg2, "A99D13013E892EE2"),
        };
    }

}
