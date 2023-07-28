
[toc]

# 相关标准和文档

- 《GBT 15852.1-2008 信息技术 安全技术 消息鉴别码 第1部分：采用分组密码的机制》
- 《GBT 15852.1-2020 信息技术 安全技术 消息鉴别码 第1部分：采用分组密码的机制》
- ISO 9797 Message Authentication Codes (MACs)
  Part 1: Mechanisms using a block cipher
    <https://www.doc88.com/p-57347146035924.html>
  Part 2: Mechanisms using a dedicated hash-function
    <https://www.doc88.com/p-0159667006070.html>
  Part 3: Mechanisms using a universal hash-function
    <https://www.doc88.com/p-9734810928184.html>
- RFC4493: The AES-CMAC Algorithm
- T. Iwata and K. Kurosawa. OMAC: One-Key CBC MAC
  <https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/omac/omac-ad.pdf>
- NIST SP800-38A Recommendation for Block Cipher modes of Operation – Methods and Techniques
- NIST SP800-38B Recommendation for Block Cipher Modes of Operation – the CMAC Mode for Authentication
  <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf>

- ANSI X3.92 Data Encryption Algorithm (DEA)
- ANSI X3.106 Modems of DEA Operation
- ANSI X4.16 American National Standard for financial services, financial transaction cards, magnetic stripe encoding
- ANSI X9.8 Personal Identification Number (PIN) Management and Security
- ANSI X9.9 Financial institution message authentication (wholesale)
- ANSI X9.19 Financial Institution Retail Message Authentication (MAC)
- ISO 7810 Identification cards – Physical characteristics
- ISO 7811 Identification cards – Recording technique
- ISO 7812 Identification cards – Identification of issuers
- ISO 7813 Identification cards – Financial transaction cards
- ISO 7816 Identification cards – Integrated circuit(s) cards with contacts
- ISO 8583 Bank card originated messages – Interchange message specifications – Content for financial transactions
- ISO 8731-1 Banking: Approved algorithms for message authentication
  Part 1 – DEA
  <https://www.doc88.com/p-373487237594.html>
  Part 2 – Message Authentication algorithms
  <https://www.doc88.com/p-1426368720696.html>
- ISO 9807 Banking and releated financial service – Requirements for Message Authentication(Retail)
  <https://www.doc88.com/p-9992812642133.html>

# 概述

CMAC, Cipher-based MAC, 即基于AES对称加密算法的MAC，可参考`ISO 9797-1`标准，其中详细定义了CMAC算法，其对应的国标为`《GBT 15852.1》`。
最早的CMAC是基于DES的CBC模式构造的MAC，即CBC-MAC，可参考`ANSI X9.9`、`ANSI X9.19`。
然后 John Black 和 Phillip Rogaway 于2000年提出的避免CBC-MAC安全缺陷的XCBC模式（Extend Cipher Block Chaining Mode），作为CBC模式的扩展，用来构造MAC，即`XCBC-MAC`。
再后来，Tetsu Iwata 和 Kaoru Kurosawa 基于XCBC-MAC提出了`OMAC`，即`One-Key CBC-MAC`，接着又精益求精第提出了OMAC1，前面的OMAC被重新命名为OMAC2，可参考其论文。
现在提到CMAC通常是指OMAC，而OMAC通常是指OMAC1，可参考`NIST SP800-38B`标准，也可参考`RFC4493`文档，其中的测试数据里使用了AES128/192/256算法和3DES算法。
基于`《GBT 15852.1》`的算法1和填充1可以实现《GBT 36322》中的`SDF_CalculateMAC`接口。

# 文档说明

1. ISO 9797: CMAC算法，定义了几种不同MAC算法和填充方式。
2. GBT 15852.1: 国家标准。2008版本对标ISO 9797-1:1999；2020版本对标ISO 9797-1:2011。
3. X9.9: DES CBC-MAC，其算法对应到“GBT 15852.1”中的“算法1，填充1”。
4. X9.19: 3DES CBC-MAC，其算法对应到“GBT 15852.1”中的“算法3，填充1”。
5. SP800-38B: 定义了使用AES和TDEA算法来计算MAC的CMAC模式

# CMAC：《GBT 15852.1-2020》

1. 总结

|算法 |密钥诱导<br>(可选;2种)|消息填充<br>(4种)|初始变换<br>(3种)|最终迭代<br>(4种) |输出变换<br>(3种)|截断操作<br>(2种)|
|--------------------|-----------|--------|--------|---------|--------|--------|
|算法1: CBC-MAC  |           |1/2/3   |1       |1        |1       |1       | 
|算法2: EMAC           |1(可能)      |1/2/3   |1       |1        |2-key2  |1       | 
|算法3: ANSI retail MAC|           |1/2/3   |1       |1        |3-key2  |1       | 
|算法4: MacDES         |1(可能)      |1/2/3   |2-K1    |1        |2-key2  |1       | 
|算法5: CMAC/OMAC1     |2          |4       |1       |3-(K1,K2)|1       |1       |
|算法6: LMAC           |1(可能)      |1/2/3   |1       |2-K2     |1       |1       |
|算法7: TrCBC          |           |4       |1       |1        |1       |2       | 
|算法8: CBCR           |           |4       |3       |4        |1       |1       |

## ParametersWithPadding类

ParametersWithPadding类用来设置算法的各种参数。其中定义**key1**表示需要输入的原始密钥；**key2**表示在输出变换中使用的密钥，可能是在最开始设置的，也可能是通过密钥诱导生成的。

## YCMac类

在**YCMac**类中实现了标准中的8种算法。其中定义的**K1**，表示用在初始变换2或最终迭代3中的密钥；**K2**表示用在最终迭代2/3中的密钥。
2020标准中定义的MAC算法的8步操作在YCMac中的处理方法如下：

- 第1步：**密钥诱导**: keyInduce
- 第2步：**消息填充**: paddingTransform
- 第3步：**数据分割**: 在 update 中自动处理
- 第4步：**初始变换**: initTransform
- 第5步：**迭代应用分组密码**: 在 update 中自动处理
- 第6步：**最终迭代**: lastIteration
- 第7步：**输出变换**: outTransform
- 第8步：**截断操作**: truncate

## 密钥诱导

在2008标准中定义了一个密钥诱导，在2020标准中定义了另外两个不同的密钥诱导，即密钥诱导1和密钥诱导2。密钥诱导在YCMac中的keyInduce方法中按照不同的算法进行处理。

但对于算法2有点特殊，为了兼容2008标准及其附录测试，在ParametersWithPadding中定义了keyInduce参数表示密钥诱导方式(仅用于算法2中)。

- 0: 表示使用2008标准中的密钥诱导；在2008标准中定义，并在附录测试中用到；
- 1: 表示使用2020标准中的密钥诱导1。在2020标准中定义，但附录测试中提供了2个密钥，未用到。  
- 默认为1，以符合2020标准。所以为了兼容2008标准或验证2008标准的附录测试，需要手动设置为0.

  算法1/3/7/8不需要密钥诱导，其他算法的密钥诱导参看下面的代码：

```java
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
```

## 测试

在YMacTest的 test_GBT15852_2020() 里对《GBT 15852.1-2020 信息技术 安全技术 消息鉴别码 第1部分：采用分组密码的机制》-附录B 进行了测试和验证。


# 博客
<https://blog.csdn.net/yaoyuanyylyy/article/details/127687829>


