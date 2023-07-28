package org.yy.mac;

/**
 * SymmCipher Crypt Exception.
 *
 * Created by YaoYuan on 2020/11/13.
 */
public class YCryptoException extends Exception{
    public YCryptoException() {
        super();
    }

    public YCryptoException(String message) {
        super(message);
    }

    public YCryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public YCryptoException(Throwable cause) {
        super(cause);
    }

    protected YCryptoException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}