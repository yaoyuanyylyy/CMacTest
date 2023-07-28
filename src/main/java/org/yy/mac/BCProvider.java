package org.yy.mac;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * Get BC provider instance.
 *
 * Created by YaoYuan on 2020/11/13.
 */
public class BCProvider {
    private static volatile Provider bcProvider;

    /**
     * Code copy from {@link org.bouncycastle.jcajce.util.BCJcaJceHelper}.
     *
     * @return Provider for BouncyCastle
     */
    public static synchronized Provider getProvider()
    {
        final Provider system = Security.getProvider("BC");
        if (system instanceof BouncyCastleProvider)
            return system;
        else if (bcProvider != null)
            return bcProvider;
        else {
            bcProvider = new BouncyCastleProvider();
            return bcProvider;
        }
    }
}
