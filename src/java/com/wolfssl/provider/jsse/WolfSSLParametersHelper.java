/* WolfSSLEngineHelper.java
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */
package com.wolfssl.provider.jsse;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import javax.net.ssl.SSLParameters;

public class WolfSSLParametersHelper
{
    private static Method getServerNames = null;
    private static Method setServerNames = null;

    /* Runs upon class initialization to detect if this version of Java
     * has SSLParameters methods that older versions may not have */
    static
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Object run() {
                Class<?> c = SSLParameters.class;
                Method[] methods = c.getDeclaredMethods();
                if (methods == null) {
                    return null;
                }

                /* check for availability of methods */
                try {
                    for (Method m : methods) {
                        switch (m.getName()) {
                            case "getServerNames":
                                getServerNames = m;
                                continue;
                            case "setServerNames":
                                setServerNames = m;
                                continue;
                            default:
                                continue;
                        }
                    }
                } catch (Exception e) {
                }

                return null;
            }
        });
    }

    /**
     * Creates a new SSLParameters class with the same settings as the
     * WolfSSLParameters passed in.
     *
     * @param in WolfSSLParameters to convert to SSLParameters
     * @return new SSLParameters object representing same settings as "in"
     */
    protected static SSLParameters decoupleParams(WolfSSLParameters in) {

        /* Note: Android API 23 only supports the following SSLParameters
         * methods. All newer methods we will need to conditionally
         * support:
         *     get/setCipherSuites()
         *     get/setCipherSuites()
         *     get/setNeedClientAuth()
         *     get/setWantClientAuth()
         */

        SSLParameters ret = new SSLParameters(in.getCipherSuites(),
                                              in.getProtocols());

        ret.setNeedClientAuth(in.getNeedClientAuth());
        if (!ret.getNeedClientAuth()) {
            ret.setWantClientAuth(in.getWantClientAuth());
        }

        /* Methods added as of JDK 1.8, older JDKs will not have them. Using
         * Java reflection to detect availability. */

        if (setServerNames != null) {

            try {
                /* load WolfSSLJDK8Helper at runtime, not compiled on older JDKs */
                Class<?> cls = Class.forName("com.wolfssl.provider.jsse.WolfSSLJDK8Helper");
                Object obj = cls.getConstructor().newInstance();
                Class[] paramList = new Class[3];
                paramList[0] = javax.net.ssl.SSLParameters.class;
                paramList[1] = java.lang.reflect.Method.class;
                paramList[2] = com.wolfssl.provider.jsse.WolfSSLParameters.class;

                Method mth = cls.getDeclaredMethod("setServerNames", paramList);
                mth.invoke(obj, ret, setServerNames, in);

            } catch (Exception e) {
                /* ignore, class not found */
            }
        }

        /* The following SSLParameters features are not yet supported
         * by wolfJSSE (see Android API 23 note above). They are supported
         * with newer versions of SSLParameters, but will need to be added
         * conditionally to wolfJSSE when supported. */
        /*ret.setAlgorithmConstraints(in.getAlgorithmConstraints());
        ret.setApplicationProtocols(in.getApplicationProtocols());
        ret.setEnableRetransmissions(in.getEnableRetransmissions());
        ret.setEndpointIdentificationAlgorithm(
            in.getEndpointIdentificationAlgorithm());
        ret.setMaximumPacketSize(in.getMaximumPacketSize());
        ret.setSNIMatchers(in.getSNIMatchers());
        ret.setUseCipherSuitesOrder(in.getUseCipherSuitesOrder());
        */

        return ret;
    }

    /**
     * Import SSLParameters into an existing WolfSSLParameters object. Used
     * internally by SSLSocket.setSSLParameters().
     *
     * @param in SSLParameters to import settings from
     * @param out WolfSSLParameters to copy settings into
     */
    protected static void importParams(SSLParameters in,
                                       WolfSSLParameters out) {

        if (in == null || out == null) {
            throw new NullPointerException("input parameters cannot be " +
                    "null to WolfSSLParametersHelper.importParams()");
        }

        /* Note: Android API 23 only supports the following SSLParameters
         * methods. All newer methods we will need to conditionally
         * support:
         *     get/setCipherSuites()
         *     get/setCipherSuites()
         *     get/setNeedClientAuth()
         *     get/setWantClientAuth()
         */

        out.setCipherSuites(in.getCipherSuites());
        out.setProtocols(in.getProtocols());
        out.setNeedClientAuth(in.getNeedClientAuth());
        if (!out.getNeedClientAuth()) {
            out.setWantClientAuth(in.getWantClientAuth());
        }

        /* Methods added as of JDK 1.8, older JDKs will not have them. Using
         * Java reflection to detect availability. */

        if (getServerNames != null) {
            try {
                /* load WolfSSLJDK8Helper at runtime, not compiled on older JDKs */
                Class<?> cls = Class.forName("com.wolfssl.provider.jsse.WolfSSLJDK8Helper");
                Object obj = cls.getConstructor().newInstance();
                Class[] paramList = new Class[2];
                paramList[0] = javax.net.ssl.SSLParameters.class;
                paramList[1] = com.wolfssl.provider.jsse.WolfSSLParameters.class;

                Method mth = cls.getDeclaredMethod("getServerNames", paramList);
                mth.invoke(obj, in, out);

            } catch (Exception e) {
                /* ignore, class not found */
            }
        }

        /* The following SSLParameters features are not yet supported
         * by wolfJSSE (see Android API 23 note above). They are supported
         * with newer versions of SSLParameters, but will need to be added
         * conditionally to wolfJSSE when supported. */
        /*out.setAlgorithmConstraints(in.getAlgorithmConstraints());
        out.setApplicationProtocols(in.getApplicationProtocols());
        out.setEnableRetransmissions(in.getEnableRetransmissions());
        out.setEndpointIdentificationAlgorithm(
            in.getEndpointIdentificationAlgorithm());
        out.setMaximumPacketSize(in.getMaximumPacketSize());
        out.setSNIMatchers(in.getSNIMatchers());
        out.setUseCipherSuitesOrder(in.getUseCipherSuitesOrder());
        */
    }
}

