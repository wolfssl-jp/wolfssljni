/* WolfSSLParameters.java
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

import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

/**
 * wolfJSSE implementation of SSLParameters
 *
 * This class includes the functionality of java SSLParameters, but allows
 * wolfJSSE better control over settings, interop with older Java versions,
 * etc. Strings set and returned should be cloned.
 *
 * This class is used internally to wolfJSSE. When a SSLParameters needs to
 * be returned to an application (ex: SSLContext.getDefaultSSLParameters(),
 * SSLContext.getSupportedSSLParameters()) wolfJSSE calls
 * WolfSSLEngineHelper.decoupleParams() which creates a SSLParameters object
 * from a WolfSSLParameters.
 */
final class WolfSSLParameters {

    private String[] cipherSuites;
    private String[] protocols;
    private boolean wantClientAuth = false;
    private boolean needClientAuth = false;
    private String endpointIdAlgorithm;
    private List<WolfSSLSNIServerName> serverNames;
    private boolean useCipherSuiteOrder = true;
    String[] applicationProtocols = new String[0];
    private boolean useSessionTickets = false;
    private byte[] alpnProtocols = null;

    /* create duplicate copy of these parameters */
    protected WolfSSLParameters copy() {
        WolfSSLParameters cp = new WolfSSLParameters();
        cp.setCipherSuites(this.cipherSuites);
        cp.setProtocols(this.protocols);
        cp.wantClientAuth = this.wantClientAuth;
        cp.needClientAuth = this.needClientAuth;
        cp.setServerNames(this.getServerNames());
        cp.useSessionTickets = this.useSessionTickets;

        /* TODO: duplicate other properties here when WolfSSLParameters
         * can handle them */

        return cp;
    }

    String[] getCipherSuites() {
        return this.cipherSuites.clone();
    }

    void setCipherSuites(String[] cipherSuites) {
        /* cipherSuites array is sanitized by wolfJSSE caller */
        this.cipherSuites = cipherSuites.clone();
    }

    String[] getProtocols() {
        return this.protocols.clone();
    }

    void setProtocols(String[] protocols) {
        /* protocols array is sanitized by wolfJSSE caller */
        this.protocols = protocols.clone();
    }

    boolean getWantClientAuth() {
        return this.wantClientAuth;
    }

    void setWantClientAuth(boolean wantClientAuth) {
        /* wantClientAuth OR needClientAuth can be set, not both */
        this.wantClientAuth = wantClientAuth;
        this.needClientAuth = false;
    }

    boolean getNeedClientAuth() {
        return this.needClientAuth;
    }

    void setNeedClientAuth(boolean needClientAuth) {
        /* wantClientAuth OR needClientAuth can be set, not both */
        this.needClientAuth = needClientAuth;
        this.wantClientAuth = false;
    }

    String getEndpointIdentificationAlgorithm() {
        return this.endpointIdAlgorithm;
    }

    void setEndPointIdentificationAlgorithm(String algorithm) {
        this.endpointIdAlgorithm = algorithm;
    }

    void setServerNames(List<WolfSSLSNIServerName> serverNames) {
        if (serverNames == null) {
            this.serverNames = null;
        } else {
            this.serverNames = Collections.unmodifiableList(
                    new ArrayList<WolfSSLSNIServerName>(serverNames));
        }
    }

    List<WolfSSLSNIServerName> getServerNames() {
        if (this.serverNames == null) {
            return null;
        } else {
            return Collections.unmodifiableList(
                    new ArrayList<WolfSSLSNIServerName>(this.serverNames));
        }
    }

    /* not part of Java SSLParameters. Needed here for Android compatibility */
    void setUseSessionTickets(boolean useTickets) {
        this.useSessionTickets = useTickets;
    }

    boolean getUseSessionTickets() {
        return this.useSessionTickets;
    }

    void setAlpnProtocols(byte[] alpnProtos) {

        if (alpnProtos == null || alpnProtos.length == 0) {
            throw new IllegalArgumentException(
                "ALPN protocol array null or zero length");
        }

        this.alpnProtocols = alpnProtos;
    }

    byte[] getAlpnProtos() {
        return this.alpnProtocols;
    }

    /* TODO, create our own class for SNIMatcher, in case Java doesn't support it */
    //void setSNIMatchers(Collection<SNIMatcher> matchers) {
    //    /* TODO */
    //}

    /* TODO, create our own class for SNIMatcher, in case Java doesn't support it */
    //Collection<SNIMatcher> getSNIMatchers() {
    //    return null; /* TODO */
    //}

    void setUseCipherSuitesOrder(boolean honorOrder) {
        this.useCipherSuiteOrder = honorOrder;
    }

    boolean getUseCipherSuitesOrder() {
        return this.useCipherSuiteOrder;
    }

    String[] getApplicationProtocols() {
        return this.applicationProtocols.clone();
    }

    void setApplicationProtocols(String[] protocols) {
        this.applicationProtocols = protocols.clone();
    }
}

