/* WolfSSLImplementSession.java
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

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLSession;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.X509KeyManager;
import javax.security.cert.*;

/**
 * wolfSSL Session
 * Note: suppress depreciation warning for javax.security.cert.X509Certificate
 * @author wolfSSL
 */
@SuppressWarnings("deprecation")
public class WolfSSLImplementSSLSession implements SSLSession {
    private WolfSSLSession ssl;
    private final WolfSSLAuthStore authStore;
    private WolfSSLSessionContext ctx = null;
    private boolean valid;
    private final HashMap<String, Object> binding;
    private final int port;
    private final String host;
    String protocol = null;
    Date creation;
    Date accessed; /* when new connection was made using session */

    /**
     * Is this object currently inside the WolfSSLAuthStore session cache table?
     *
     * Used to mark when and where native WOLFSSL_SESSION pointers are freed.
     * Sessions inside the table always have their sesPtr freed by the finalizer
     * upon garbage collection. Otherwise, if sessions are taken out of the
     * table and sesPtr is updated afterwards sesPtrUpdateAfterTable is set to
     * true and the sesPtr is then freed by that object either during
     * setResume() or finalization.
     */
    protected boolean isInTable = false;

    /**
     * Indicates if this session was retrieved out of the WolfSSLAuthStore
     * session table/store. This is used by WolfSSLEngineHelper to help
     * determine if session creation is allowed. See Javadocs for
     * SSLEngine/SSLSocket setEnableSessionCreation()
     */
    protected boolean isFromTable = false;

    /**
     * Tracks if WOLFSSL_SESSION pointer has been updated after retreived from
     * cache table.
     */
    protected boolean sesPtrUpdatedAfterTable = false;

    /**
     * has this session been registered
     */
    private long sesPtr = 0;
    private String nullCipher = "SSL_NULL_WITH_NULL_NULL";
    private String nullProtocol = "NONE";

    /*
     * Lock around access to WOLFSSL_SESSION pointer. Static since there could
     * be multiple WolfSSLSocket refering to the same WOLFSSL_SESSION pointer
     * in resumption cases.
     */
    private static final Object sesPtrLock = new Object();

    public WolfSSLImplementSSLSession (WolfSSLSession in, int port, String host,
            WolfSSLAuthStore params) {
        this.ssl = in;
        this.port = port;
        this.host = host;
        this.authStore = params;
        this.valid = false; /* flag if joining or resuming session is allowed */
        this.sesPtr = 0;
        this.protocol = this.nullProtocol;
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();
    }

    public WolfSSLImplementSSLSession (WolfSSLSession in,
                                       WolfSSLAuthStore params) {
        this.ssl = in;
        this.port = -1;
        this.host = null;
        this.authStore = params;
        this.valid = false; /* flag if joining or resuming session is allowed */
        this.sesPtr = 0;
        this.protocol = this.nullProtocol;
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();
    }

    public WolfSSLImplementSSLSession (WolfSSLAuthStore params) {
        this.port = -1;
        this.host = null;
        this.authStore = params;
        this.valid = false; /* flag if joining or resuming session is allowed */
        this.sesPtr = 0;
        this.protocol = this.nullProtocol;
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();
    }

    public byte[] getId() {
        if (ssl == null) {
            return new byte[0];
        }
        return this.ssl.getSessionID();
    }

    public synchronized SSLSessionContext getSessionContext() {
        return ctx;
    }

    /**
     * Setter function for the SSLSessionContext used with session creation
     * @param ctx value to set the session context as
     */
    protected void setSessionContext(WolfSSLSessionContext ctx) {
        this.ctx = ctx;
    }

    public long getCreationTime() {
        return creation.getTime();
    }

    public long getLastAccessedTime() {
        return accessed.getTime();
    }

    public void invalidate() {
        this.valid = false;
    }

    public boolean isValid() {
        return this.valid;
    }

    /**
     * Return status of internal session pointer (WOLFSSL_SESSION).
     * 
     * @return true if this.sesPtr is set, otherwise false if 0
     */
    protected boolean sessionPointerSet() {
        synchronized (sesPtrLock) {
            if (this.sesPtr == 0) {
                return false;
            }
            return true;
        }
    }

    /**
     * After a connection has been established or on restoring connection the session
     * is then valid and can be joined or resumed
     * @param in true/false valid boolean
     */
    protected void setValid(boolean in) {
        this.valid = in;
    }

    /**
     * Check if this session is resumable.
     *
     * Calls down to native wolfSSL_SESSION_is_resumable() with
     * WOLFSSL_SESSION pointer.
     *
     * @return true if resumable, otherwise false
     */
    protected synchronized boolean isResumable() {
        synchronized (sesPtrLock) {
            if (WolfSSLSession.sessionIsResumable(this.sesPtr) == 1) {
                return true;
            } else {
                return false;
            }
        }
    }


    public void putValue(String name, Object obj) {
        Object old;

        if (name == null) {
            throw new IllegalArgumentException();
        }

        /* check if Object should be notified */
        if (obj instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) obj).valueBound(
                    new SSLSessionBindingEvent(this, name));
        }

        old = binding.put(name, obj);
        if (old != null) {
            if (old instanceof SSLSessionBindingListener) {
                ((SSLSessionBindingListener) old).valueUnbound(
                        new SSLSessionBindingEvent(this, name));
            }
        }
    }

    public Object getValue(String name) {
        return binding.get(name);
    }

    public void removeValue(String name) {
        Object obj;

        if (name == null) {
            throw new IllegalArgumentException();
        }

        obj = binding.get(name);
        if (obj != null) {
            /* check if Object should be notified */
            if (obj instanceof SSLSessionBindingListener) {
                ((SSLSessionBindingListener) obj).valueUnbound(
                        new SSLSessionBindingEvent(this, name));
            }
            binding.remove(name);
        }
    }

    public String[] getValueNames() {
        return binding.keySet().toArray(new String[binding.keySet().size()]);
    }

    public Certificate[] getPeerCertificates()
            throws SSLPeerUnverifiedException {
        long x509;
        WolfSSLX509 cert;

        if (ssl == null) {
            throw new SSLPeerUnverifiedException("handshake not complete");
        }

        try {
            x509 = this.ssl.getPeerCertificate();
        } catch (IllegalStateException | WolfSSLJNIException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
            return null;
        }

        /* if no peer cert, throw SSLPeerUnverifiedException */
        if (x509 == 0) {
            throw new SSLPeerUnverifiedException("No peer certificate");
        }

        try {
            cert = new WolfSSLX509(x509);
        } catch (WolfSSLException ex) {
            throw new SSLPeerUnverifiedException("Error creating certificate");
        }

        return new Certificate[] { cert };
    }

    @Override
    public Certificate[] getLocalCertificates() {
        X509KeyManager km = authStore.getX509KeyManager();
        return km.getCertificateChain(authStore.getCertAlias());
    }

    @Override
    public X509Certificate[] getPeerCertificateChain()
        throws SSLPeerUnverifiedException {
        WolfSSLX509X x509;

        if (ssl == null) {
            throw new SSLPeerUnverifiedException("handshake not done");
        }

        try {
            x509 = new WolfSSLX509X(this.ssl.getPeerCertificate());
            return new X509Certificate[]{ (X509Certificate)x509 };
        } catch (IllegalStateException | WolfSSLJNIException |
                WolfSSLException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        if (ssl == null) {
            throw new SSLPeerUnverifiedException("handshake not done");
        }

        try {
            WolfSSLX509 x509 = new WolfSSLX509(this.ssl.getPeerCertificate());
            return x509.getSubjectDN();
        } catch (IllegalStateException | WolfSSLJNIException |
                WolfSSLException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public Principal getLocalPrincipal() {
        int i;

        X509KeyManager km = authStore.getX509KeyManager();
        java.security.cert.X509Certificate[] certs =
                km.getCertificateChain(authStore.getCertAlias());

        if (certs == null) {
            return null;
        }

        for (i = 0; i < certs.length; i++) {
            if (certs[i].getBasicConstraints() < 0) {
                /* is not a CA treat as end of chain */
                return certs[i].getSubjectDN();
            }
        }
        return null;
    }

    @Override
    public String getCipherSuite() {
        if (ssl == null) {
            return this.nullCipher;
        }

        try {
            return this.ssl.cipherGetName();
        } catch (IllegalStateException | WolfSSLJNIException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Return the cipher suite from the native WOLFSSL_SESSION structure.
     *
     * @return String representation of the cipher suite from the native
     *         WOLFSSL_SESSION structure, or NULL if not able to be
     *         retrieved.
     */
    public synchronized String getSessionCipherSuite() {
        synchronized (sesPtrLock) {
            return WolfSSLSession.sessionGetCipherName(this.sesPtr);
        }
    }

    @Override
    public String getProtocol() {
           return this.protocol;
    }

    @Override
    public String getPeerHost() {
        return this.host;
    }

    @Override
    public int getPeerPort() {
        return this.port;
    }

    @Override
    public int getPacketBufferSize() {
        return 16394; /* 2^14, max size by standard, enum MAX_RECORD_SIZE */
    }

    @Override
    public int getApplicationBufferSize() {
        /* 16394 - (38 + 64)
         * max added to msg, mac + pad  from RECORD_HEADER_SZ + BLOCK_SZ (pad) +
         * Max digest sz + BLOC_SZ (iv) + pad byte (1)
         */
        return 16292;
    }


    /**
     * Takes in a new WOLFSSL object and sets the stored session
     * @param in WOLFSSL session to set resume in
     */
    protected void resume(WolfSSLSession in) {
        ssl = in;
        ssl.setSession(this.sesPtr);
    }


    /**
     * Should be called on shutdown or after handshake has completed to save
     * the session pointer.
     */
    protected synchronized void setResume() {

        long tmpSesPtr = 0;

        if (ssl != null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "entered setResume(), trying to get sesPtrLock");

            synchronized (sesPtrLock) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "got sesPtrLock: this.sesPtr = " + this.sesPtr);

                /* Only free existing WOLFSSL_SESSION pointer if this
                 * object is in the WolfSSLAuthStore cache table (store),
                 * or it is NOT in the store but has been updated after it
                 * was pulled out of the store. The original WOLFSSL_SESSION
                 * pointer is freed when that original object is garbage
                 * collected during finalization or manually freed */
                if (this.sesPtr != 0) {
                    if (this.isInTable ||
                        (!this.isInTable && this.sesPtrUpdatedAfterTable)) {

                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                           "calling WolfSSLSession.freeSession(this.sesPtr)");

                        WolfSSLSession.freeSession(this.sesPtr);
                        /* reset this.sesPtr to 0 in case ssl.getSession() below
                         * blocks on WOLFSSL lock */
                        this.sesPtr = 0;
                    }
                }
            }

            /* Get new WOLFSSL_SESSION pointer for updated WOLFSSL locally
             * instead inside of sesPtrLock to minimize blocking time inside
             * that lock, then set class variable next inside lock once
             * value has been retrieved. */
            tmpSesPtr = ssl.getSession();
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "called ssl.getSession(), new this.sesPtr = " +
                tmpSesPtr);

            synchronized (sesPtrLock) {
                this.sesPtr = tmpSesPtr;

                if (this.sesPtr != 0) {
                    this.valid = true;
                }

                /* If this object is not in the WolfSSLAuthStore store,
                 * mark that we have updated the sesPtr in order to
                 * correctly free later on */
                if (!this.isInTable) {
                    this.sesPtrUpdatedAfterTable = true;
                }
            }

            /* Update cached values in this SSLSession from WolfSSLSession,
             * in case that goes out of scope and is garbage collected. */
            updateStoredSessionValues();
        }
    }

    protected synchronized void updateStoredSessionValues() {

        try {
            this.protocol = this.ssl.getVersion();
        } catch (IllegalStateException | WolfSSLJNIException ex) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "Not able to update stored WOLFSSL protocol");
        }
    }

    /**
     * Sets the native WOLFSSL_SESSION timeout
     * @param in timeout in seconds
     */
    protected void setNativeTimeout(long in) {
        ssl.setSessTimeout(in);
    }
}
