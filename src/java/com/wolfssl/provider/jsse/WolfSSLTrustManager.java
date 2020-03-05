/* WolfSSLTrustManager.java
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLException;

/**
 * wolfSSL implemenation of TrustManagerFactorySpi
 *
 * @author wolfSSL
 */
public class WolfSSLTrustManager extends TrustManagerFactorySpi {
    private KeyStore store;

    @Override
    protected void engineInit(KeyStore in) throws KeyStoreException {
        KeyStore certs = in;
        if (in == null) {
            String pass = System.getProperty("javax.net.ssl.trustStorePassword");
            String file = System.getProperty("javax.net.ssl.trustStore");
            String type = System.getProperty("javax.net.ssl.trustStoreType");
            String vmVendor = System.getProperty("java.vm.vendor");
            char passAr[] = null;
            InputStream stream = null;
            boolean systemCertsFound = false;
            int aliasCnt = 0;
            String[] cafiles = null;

            try {
                if (pass != null) {
                    passAr = pass.toCharArray();
                }

                /* default to JKS KeyStore type if not set at system level */
                try {
                    if (type != null && type != "") {
                        certs = KeyStore.getInstance(type);
                    } else {
                        if (vmVendor.equals("The Android Project")) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "Detected Android VM, using BKS KeyStore type");
                            certs = KeyStore.getInstance("BKS");
                        } else {
                            certs = KeyStore.getInstance("JKS");
                        }
                    }
                } catch (KeyStoreException kse) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                        "Unsupported KeyStore type: " + type);
                    throw kse;
                }

                try {
                    /* initialize KeyStore, loading certs below will
                     * overwrite if needed, otherwise Android needs
                     * this to be initialized here */
                    certs.load(null, null);

                } catch (Exception e) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                        "Error initializing KeyStore with load(null, null)");
                    throw e;
                }

                if (file == null) {
                    /* try to load trusted system certs if possible */
                    String home = System.getenv("JAVA_HOME");
                    if (home != null) {
                        if (!home.endsWith("/") && !home.endsWith("\\")) {
                            /* add trailing slash if not there already */
                            home = home.concat("/");
                        }

                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "$JAVA_HOME = " + home);

                        /* trying: "lib/security/jssecacerts" */
                        File f = new File(home.concat(
                                            "jre/lib/security/jssecacerts"));
                        if (f.exists()) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                    "Loading certs from " +
                                    home.concat("lib/security/jssecacerts"));
                            stream = new FileInputStream(f);
                            certs.load(stream, passAr);
                            stream.close();
                            systemCertsFound = true;
                        }

                        /* trying: "lib/security/cacerts" */
                        f = new File(home.concat("jre/lib/security/cacerts"));
                        if (f.exists()) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                    "Loading certs from " +
                                    home.concat("lib/security/cacerts"));
                            stream = new FileInputStream(f);
                            certs.load(stream, passAr);
                            stream.close();
                            systemCertsFound = true;
                        }
                    }

                    /* ANDROID, detect based on ANDROID_ROOT */
                    home = System.getenv("ANDROID_ROOT");
                    if (home != null) {
                        /* try: "/system/security/cacerts/*"
                         * this is a directory of individual PEM files */

                        if (!home.endsWith("/") && !home.endsWith("\\")) {
                            /* add trailing slash if not there already */
                            home = home.concat("/");
                        }

                        String caStoreDir = home.concat("etc/security/cacerts");
                        File cadir = new File(caStoreDir);
                        try {
                            cafiles = cadir.list();
                        } catch (Exception e) {
                            /* denied access reading cacerts directory */
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                                "Permission error when trying to read " +
                                "system CA certificates");
                            throw e;
                        }
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "Found " + cafiles.length + " CA files to load " +
                            "into KeyStore");

                        /* get factory for cert creation */
                        CertificateFactory cfactory =
                            CertificateFactory.getInstance("X.509");

                        /* loop over all PEM certs */
                        for (String cafile : cafiles) {

                            WolfSSLCertificate certPem;
                            String fullCertPath = caStoreDir.concat("/");
                            fullCertPath = fullCertPath.concat(cafile);

                            try {
                                certPem = new WolfSSLCertificate(
                                    fullCertPath, WolfSSL.SSL_FILETYPE_PEM);
                            } catch (WolfSSLException we) {
                                /* skip, error parsing PEM */
                                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                    "Skipped loading cert: " + fullCertPath);
                                continue;
                            }

                            byte[] derArray = certPem.getDer();
                            certPem.free();
                            ByteArrayInputStream bis =
                                new ByteArrayInputStream(derArray);
                            Certificate tmpCert = null;

                            try {
                                tmpCert = cfactory.generateCertificate(bis);
                            } catch (CertificateException ce) {
                                WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                                    "Error generating certificate from " +
                                    "ByteArrayInputStream");
                                throw ce;
                            }

                            String aliasString = "alias" + aliasCnt;
                            try {
                                certs.setCertificateEntry(aliasString, tmpCert);
                            } catch (KeyStoreException kse) {
                                WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                                    "Error setting certificate entry in " +
                                    "KeyStore, skipping loading cert");
                                continue;
                            }

                            /* increment alias counter for unique aliases */
                            aliasCnt++;
                        }
                        systemCertsFound = true;
                    }

                    if (systemCertsFound == false) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "No trusted system certs found, " +
                                "using Anonymous cipher suite");
                    }
                }
                else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "Loading certs from " + file);
                    stream = new FileInputStream(file);
                    certs.load(stream, passAr);
                    stream.close();
                }
            } catch (FileNotFoundException ex) {
                Logger.getLogger(
                        WolfSSLTrustManager.class.getName()).log(
                            Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(
                        WolfSSLTrustManager.class.getName()).log(
                            Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(
                        WolfSSLTrustManager.class.getName()).log(
                            Level.SEVERE, null, ex);
            } catch (CertificateException ex) {
                Logger.getLogger(
                        WolfSSLTrustManager.class.getName()).log(
                            Level.SEVERE, null, ex);
            }
        }
        this.store = certs;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters arg0)
        throws InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        /* array of WolfSSLX509Trust objects to use */
        TrustManager[] tm = {new WolfSSLTrustX509(this.store)};
        return tm;
    }
}
