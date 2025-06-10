/* ThreadedSSLSocketClientServer.java
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

/**
 * SSLSocket example that connects a client thread to a server thread.
 *
 * This example creates two threads, one server and one client. The examples
 * are set up to use the SSLSocket and SSLServerSocket classes. They make
 * one connection (handshake) and shut down.
 *
 * Example usage:
 *
 * $ ./examples/provider/ThreadedSSLSocketClientServer.sh
 */

import java.util.*;
import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

import com.wolfssl.WolfSSL;
import com.wolfssl.provider.jsse.WolfSSLProvider;

public class ThreadedSSLSocketClientServer
{
    String tmfImpl = "SunX509";     /* TrustManagerFactory provider */
    String kmfImpl = "SunX509";     /* KeyManagerFactory provider */
    String ctxImpl = "wolfJSSE";    /* SSLContext provider */
    int srvPort = 443;            /* server port */
    static int numLoop;
    static String host = null;
    static int port;
    static int tlsv;
    static int iIllegalStateException = 0;        /*  */
    class ServerThread extends Thread
    {
        private String keyStorePath;
        private String trustStorePath;
        private char[] ksPass;
        private char[] tsPass;


        public ServerThread(String keyStorePath, String keyStorePass,
            String trustStorePath, String trustStorePass) {

            this.keyStorePath = keyStorePath;
            this.trustStorePath = trustStorePath;
            this.ksPass = keyStorePass.toCharArray();
            this.tsPass = trustStorePass.toCharArray();
        }

        public void run() {

            try {

                KeyStore pKey = KeyStore.getInstance("JKS");
                pKey.load(new FileInputStream(keyStorePath), ksPass);
                KeyStore cert = KeyStore.getInstance("JKS");
                cert.load(new FileInputStream(trustStorePath), tsPass);

                TrustManagerFactory tm = TrustManagerFactory.getInstance(tmfImpl, "wolfJSSE");
                tm.init(cert);

                KeyManagerFactory km = KeyManagerFactory.getInstance(kmfImpl, "wolfJSSE");
                km.init(pKey, ksPass);

                SSLContext ctx = SSLContext.getInstance("TLS", ctxImpl);
                ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

                SSLServerSocket ss = (SSLServerSocket)ctx
                    .getServerSocketFactory().createServerSocket(srvPort);

                SSLSocket sock = (SSLSocket)ss.accept();
                sock.startHandshake();
                sock.close();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    class ClientThread extends Thread
    {
        private String keyStorePath;
        private String trustStorePath;
        private char[] ksPass;
        private char[] tsPass;
        private int ID;
        private boolean clientFlag;
        private SSLSocket socket = null;

        private List<String> getSubjectAltNames(X509Certificate certificate, int type) {
            List<String> result = new ArrayList();
            try {
              Collection<?> subjectAltNames = certificate.getSubjectAlternativeNames();
              if (subjectAltNames == null) {
                return Collections.emptyList();
              }
              for (Object subjectAltName : subjectAltNames) {
                List<?> entry = (List<?>) subjectAltName;
                if (entry == null || entry.size() < 2) {
                  continue;
                }
                Integer altNameType = (Integer) entry.get(0);
                if (altNameType == null) {
                  continue;
                }
                if (altNameType == type) {
                  String altName = (String) entry.get(1);
                  if (altName != null) {
                    result.add(altName);
                  }
                }
              }
              return result;
            } catch (Exception e) {
              return Collections.emptyList();
            }
        }

        private void showPeer(int ID, SSLSocket sock, Boolean getAlt, Boolean showCert) {
            SSLSession session = sock.getSession();

            if (session != null)
            {
                System.out.println("SSL version is ID(" + ID + ") " + session.getProtocol());
                System.out.println("SSL cipher suite is ID(" + ID + ") " + session.getCipherSuite());
            } else {
                try {
                    throw new Exception("Session object is NULL!!!!");
                }
                catch (Exception e) {
                    e.printStackTrace();
                }
            }

            try {
                Certificate[] certs = session.getPeerCertificates();
                Certificate[] certs1 = session.getPeerCertificates();
                if (certs != null && certs.length > 0 && showCert) {
                    System.out.println(((X509Certificate)certs[0]).toString());
                }
                else if(certs == null)
                {
                    throw new Exception("Certs are NULL!!!!");
                }
                if (certs1 != null && certs1.length > 0 && showCert) {
                    System.out.println(((X509Certificate)certs1[0]).toString());
                }
                else if(certs1 == null)
                {
                    throw new Exception("Certs1 are NULL!!!!");
                }
                if(getAlt) {
                    X509Certificate cert = (X509Certificate)certs[0];
                    List<String> altNames1 = getSubjectAltNames(cert, 2);
                    boolean hasDns = false;
                    if (altNames1.size() == 0) {
                        throw new Exception("alt Name size is zero!!!!!!!!");
                    }
                }

            } catch (Exception e) {
                long threadId = Thread.currentThread().getId();
                System.out.println("Thread # " + threadId);
                System.out.println("ID(" + ID + ") has an exception.");
                e.printStackTrace();
            }
        }

        public ClientThread(int id, String keyStorePath, String keyStorePass,
            String trustStorePath, String trustStorePass, SSLSocket socket) {

            this.ID = id;
            this.keyStorePath = keyStorePath;
            this.trustStorePath = trustStorePath;
            this.ksPass = keyStorePass.toCharArray();
            this.tsPass = trustStorePass.toCharArray();
            this.socket = socket;
            this.clientFlag = false;

            HandshakeCompletedListener clientListener =
            new HandshakeCompletedListener() {
                @Override
                public void handshakeCompleted(HandshakeCompletedEvent event) {
                    /* toggle client flag */
                    clientFlag = true;
                }
            };

            this.socket.addHandshakeCompletedListener(clientListener);
        }

        public ClientThread(int id, SSLContext ctx, String keyStorePath, String keyStorePass,
            String trustStorePath, String trustStorePass) {

            this.ID = id;
            this.keyStorePath = keyStorePath;
            this.trustStorePath = trustStorePath;
            this.ksPass = keyStorePass.toCharArray();
            this.tsPass = trustStorePass.toCharArray();
            /* */
            try {
                this.socket =
                     (SSLSocket)ctx.getSocketFactory().createSocket(host, port);
            }
            catch(Exception e){
                e.printStackTrace();
            }

            this.clientFlag = false;

            HandshakeCompletedListener clientListener =
            new HandshakeCompletedListener() {
                @Override
                public void handshakeCompleted(HandshakeCompletedEvent event) {
                    /* toggle client flag */
                    clientFlag = true;
                }
            };

            this.socket.addHandshakeCompletedListener(clientListener);
        }

        public void run() {
            try {
                int rnd = (int)Math.ceil(Math.random() * 10);
                /* random wait 0-9 second */
                if(ID != 0) {
                    Thread.sleep(rnd*100);
                }
                socket.setNeedClientAuth(false);
                socket.startHandshake();

                rnd = (int)Math.ceil(Math.random() * 10);
                if (ID != 0) {
                    Thread.sleep(rnd*100);
                    if (clientFlag  == true) {
                        //System.out.println("ID " + ID + " clientFlag is true. HandShake is done");
                        showPeer(ID, socket, true, false);
                    }
                    else
                    {
                        System.out.println("clientFlag is still false.!!! something wrong");
                    }
                }

                socket.close();
                socket = null;
                if (iIllegalStateException == 1) {
                    System.gc();
                }
            } catch (Exception e) {
                System.out.println("ID(" + ID + ") has an exception.");
                e.printStackTrace();
            }
        }
    }/* Client class */

    public ThreadedSSLSocketClientServer(String[] args) {

        Security.addProvider(new WolfSSLProvider());

        String serverKS = "./examples/provider/server.jks";
        String serverTS = "./examples/provider/client.jks";
        String clientKS = "./examples/provider/client.jks";
        String clientTS = "./examples/provider/client.jks";
        String pass = "wolfSSL test";
    }

    public ThreadedSSLSocketClientServer(String[] args, int clientOnly) {

        int i = 0;
        int k = 0;
        int numOfObjects = 10;
        KeyStore pKey;
        KeyManagerFactory km = null;
        TrustManagerFactory tm = null;
        KeyStore cert = null;
        SSLContext ctx = null;
        Security.addProvider(new WolfSSLProvider());

        String clientKS = "./examples/provider/client.jks";
        String clientTS = "./examples/provider/client.jks";
        String pass = "wolfSSL test";
        SSLSocket[] sockets = new SSLSocket[numOfObjects];
        ClientThread[] clients = new ClientThread[numOfObjects];

        i = 0;
        System.out.println("Number of Loop :" + numLoop);
        while(i < numLoop) {
            try {
            pKey = KeyStore.getInstance("JKS");
            pKey.load(new FileInputStream(clientKS), pass.toCharArray());
            cert = KeyStore.getInstance("JKS");
            cert.load(new FileInputStream(clientTS), pass.toCharArray());

            tm = TrustManagerFactory.getInstance(tmfImpl, "wolfJSSE");
            tm.init(cert);

            km = KeyManagerFactory.getInstance(kmfImpl, "wolfJSSE");
            km.init(pKey, pass.toCharArray());

            if (tlsv == 0)
                ctx = SSLContext.getInstance("TLSv1.2", ctxImpl);
            else
                ctx = SSLContext.getInstance("TLS", ctxImpl);

            ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

            }
            catch (Exception e) {
                e.printStackTrace();
            }

            for (k = 0; k < numOfObjects; k++) {
                if(iIllegalStateException == 0) {
                        for (k=0;k < numOfObjects; k++) {
                        try {
                            if (ctx != null)
                                sockets[k] = (SSLSocket)ctx.getSocketFactory().createSocket(host, port);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        clients[k] = new ClientThread(k, clientKS, pass, clientTS, pass, sockets[k]);
                    }
                } else {
                    clients[k] = new ClientThread(k, ctx, clientKS, pass, clientTS, pass);
                }
            }
            /* !!!!! */
            for (k = 0; k < numOfObjects; k++) {
                clients[k].start();
            }

            try {
                System.out.println(i + " start clients to connect host " +
                    host + " port " + port);
                for (k = 0; k < numOfObjects; k++) {
                    /* VVVVV */
                    //clients[k].start();
                    clients[k].join();
                }

                /* wait 1 second */
                Thread.sleep(100);
            }
            catch(InterruptedException e){
                e.printStackTrace();
            }

            i++;
        }

        if (ctx != null){
            ctx = null;
        }
    }

    static void parseArgsAndPasswords(String[] args) {
            host = args[0];
            port = Integer.parseInt(args[1]);
            tlsv = Integer.parseInt(args[2]);
            if (args.length > 3)
                numLoop = Integer.parseInt(args[3]);
            else
                numLoop = 20;

            iIllegalStateException = Integer.parseInt(args[4]);
            if (iIllegalStateException < 0 ||
                iIllegalStateException > 1) {
                System.out.println("forcegc must be 0 or 1");
                System.exit(1);
            }
    }
    public static void main(String[] args) {
        //
        try{
        Thread.sleep(1000*1*1);// wait 1 s
        } catch(InterruptedException e){
            e.printStackTrace();
        }
        parseArgsAndPasswords(args);
        ThreadedSSLSocketClientServer tst = new ThreadedSSLSocketClientServer(args, 1);
        tst = null;

        /* force call GC */
        Runtime r = Runtime.getRuntime();
        r.gc();

        try {
            Thread.sleep(1000);// wait 1 s
        } catch(InterruptedException e){
                e.printStackTrace();
        }

        /* force call GC */
        r.gc();

        try {
            Thread.sleep(1000);// wait 3 min
        } catch(InterruptedException e){
                e.printStackTrace();
        }

        WolfSSL.cleanup();

        try {
            Thread.sleep(1000);
        } catch(InterruptedException e){
                e.printStackTrace();
        }
    }

    protected void finalize() throws Throwable
    {
        super.finalize();
    }
}

