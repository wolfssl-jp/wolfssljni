#!/bin/bash

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./lib/:/usr/local/lib
# Usage
#  ./ThreadedSSLSocketClientServer.sh [host] [port] [0:TLS12, 1:TLS13] [Number of Loops] [1:Force GC for IllegalStateException Case, 0:No]
# Example:
#  ./ThreadedSSLSocketClientServer.sh 66.45.16.180 443 1 10 1
#   Connects to 60.45.16.180 by using TLS 1.3 and runs 10 loops with GC forced.
java -classpath ./lib/wolfssl.jar:./lib/wolfssl-jsse.jar:./examples/build -Dsun.boot.library.path=./lib/ ThreadedSSLSocketClientServer $@


# To run the app to against 60.45.16.180, it needs to update clinet.jks as follows:
# 1. Download the certificate from the server. e.g. using Web browser.
# 2. Import the certificate into client.jks:
# $ keytool -importcert -alias my_cert -file 604516180_Certificate_Services.crt -keystore client.jks
