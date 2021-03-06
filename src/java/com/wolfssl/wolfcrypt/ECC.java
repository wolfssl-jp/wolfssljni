/* ECC.java
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

package com.wolfssl.wolfcrypt;

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt ECC implementation, used for examples.
 * This class contains a subset of the WolfCrypt ECC implementation and was
 * written to be used with this package's example ECC public key callbacks.
 * Usage can be found in examples/Client.java and examples/Server.java.
 *
 * @author  wolfSSL
 * @version 1.0, August 2013
 */
public class ECC {

    public native int doVerify(ByteBuffer sig, long sigSz, ByteBuffer hash,
            long hashLen, ByteBuffer keyDer, long keySz, int[] result);

    public native int doSign(ByteBuffer in, long inSz, ByteBuffer out,
            long[] outSz, ByteBuffer key, long keySz);

}

