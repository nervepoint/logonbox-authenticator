package com.logonbox.authenticator;

/*
 * #%L
 * LogonBox Authenticator API
 * %%
 * Copyright (C) 2022 LogonBox Limited
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

class ByteArrayReader extends ByteArrayInputStream {

	ByteArrayReader(byte[] data) {
		super(data);
	}

	private void checkLength(long len) throws IOException {
		if (len > available()) {
			throw new IOException(String.format("Unexpected length of %d bytes exceeds available data of %d bytes", len,
					available()));
		}
	}

	public long readInt() throws IOException {
		checkLength(4);
		int ch1 = read();
		int ch2 = read();
		int ch3 = read();
		int ch4 = read();
		return ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4 << 0)) & 0xFFFFFFFFL;
	}

	public String readString() throws IOException {
		int len = (int) readInt();
		checkLength(len);
		var tmp = new byte[len];
		read(tmp);
		return new String(tmp, "UTF-8");
	}

	public BigInteger readBigInteger() throws IOException {
		int len = (int) readInt();
		checkLength(len);
		var tmp = new byte[len];
		read(tmp);
		return new BigInteger(tmp);
	}

	public byte[] readBinaryString() throws IOException {
		int len = (int) readInt();
		checkLength(len);
		var tmp = new byte[len];
		read(tmp);
		return tmp;

	}

	public boolean readBoolean() throws IOException {
		checkLength(1);
		return read() == 1;
	}
}