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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public class ByteArrayWriter extends ByteArrayOutputStream {

	public void writeBigInteger(BigInteger bi) throws IOException {
		var raw = bi.toByteArray();

		writeInt(raw.length);
		write(raw);
	}

	public void writeInt(long i) throws IOException {
		var raw = new byte[4];

		raw[0] = (byte) (i >> 24);
		raw[1] = (byte) (i >> 16);
		raw[2] = (byte) (i >> 8);
		raw[3] = (byte) (i);

		write(raw);
	}

	public void writeString(String str) throws IOException {
		writeString(str, "UTF-8");
	}
	
	public void writeString(String str, String charset) throws IOException {

	    if (str == null) {
	      writeInt(0);
	    }
	    else {
	      var tmp = str.getBytes();

	      writeInt(tmp.length);
	      write(tmp);
	    }
	  }

	public void writeBinaryString(byte[] data) throws IOException {
		writeInt(data.length);
		write(data);
	}
}
