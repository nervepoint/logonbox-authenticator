package com.logonbox.authenticator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.IOException;
import java.math.BigInteger;

import org.junit.jupiter.api.Test;

public class ByteArrayWriterTest {

	@Test
	void testString() throws IOException {
		var w = new ByteArrayWriter();
		w.writeString("A Test String");
		assertArrayEquals(new byte[] { (byte) 0, (byte) 0, (byte) 0, (byte) 13, (byte) 65, (byte) 32, (byte) 84,
				(byte) 101, (byte) 115, (byte) 116, (byte) 32, (byte) 83, (byte) 116, (byte) 114, (byte) 105,
				(byte) 110, (byte) 103 }, w.toByteArray());
	}

	@Test
	void testInteger() throws IOException {
		var w = new ByteArrayWriter();
		w.writeInt(4294967295l);
		w.writeInt(0l);
		w.writeInt(255l);
		w.writeInt(4294967040l);
		assertArrayEquals(new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0, 0, 0, 0, 0, 0, 0,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0 }, w.toByteArray());
	}

	@Test
	void testBigInteger() throws IOException {
		var w = new ByteArrayWriter();
		w.writeBigInteger(new BigInteger("329802389981797891243908975290812"));
		assertArrayEquals(new byte[] { (byte) 0, (byte) 0, (byte) 0, (byte) 14, (byte) 16, (byte) 66, (byte) 176,
				(byte) 254, (byte) 247, (byte) 114, (byte) 215, (byte) 130, (byte) 240, (byte) 27, (byte) 237,
				(byte) 39, (byte) 233, (byte) 188 }, w.toByteArray());

	}

	@Test
	void testBinaryString() throws IOException {
		var w = new ByteArrayWriter();
		w.writeBinaryString(
				"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
						.getBytes("UTF-8"));
		assertArrayEquals(
				new byte[] { (byte) 0, (byte) 0, (byte) 0, (byte) 123, (byte) 76, (byte) 111, (byte) 114, (byte) 101,
						(byte) 109, (byte) 32, (byte) 105, (byte) 112, (byte) 115, (byte) 117, (byte) 109, (byte) 32,
						(byte) 100, (byte) 111, (byte) 108, (byte) 111, (byte) 114, (byte) 32, (byte) 115, (byte) 105,
						(byte) 116, (byte) 32, (byte) 97, (byte) 109, (byte) 101, (byte) 116, (byte) 44, (byte) 32,
						(byte) 99, (byte) 111, (byte) 110, (byte) 115, (byte) 101, (byte) 99, (byte) 116, (byte) 101,
						(byte) 116, (byte) 117, (byte) 114, (byte) 32, (byte) 97, (byte) 100, (byte) 105, (byte) 112,
						(byte) 105, (byte) 115, (byte) 99, (byte) 105, (byte) 110, (byte) 103, (byte) 32, (byte) 101,
						(byte) 108, (byte) 105, (byte) 116, (byte) 44, (byte) 32, (byte) 115, (byte) 101, (byte) 100,
						(byte) 32, (byte) 100, (byte) 111, (byte) 32, (byte) 101, (byte) 105, (byte) 117, (byte) 115,
						(byte) 109, (byte) 111, (byte) 100, (byte) 32, (byte) 116, (byte) 101, (byte) 109, (byte) 112,
						(byte) 111, (byte) 114, (byte) 32, (byte) 105, (byte) 110, (byte) 99, (byte) 105, (byte) 100,
						(byte) 105, (byte) 100, (byte) 117, (byte) 110, (byte) 116, (byte) 32, (byte) 117, (byte) 116,
						(byte) 32, (byte) 108, (byte) 97, (byte) 98, (byte) 111, (byte) 114, (byte) 101, (byte) 32,
						(byte) 101, (byte) 116, (byte) 32, (byte) 100, (byte) 111, (byte) 108, (byte) 111, (byte) 114,
						(byte) 101, (byte) 32, (byte) 109, (byte) 97, (byte) 103, (byte) 110, (byte) 97, (byte) 32,
						(byte) 97, (byte) 108, (byte) 105, (byte) 113, (byte) 117, (byte) 97, (byte) 46 },
				w.toByteArray());

	}
}
