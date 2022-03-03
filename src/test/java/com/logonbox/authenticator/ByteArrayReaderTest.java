package com.logonbox.authenticator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.math.BigInteger;

import org.junit.jupiter.api.Test;

public class ByteArrayReaderTest {
	
	@Test
	void stringUnderflow() {
		assertThrows(IOException.class, () -> {
			new ByteArrayReader(new byte[] { (byte) 0, (byte) 0, (byte) 0, (byte) 13, (byte) 65, (byte) 32,
					(byte) 84, (byte) 101, (byte) 115, (byte) 116 }).readString();
		});
	}
	
	@Test
	void intUnderflow() {
		assertThrows(IOException.class, () -> {
			new ByteArrayReader(new byte[] { (byte) 0, (byte) 0, (byte) 0 }).readInt();
		});
	}

	@Test
	void testString() throws IOException {
		var r = new ByteArrayReader(new byte[] { (byte) 0, (byte) 0, (byte) 0, (byte) 13, (byte) 65, (byte) 32,
				(byte) 84, (byte) 101, (byte) 115, (byte) 116, (byte) 32, (byte) 83, (byte) 116, (byte) 114, (byte) 105,
				(byte) 110, (byte) 103 });
		assertEquals("A Test String", r.readString());
	}

	@Test
	void testInteger() throws IOException {
		var r = new ByteArrayReader(new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0, 0, 0, 0, 0, 0,
				0, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0 });
		assertEquals(4294967295l, r.readInt());
		assertEquals(0l, r.readInt());
		assertEquals(255l, r.readInt());
		assertEquals(4294967040l, r.readInt());
	}

	@Test
	void testBigInteger() throws IOException {
		var r = new ByteArrayReader(new byte[] { (byte) 0, (byte) 0, (byte) 0, (byte) 14, (byte) 16, (byte) 66,
				(byte) 176, (byte) 254, (byte) 247, (byte) 114, (byte) 215, (byte) 130, (byte) 240, (byte) 27,
				(byte) 237, (byte) 39, (byte) 233, (byte) 188 });
		assertEquals(new BigInteger("329802389981797891243908975290812"), r.readBigInteger());
	}

	@Test
	void testBinaryString() throws IOException {
		var r = new ByteArrayReader(new byte[] { (byte) 0, (byte) 0, (byte) 0, (byte) 123, (byte) 76, (byte) 111,
				(byte) 114, (byte) 101, (byte) 109, (byte) 32, (byte) 105, (byte) 112, (byte) 115, (byte) 117,
				(byte) 109, (byte) 32, (byte) 100, (byte) 111, (byte) 108, (byte) 111, (byte) 114, (byte) 32,
				(byte) 115, (byte) 105, (byte) 116, (byte) 32, (byte) 97, (byte) 109, (byte) 101, (byte) 116, (byte) 44,
				(byte) 32, (byte) 99, (byte) 111, (byte) 110, (byte) 115, (byte) 101, (byte) 99, (byte) 116, (byte) 101,
				(byte) 116, (byte) 117, (byte) 114, (byte) 32, (byte) 97, (byte) 100, (byte) 105, (byte) 112,
				(byte) 105, (byte) 115, (byte) 99, (byte) 105, (byte) 110, (byte) 103, (byte) 32, (byte) 101,
				(byte) 108, (byte) 105, (byte) 116, (byte) 44, (byte) 32, (byte) 115, (byte) 101, (byte) 100, (byte) 32,
				(byte) 100, (byte) 111, (byte) 32, (byte) 101, (byte) 105, (byte) 117, (byte) 115, (byte) 109,
				(byte) 111, (byte) 100, (byte) 32, (byte) 116, (byte) 101, (byte) 109, (byte) 112, (byte) 111,
				(byte) 114, (byte) 32, (byte) 105, (byte) 110, (byte) 99, (byte) 105, (byte) 100, (byte) 105,
				(byte) 100, (byte) 117, (byte) 110, (byte) 116, (byte) 32, (byte) 117, (byte) 116, (byte) 32,
				(byte) 108, (byte) 97, (byte) 98, (byte) 111, (byte) 114, (byte) 101, (byte) 32, (byte) 101, (byte) 116,
				(byte) 32, (byte) 100, (byte) 111, (byte) 108, (byte) 111, (byte) 114, (byte) 101, (byte) 32,
				(byte) 109, (byte) 97, (byte) 103, (byte) 110, (byte) 97, (byte) 32, (byte) 97, (byte) 108, (byte) 105,
				(byte) 113, (byte) 117, (byte) 97, (byte) 46 });

		assertArrayEquals(
				"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
						.getBytes("UTF-8"),
				r.readBinaryString());

	}


	@Test
	void testBoolean() throws IOException {
		var r = new ByteArrayReader(new byte[] { (byte) 0, (byte) 1 });
		assertEquals(false, r.readBoolean());		
		assertEquals(true, r.readBoolean());
	}
}
