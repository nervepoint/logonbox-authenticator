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
	void testNullString() throws IOException {
		var w = new ByteArrayWriter();
		w.writeString(null);
		assertArrayEquals(new byte[] { (byte) 0, (byte) 0, (byte) 0, (byte) 0 }, w.toByteArray());
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
	void testBool() throws IOException {
		var w = new ByteArrayWriter();
		w.writeBoolean(true);
		assertArrayEquals(new byte[] { (byte) 0x1 }, w.toByteArray());
		w.writeBoolean(false);
		assertArrayEquals(new byte[] { (byte) 0x1, 0x00 }, w.toByteArray());
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
	void testMassiveInteger() throws IOException {
		var w = new ByteArrayWriter();
		w.writeBigInteger(new BigInteger(
				"4986580695048258251352289243969528543723799114324057371323608612564101467693190796478532220284311403189255873250803291602531019677110835331481798144386049284511688009328775687804730487000620487321119382781090544960120583643153599562724683545896843186364280959049341308629380720692043569110468202632021048673338887960542310457475382130231373634793736853819191982436405235215379401298185584213567077387840129057385674664071727417723315763120148348448625747824864998778650276874067046964948041454108472270884726573176720890632226924444526896411492224011080798782446878497167945815843132905198949069567082142592104355525279386692616234048604119115967592552701346081832583566701136596353331815241580453022478423878876764704414366376336598553049072822810090907768245535476110588270567353835663980833082822835527392197580869451516391575655964243632587493986489280683147080083155190055556030197814111481606633955453576346428985945179"));
		assertArrayEquals(new byte[] { (byte) 0, (byte) 0, (byte) 1, (byte) 129, (byte) 0, (byte) 219, (byte) 187,
				(byte) 194, (byte) 33, (byte) 195, (byte) 140, (byte) 127, (byte) 7, (byte) 175, (byte) 149, (byte) 255,
				(byte) 85, (byte) 187, (byte) 33, (byte) 19, (byte) 91, (byte) 211, (byte) 199, (byte) 5, (byte) 237,
				(byte) 90, (byte) 0, (byte) 155, (byte) 254, (byte) 36, (byte) 119, (byte) 8, (byte) 188, (byte) 150,
				(byte) 217, (byte) 238, (byte) 237, (byte) 90, (byte) 223, (byte) 43, (byte) 21, (byte) 237, (byte) 235,
				(byte) 55, (byte) 138, (byte) 131, (byte) 252, (byte) 118, (byte) 236, (byte) 201, (byte) 9, (byte) 163,
				(byte) 47, (byte) 30, (byte) 139, (byte) 78, (byte) 117, (byte) 127, (byte) 191, (byte) 123, (byte) 137,
				(byte) 169, (byte) 168, (byte) 62, (byte) 179, (byte) 79, (byte) 118, (byte) 184, (byte) 119, (byte) 19,
				(byte) 169, (byte) 223, (byte) 68, (byte) 154, (byte) 25, (byte) 117, (byte) 175, (byte) 114,
				(byte) 110, (byte) 170, (byte) 14, (byte) 20, (byte) 92, (byte) 110, (byte) 158, (byte) 73, (byte) 57,
				(byte) 123, (byte) 52, (byte) 245, (byte) 87, (byte) 240, (byte) 34, (byte) 231, (byte) 184, (byte) 153,
				(byte) 186, (byte) 114, (byte) 242, (byte) 99, (byte) 25, (byte) 131, (byte) 37, (byte) 240, (byte) 29,
				(byte) 207, (byte) 117, (byte) 37, (byte) 242, (byte) 52, (byte) 219, (byte) 49, (byte) 88, (byte) 208,
				(byte) 186, (byte) 193, (byte) 85, (byte) 242, (byte) 176, (byte) 154, (byte) 112, (byte) 176,
				(byte) 81, (byte) 107, (byte) 219, (byte) 126, (byte) 133, (byte) 206, (byte) 92, (byte) 18, (byte) 178,
				(byte) 156, (byte) 177, (byte) 26, (byte) 152, (byte) 189, (byte) 81, (byte) 41, (byte) 30, (byte) 226,
				(byte) 88, (byte) 70, (byte) 123, (byte) 0, (byte) 164, (byte) 176, (byte) 105, (byte) 91, (byte) 166,
				(byte) 221, (byte) 169, (byte) 159, (byte) 163, (byte) 94, (byte) 40, (byte) 145, (byte) 123, (byte) 94,
				(byte) 202, (byte) 91, (byte) 246, (byte) 150, (byte) 171, (byte) 157, (byte) 244, (byte) 102,
				(byte) 86, (byte) 236, (byte) 54, (byte) 28, (byte) 141, (byte) 210, (byte) 49, (byte) 218, (byte) 149,
				(byte) 106, (byte) 78, (byte) 196, (byte) 232, (byte) 174, (byte) 20, (byte) 66, (byte) 213, (byte) 176,
				(byte) 239, (byte) 147, (byte) 80, (byte) 102, (byte) 232, (byte) 173, (byte) 142, (byte) 48,
				(byte) 122, (byte) 76, (byte) 161, (byte) 193, (byte) 238, (byte) 64, (byte) 90, (byte) 45, (byte) 189,
				(byte) 182, (byte) 162, (byte) 163, (byte) 218, (byte) 158, (byte) 187, (byte) 2, (byte) 145, (byte) 84,
				(byte) 14, (byte) 254, (byte) 177, (byte) 241, (byte) 142, (byte) 245, (byte) 165, (byte) 130,
				(byte) 241, (byte) 124, (byte) 94, (byte) 23, (byte) 172, (byte) 48, (byte) 252, (byte) 201, (byte) 209,
				(byte) 160, (byte) 21, (byte) 17, (byte) 18, (byte) 222, (byte) 198, (byte) 190, (byte) 34, (byte) 136,
				(byte) 26, (byte) 78, (byte) 163, (byte) 127, (byte) 61, (byte) 152, (byte) 31, (byte) 106, (byte) 98,
				(byte) 144, (byte) 251, (byte) 112, (byte) 205, (byte) 91, (byte) 244, (byte) 138, (byte) 167,
				(byte) 23, (byte) 92, (byte) 210, (byte) 60, (byte) 229, (byte) 6, (byte) 213, (byte) 244, (byte) 87,
				(byte) 225, (byte) 55, (byte) 171, (byte) 143, (byte) 90, (byte) 234, (byte) 223, (byte) 36, (byte) 247,
				(byte) 110, (byte) 251, (byte) 98, (byte) 121, (byte) 3, (byte) 145, (byte) 52, (byte) 133, (byte) 81,
				(byte) 128, (byte) 148, (byte) 122, (byte) 147, (byte) 215, (byte) 231, (byte) 226, (byte) 163,
				(byte) 179, (byte) 133, (byte) 244, (byte) 249, (byte) 209, (byte) 83, (byte) 56, (byte) 88, (byte) 78,
				(byte) 245, (byte) 243, (byte) 130, (byte) 155, (byte) 181, (byte) 131, (byte) 57, (byte) 235,
				(byte) 22, (byte) 233, (byte) 67, (byte) 205, (byte) 208, (byte) 210, (byte) 41, (byte) 157, (byte) 208,
				(byte) 212, (byte) 73, (byte) 142, (byte) 122, (byte) 231, (byte) 128, (byte) 124, (byte) 170,
				(byte) 172, (byte) 214, (byte) 231, (byte) 191, (byte) 205, (byte) 195, (byte) 176, (byte) 16,
				(byte) 57, (byte) 92, (byte) 51, (byte) 74, (byte) 250, (byte) 171, (byte) 132, (byte) 254, (byte) 178,
				(byte) 37, (byte) 46, (byte) 234, (byte) 47, (byte) 107, (byte) 153, (byte) 242, (byte) 179, (byte) 120,
				(byte) 82, (byte) 184, (byte) 195, (byte) 224, (byte) 134, (byte) 61, (byte) 79, (byte) 116, (byte) 34,
				(byte) 173, (byte) 153, (byte) 170, (byte) 221, (byte) 144, (byte) 64, (byte) 120, (byte) 43,
				(byte) 128, (byte) 117, (byte) 158, (byte) 62, (byte) 153, (byte) 195, (byte) 224, (byte) 114,
				(byte) 254, (byte) 30, (byte) 161, (byte) 112, (byte) 80, (byte) 168, (byte) 103, (byte) 2, (byte) 215,
				(byte) 130, (byte) 120, (byte) 171, (byte) 67, (byte) 25, (byte) 172, (byte) 91 }, w.toByteArray());
	}

	@Test
	void testSigRsa() throws IOException {
		var w = new ByteArrayWriter();
		w.writeString("ssh-rsa");
		w.writeBigInteger(new BigInteger("65537"));
		w.writeBigInteger(new BigInteger(
				"4986580695048258251352289243969528543723799114324057371323608612564101467693190796478532220284311403189255873250803291602531019677110835331481798144386049284511688009328775687804730487000620487321119382781090544960120583643153599562724683545896843186364280959049341308629380720692043569110468202632021048673338887960542310457475382130231373634793736853819191982436405235215379401298185584213567077387840129057385674664071727417723315763120148348448625747824864998778650276874067046964948041454108472270884726573176720890632226924444526896411492224011080798782446878497167945815843132905198949069567082142592104355525279386692616234048604119115967592552701346081832583566701136596353331815241580453022478423878876764704414366376336598553049072822810090907768245535476110588270567353835663980833082822835527392197580869451516391575655964243632587493986489280683147080083155190055556030197814111481606633955453576346428985945179"));

		assertArrayEquals(new byte[] { 0, (byte) 0, (byte) 0, (byte) 7, (byte) 115, (byte) 115, (byte) 104, (byte) 45,
				(byte) 114, (byte) 115, (byte) 97, (byte) 0, (byte) 0, (byte) 0, (byte) 3, (byte) 1, (byte) 0, (byte) 1,
				(byte) 0, (byte) 0, (byte) 1, (byte) 129, (byte) 0, (byte) 219, (byte) 187, (byte) 194, (byte) 33,
				(byte) 195, (byte) 140, (byte) 127, (byte) 7, (byte) 175, (byte) 149, (byte) 255, (byte) 85, (byte) 187,
				(byte) 33, (byte) 19, (byte) 91, (byte) 211, (byte) 199, (byte) 5, (byte) 237, (byte) 90, (byte) 0,
				(byte) 155, (byte) 254, (byte) 36, (byte) 119, (byte) 8, (byte) 188, (byte) 150, (byte) 217, (byte) 238,
				(byte) 237, (byte) 90, (byte) 223, (byte) 43, (byte) 21, (byte) 237, (byte) 235, (byte) 55, (byte) 138,
				(byte) 131, (byte) 252, (byte) 118, (byte) 236, (byte) 201, (byte) 9, (byte) 163, (byte) 47, (byte) 30,
				(byte) 139, (byte) 78, (byte) 117, (byte) 127, (byte) 191, (byte) 123, (byte) 137, (byte) 169,
				(byte) 168, (byte) 62, (byte) 179, (byte) 79, (byte) 118, (byte) 184, (byte) 119, (byte) 19, (byte) 169,
				(byte) 223, (byte) 68, (byte) 154, (byte) 25, (byte) 117, (byte) 175, (byte) 114, (byte) 110,
				(byte) 170, (byte) 14, (byte) 20, (byte) 92, (byte) 110, (byte) 158, (byte) 73, (byte) 57, (byte) 123,
				(byte) 52, (byte) 245, (byte) 87, (byte) 240, (byte) 34, (byte) 231, (byte) 184, (byte) 153, (byte) 186,
				(byte) 114, (byte) 242, (byte) 99, (byte) 25, (byte) 131, (byte) 37, (byte) 240, (byte) 29, (byte) 207,
				(byte) 117, (byte) 37, (byte) 242, (byte) 52, (byte) 219, (byte) 49, (byte) 88, (byte) 208, (byte) 186,
				(byte) 193, (byte) 85, (byte) 242, (byte) 176, (byte) 154, (byte) 112, (byte) 176, (byte) 81,
				(byte) 107, (byte) 219, (byte) 126, (byte) 133, (byte) 206, (byte) 92, (byte) 18, (byte) 178,
				(byte) 156, (byte) 177, (byte) 26, (byte) 152, (byte) 189, (byte) 81, (byte) 41, (byte) 30, (byte) 226,
				(byte) 88, (byte) 70, (byte) 123, (byte) 0, (byte) 164, (byte) 176, (byte) 105, (byte) 91, (byte) 166,
				(byte) 221, (byte) 169, (byte) 159, (byte) 163, (byte) 94, (byte) 40, (byte) 145, (byte) 123, (byte) 94,
				(byte) 202, (byte) 91, (byte) 246, (byte) 150, (byte) 171, (byte) 157, (byte) 244, (byte) 102,
				(byte) 86, (byte) 236, (byte) 54, (byte) 28, (byte) 141, (byte) 210, (byte) 49, (byte) 218, (byte) 149,
				(byte) 106, (byte) 78, (byte) 196, (byte) 232, (byte) 174, (byte) 20, (byte) 66, (byte) 213, (byte) 176,
				(byte) 239, (byte) 147, (byte) 80, (byte) 102, (byte) 232, (byte) 173, (byte) 142, (byte) 48,
				(byte) 122, (byte) 76, (byte) 161, (byte) 193, (byte) 238, (byte) 64, (byte) 90, (byte) 45, (byte) 189,
				(byte) 182, (byte) 162, (byte) 163, (byte) 218, (byte) 158, (byte) 187, (byte) 2, (byte) 145, (byte) 84,
				(byte) 14, (byte) 254, (byte) 177, (byte) 241, (byte) 142, (byte) 245, (byte) 165, (byte) 130,
				(byte) 241, (byte) 124, (byte) 94, (byte) 23, (byte) 172, (byte) 48, (byte) 252, (byte) 201, (byte) 209,
				(byte) 160, (byte) 21, (byte) 17, (byte) 18, (byte) 222, (byte) 198, (byte) 190, (byte) 34, (byte) 136,
				(byte) 26, (byte) 78, (byte) 163, (byte) 127, (byte) 61, (byte) 152, (byte) 31, (byte) 106, (byte) 98,
				(byte) 144, (byte) 251, (byte) 112, (byte) 205, (byte) 91, (byte) 244, (byte) 138, (byte) 167,
				(byte) 23, (byte) 92, (byte) 210, (byte) 60, (byte) 229, (byte) 6, (byte) 213, (byte) 244, (byte) 87,
				(byte) 225, (byte) 55, (byte) 171, (byte) 143, (byte) 90, (byte) 234, (byte) 223, (byte) 36, (byte) 247,
				(byte) 110, (byte) 251, (byte) 98, (byte) 121, (byte) 3, (byte) 145, (byte) 52, (byte) 133, (byte) 81,
				(byte) 128, (byte) 148, (byte) 122, (byte) 147, (byte) 215, (byte) 231, (byte) 226, (byte) 163,
				(byte) 179, (byte) 133, (byte) 244, (byte) 249, (byte) 209, (byte) 83, (byte) 56, (byte) 88, (byte) 78,
				(byte) 245, (byte) 243, (byte) 130, (byte) 155, (byte) 181, (byte) 131, (byte) 57, (byte) 235,
				(byte) 22, (byte) 233, (byte) 67, (byte) 205, (byte) 208, (byte) 210, (byte) 41, (byte) 157, (byte) 208,
				(byte) 212, (byte) 73, (byte) 142, (byte) 122, (byte) 231, (byte) 128, (byte) 124, (byte) 170,
				(byte) 172, (byte) 214, (byte) 231, (byte) 191, (byte) 205, (byte) 195, (byte) 176, (byte) 16,
				(byte) 57, (byte) 92, (byte) 51, (byte) 74, (byte) 250, (byte) 171, (byte) 132, (byte) 254, (byte) 178,
				(byte) 37, (byte) 46, (byte) 234, (byte) 47, (byte) 107, (byte) 153, (byte) 242, (byte) 179, (byte) 120,
				(byte) 82, (byte) 184, (byte) 195, (byte) 224, (byte) 134, (byte) 61, (byte) 79, (byte) 116, (byte) 34,
				(byte) 173, (byte) 153, (byte) 170, (byte) 221, (byte) 144, (byte) 64, (byte) 120, (byte) 43,
				(byte) 128, (byte) 117, (byte) 158, (byte) 62, (byte) 153, (byte) 195, (byte) 224, (byte) 114,
				(byte) 254, (byte) 30, (byte) 161, (byte) 112, (byte) 80, (byte) 168, (byte) 103, (byte) 2, (byte) 215,
				(byte) 130, (byte) 120, (byte) 171, (byte) 67, (byte) 25, (byte) 172, (byte) 91 }, w.toByteArray());

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
