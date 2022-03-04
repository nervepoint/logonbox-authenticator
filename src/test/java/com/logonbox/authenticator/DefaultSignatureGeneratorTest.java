package com.logonbox.authenticator;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;

@WireMockTest(httpsEnabled = true)
public class DefaultSignatureGeneratorTest extends AbstractHttpTest {

	@Test
	public void testFailURI() {
		var ks = new DefaultSignatureGenerator("x:", 443);
		var client = new AuthenticatorClient();
		client.enableDebug();
		var ex = assertThrows(IOException.class, () -> {
			ks.requestSignature(client, "test@test.com", "SHA256:HJmwFN7kuX0rZzPGi+4kqO2ftzQ1DAN5BwqW6B3d2AE",
					"test wants to authenticate from LogonBox Authenticator API using your localhost credentials.",
					"Authorize",
					"",
					0);
		});
		assertEquals("unsupported URI https://x::443/app/api/authenticator/signPayload", ex.getMessage());
	}
	
	@Test
	public void testConstruct1() {
		var ks = new DefaultSignatureGenerator("qwerty");
		assertEquals("qwerty", ks.getHostname());
		assertEquals(443, ks.getPort());
	}
	
	@Test
	public void testConstruct2() {
		var ks = new DefaultSignatureGenerator("qwerty", 12345);
		assertEquals("qwerty", ks.getHostname());
		assertEquals(12345, ks.getPort());
	}

	@Test
	public void testRequestSignature(WireMockRuntimeInfo wmRuntimeInfo) throws IOException {
		var mapper = new ObjectMapper();
		var root = mapper.createObjectNode();
		root.set("success", mapper.convertValue(true, JsonNode.class));
		root.set("message", mapper.convertValue("All good", JsonNode.class));
		root.set("signature",
				mapper.convertValue(
						"1eB-ogdIs4G_-KvZBNI1Gzh6tQNsHn5BsFiDUhMPr3igf2Pnnm6bwRWlUlXYFUmi4LEr1mR9Jvc_5QUA9zm_CQ==",
						JsonNode.class));
		root.set("response", mapper.convertValue(
				"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4A=",
				JsonNode.class));

		signStub(root);

		var ks = new DefaultSignatureGenerator("localhost", wmRuntimeInfo.getHttpsPort());
		var client = createClient();
		var sig = ks.requestSignature(client, "test@test.com", "SHA256:HJmwFN7kuX0rZzPGi+4kqO2ftzQ1DAN5BwqW6B3d2AE",
				"test wants to authenticate from LogonBox Authenticator API using your localhost credentials.",
				"Authorize",
				"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4A=",
				0);

		assertArrayEquals(sig, Base64.getUrlDecoder()
				.decode("1eB-ogdIs4G_-KvZBNI1Gzh6tQNsHn5BsFiDUhMPr3igf2Pnnm6bwRWlUlXYFUmi4LEr1mR9Jvc_5QUA9zm_CQ=="));
	}

	@Test
	public void testFailRequestSignature(WireMockRuntimeInfo wmRuntimeInfo) throws IOException {
		var mapper = new ObjectMapper();
		var root = mapper.createObjectNode();
		root.set("success", mapper.convertValue(false, JsonNode.class));
		root.set("message", mapper.convertValue("It's all gone a bit Pete Tong", JsonNode.class));
		root.set("signature", mapper.convertValue("XXXX", JsonNode.class));
		root.set("response", mapper.convertValue("XXXX", JsonNode.class));

		signStub(root);

		var ks = new DefaultSignatureGenerator("localhost", wmRuntimeInfo.getHttpsPort());
		var client = createClient();
		var ex = assertThrows(IOException.class, () -> {
			ks.requestSignature(client, "test@test.com", "SHA256:HJmwFN7kuX0rZzPGi+4kqO2ftzQ1DAN5BwqW6B3d2AE",
					"test wants to authenticate from LogonBox Authenticator API using your localhost credentials.",
					"Authorize",
					"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4A=",
					0);
		});
		assertEquals("It's all gone a bit Pete Tong", ex.getMessage());
	}

	@Test
	public void testFailRequestSignatureSignatureError(WireMockRuntimeInfo wmRuntimeInfo) throws IOException {
		var mapper = new ObjectMapper();
		var root = mapper.createObjectNode();
		root.set("success", mapper.convertValue(true, JsonNode.class));
		root.set("message", mapper.convertValue("XXXXXX", JsonNode.class));
		root.set("signature", mapper.convertValue("", JsonNode.class));
		var baw = new ByteArrayWriter();
		baw.writeBoolean(false);
		baw.writeString("It's all gone a bit Pete Tong");
		var bb = baw.toByteArray();
		root.set("response", mapper.convertValue(Base64.getUrlEncoder().encodeToString(bb), JsonNode.class));

		signStub(root);

		var ks = new DefaultSignatureGenerator("localhost", wmRuntimeInfo.getHttpsPort());
		var client = new AuthenticatorClient();
		client.enableDebug();
		var ex = assertThrows(IOException.class, () -> {
			ks.requestSignature(client, "test@test.com", "SHA256:HJmwFN7kuX0rZzPGi+4kqO2ftzQ1DAN5BwqW6B3d2AE",
					"test wants to authenticate from LogonBox Authenticator API using your localhost credentials.",
					"Authorize",
					"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4A=",
					0);
		});
		assertEquals("It's all gone a bit Pete Tong", ex.getMessage());
	}

	protected void signStub(ObjectNode root) {
		stubFor(post(urlEqualTo("/app/api/authenticator/signPayload"))
				.willReturn(aResponse().withHeader("Content-Type", "text/json").withJsonBody(root)));
	}

	@Test
	public void testFailRequestSignatureSignatureErrorFail(WireMockRuntimeInfo wmRuntimeInfo) throws IOException {
		var mapper = new ObjectMapper();
		var root = mapper.createObjectNode();
		root.set("success", mapper.convertValue(true, JsonNode.class));
		root.set("message", mapper.convertValue("XXXXXX", JsonNode.class));
		root.set("signature", mapper.convertValue("", JsonNode.class));
		var baw = new ByteArrayWriter();
		baw.writeBoolean(true);
		baw.writeString("It's all gone a bit Pete Tong");
		var bb = baw.toByteArray();
		root.set("response", mapper.convertValue(Base64.getUrlEncoder().encodeToString(bb), JsonNode.class));

		signStub(root);

		var ks = new DefaultSignatureGenerator("localhost", wmRuntimeInfo.getHttpsPort());
		var client = new AuthenticatorClient();
		client.enableDebug();
		var ex = assertThrows(IOException.class, () -> {
			ks.requestSignature(client, "test@test.com", "SHA256:HJmwFN7kuX0rZzPGi+4kqO2ftzQ1DAN5BwqW6B3d2AE",
					"test wants to authenticate from LogonBox Authenticator API using your localhost credentials.",
					"Authorize",
					"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4A=",
					0);
		});
		assertEquals("The server did not respond with a valid response!", ex.getMessage());
	}
}
