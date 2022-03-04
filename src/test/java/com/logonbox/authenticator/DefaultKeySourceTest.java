package com.logonbox.authenticator;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;

@WireMockTest(httpsEnabled = true)
public class DefaultKeySourceTest extends AbstractHttpTest {

	@Test
	public void testConstruct() {
		var ks = new DefaultKeySource("qwerty", 12345);
		assertEquals("qwerty", ks.getHostname());
		assertEquals(12345, ks.getPort());
	}

	@Test
	public void testListKeys(WireMockRuntimeInfo wmRuntimeInfo) {
		var kl = AuthenticatorClientTest.keyList();
		stubFor(get(urlEqualTo("/app/api/authenticator/keys/test@test.com"))
				.willReturn(aResponse().withHeader("Content-Type", "text/plain")
						.withBody(String.join("\r\n", Stream
								.concat(Arrays.asList("# Authorized", "", "# Some other comment").stream(), kl.stream())
								.collect(Collectors.toList())))));

		var ks = new DefaultKeySource("localhost", wmRuntimeInfo.getHttpsPort());
		var client = createClient();
		var it = ks.listKeys(client, "test@test.com").iterator();
		assertTrue(it.hasNext());
		assertEquals(kl.get(0), it.next());
		assertTrue(it.hasNext());
		assertEquals(kl.get(1), it.next());
		assertFalse(it.hasNext());
	}

	@Test
	public void testFailListKeysUnexpectedFormat(WireMockRuntimeInfo wmRuntimeInfo) {
		var kl = AuthenticatorClientTest.keyList();
		stubFor(get(urlEqualTo("/app/api/authenticator/keys/test@test.com"))
				.willReturn(aResponse().withHeader("Content-Type", "text/plain").withBody(String.join("\r\n", Stream
						.concat(Arrays.asList("# XXXXXXXXXX").stream(), kl.stream()).collect(Collectors.toList())))));
		var ks = new DefaultKeySource("localhost", wmRuntimeInfo.getHttpsPort());
		var client = createClient();
		assertThrows(IllegalStateException.class, () -> {
			ks.listKeys(client, "test@test.com").iterator();
		});
	}
}
