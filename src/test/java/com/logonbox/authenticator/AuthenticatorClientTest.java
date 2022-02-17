package com.logonbox.authenticator;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.net.ConnectException;
import java.util.ArrayList;

import org.junit.jupiter.api.Test;

public class AuthenticatorClientTest {

	@Test
	void testCreate1() {
		var client = new AuthenticatorClient("test.mydomain.com");
		assertEquals(443, client.getPort());
		assertEquals("test.mydomain.com", client.getHostname());
	}

	@Test
	void testCreate2() {
		var client = new AuthenticatorClient("test.mydomain.com", 8443);
		assertEquals(8443, client.getPort());
		assertEquals("test.mydomain.com", client.getHostname());
	}

	@Test
	void testUpdate() {
		var client = new AuthenticatorClient("test.mydomain.com");
		client.setAuthorizeText("Some authorize text");
		client.setPromptText("Some prompt text");
		client.setRemoteName("A remote name");
		assertEquals("Some authorize text", client.getAuthorizeText());
		assertEquals("Some prompt text", client.getPromptText());
		assertEquals("A remote name", client.getRemoteName());
	}

	@Test
	void testDebug() throws IOException {
		var client = new AuthenticatorClient("test.mydomain.com");
		var l = new ArrayList<>();
		client.enableDebug(new Logger() {
			@Override
			public void info(String msg) {
				l.add(msg);
			}

			@Override
			public void error(String msg) {
				l.add(msg);
			}

			@Override
			public void error(String msg, Throwable e) {
				l.add(msg);
			}
		});
		try {
			client.authenticate("xxxx");
		}
		catch(ConnectException ce) {
		}
		assertEquals("Some authorize text", l.get(0));
		
	}
}
