package com.logonbox.authenticator;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class AuthenticatorRequestTest extends AbstractTest {

	@Test
	void testUrl443() {
		var req = new AuthenticatorRequest(new AuthenticatorClient("test.mydomain.com"), "KX1YIKPRkmHggrCC6KB90CuyNVsl2QO8ddgkgCruZIijgn1xxr0Wxnt8bURKbF0B8j8Af1aXW");
		assertEquals(
				"https://test.mydomain.com/authenticator/sign/KX1YIKPRkmHggrCC6KB90CuyNVsl2QO8ddgkgCruZIijgn1xxr0Wxnt8bURKbF0B8j8Af1aXW",
				req.getUrl());
	}

	@Test
	void testUrl8443() {
		var req = new AuthenticatorRequest(new AuthenticatorClient("test.mydomain.com", 8443), "KX1YIKPRkmHggrCC6KB90CuyNVsl2QO8ddgkgCruZIijgn1xxr0Wxnt8bURKbF0B8j8Af1aXW");
		assertEquals(
				"https://test.mydomain.com:8443/authenticator/sign/KX1YIKPRkmHggrCC6KB90CuyNVsl2QO8ddgkgCruZIijgn1xxr0Wxnt8bURKbF0B8j8Af1aXW",
				req.getUrl());
	}
}
