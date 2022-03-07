package com.logonbox.authenticator;

public class AuthenticatorClientDebugTest extends AuthenticatorClientTest {

	@Override
	protected void configureClient(AuthenticatorClient client) {
		client.enableDebug();
	}
}
