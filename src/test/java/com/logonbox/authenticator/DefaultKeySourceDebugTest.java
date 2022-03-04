package com.logonbox.authenticator;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;

@WireMockTest(httpsEnabled = true)
public class DefaultKeySourceDebugTest extends DefaultKeySourceTest {
	@Override
	protected AuthenticatorClient createClient() {
		var c = super.createClient();
		c.enableDebug();
		return c;
	}
}
