package com.logonbox.authenticator;

import java.security.Security;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class AbstractTest {
	static {
		Security.addProvider(new EdDSASecurityProvider());
	}
}
