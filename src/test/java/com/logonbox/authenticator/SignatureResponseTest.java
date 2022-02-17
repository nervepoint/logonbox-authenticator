package com.logonbox.authenticator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

public class SignatureResponseTest {

	@Test
	void create() {
		var r = new SignatureResponse();
		assertEquals(false, r.success);
		assertNull(r.message);
		assertNull(r.response);
		assertNull(r.signature);
	}

	@Test
	void update() {
		var r = new SignatureResponse();
		r.setMessage("A message");
		r.setSuccess(true);
		r.setResponse("A response");
		r.setSignature("A signature");
		assertEquals("A message", r.getMessage());
		assertEquals(true, r.isSuccess());
		assertEquals("A response", r.getResponse());
		assertEquals("A signature", r.getSignature());

	}
}
