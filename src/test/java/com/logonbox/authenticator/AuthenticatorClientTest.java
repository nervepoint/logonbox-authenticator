package com.logonbox.authenticator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

public class AuthenticatorClientTest {

	@Test
	void testCreate1() {
		var client = new AuthenticatorClient("test.mydomain.com");
		assertEquals(443, client.getSignatureGenerator().getPort());
		assertEquals("test.mydomain.com", client.getSignatureGenerator().getHostname());
	}

	@Test
	void testCreate2() {
		var client = new AuthenticatorClient("test.mydomain.com", 8443);
		assertEquals(8443, client.getSignatureGenerator().getPort());
		assertEquals("test.mydomain.com", client.getSignatureGenerator().getHostname());
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
	void testRSAZeroRandomBytes() throws Exception {
		var sig = Base64.getDecoder().decode(
				"qoeING0vzEXTjmFrX4ZQw2AfZJhFloL6ctgUZ8iveoyoV79V5R7cBfjhVJUDuvTwIqmVtFbcj3o76MNL4cj9tEGDWxgoNf/H0Kw55k08/QW/98VDX9eXxr/gDqDjMmWTnYPlqssqq/IR/OA08dNIZMoH1Wd3G+DCszrOr07lwyPC4oSISqs84fxlBJfaO6CpHncu6JJPyhjRis3Y1DH+t8MR3gCgMz0cl01KoXcYzwYY5kTe1qSpU3G8wtfhf6gGq6cIIu6mbsP6AXSvfiJ/XVB636g2oi2e33EaXzvh2fNHi6F6mVgJvT9Biu9fbzlcs3Q5LXbOFsm5u4NRcvSZY7YRNdJAwTwgS8E9lesPt3ME4iyIlpMa1Dy+sYlKPH1G6Guigi4zt4mRAJPASWG4yUxzeOgNAz8DCT9n0t2bMgst/AV3w8GvE2wC6igA/aJnYTiq+alwB2zUCjLMBSai1Q8hsvpsYDXUq2KgCvurLB781mvJO9MKWhWD51IVPeLT");
		var keys = keyList();
		var client = new AuthenticatorClient((c, p, f, t, bt, e, fl) -> sig, (c, p) -> keys, (c) -> new byte[c]);
		client.enableDebug();
		client.setSupportedAlgorithms(Arrays.asList("ssh-rsa"));
		client.authenticate("test").verify();
	}

	@Test
	void testEd25519ZeroRandomBytes() throws Exception {
		var sig = Base64.getDecoder()
				.decode("ZCqTWvzwzOimDwBGpsxgYzhVcJfWMCbF0D00lxFOfg4Z3777zWqq3iTvQgqiPKIaRVYOQ6vN9DvbxZiJOyyTAg==");
		var keys = keyList();
		var client = new AuthenticatorClient((c, p, f, t, bt, e, fl) -> sig, (c, p) -> keys, (c) -> new byte[c]);
		client.enableDebug();
		client.setSupportedAlgorithms(Arrays.asList("ssh-ed25519"));
		assertTrue(client.authenticate("test").verify());
	}

	@Test
	void testRsaSequentialRandomBytes() throws Exception {
		var sig = Base64.getDecoder().decode(
				"FcYTC3MqvhBeWZimEclN6c1ERnYdPOfWL7Uc3gGUybs+3wIow1rZ0/mH9c4VJ2IkwgdEDspmyppoGge8JMPrFf5zxsqQzJiUzqKFQDFOe3HcSRwjJk3OM8KFaQTymHubWsCiRQCGoiUuMd+7ETF6uANad3bT6fbAWiAPjhxJSwKP4udihMXhznuNfK7llNZT9t5EdMIiS4Xp7jh4L7ZddBINTR/O/fSBRk4HAppR5yJanEnHk7pfYjRxji+7jvtwx0nDAIhgkubsnelNGTgy1zDbHGt2cBS47XSMcyzN6xChFPHCN8b6J78mEP8vCjFCZReoAckzQqelbzBoKoneS/zDmqJqNeV21RfHCKApeZ877ZW0v54B4tHNeeWGFj7nbs8PzAe8UQAAU9jZyyQIi1qYZWKK7vtqhz3OurTqGvLSrFiVGOBV3rzguqbF+Tf4a4YCUhyg+AAW266yS/vB2aVxka+SQ6fNKAnDbiFxRRCzUT5sZl+XBSg7IS/TSwVU");
		var keys = keyList();
		var client = new AuthenticatorClient((c, p, f, t, bt, e, fl) -> sig, (c, p) -> keys, sequentialRng());
		client.enableDebug();
		client.setSupportedAlgorithms(Arrays.asList("ssh-rsa"));
		assertTrue(client.authenticate("test").verify());
	}

	@Test
	void testFailRsaSequentialRandomBytes() throws Exception {
		var sig = new byte[384];
		var keys = keyList();
		var client = new AuthenticatorClient((c, p, f, t, bt, e, fl) -> sig, (c, p) -> keys, sequentialRng());
		client.enableDebug();
		client.setSupportedAlgorithms(Arrays.asList("ssh-rsa"));
		assertFalse(client.authenticate("test").verify());
	}

	@Test
	void testEd25519SequentialRandomBytes() throws Exception {
		var sig = Base64.getDecoder()
				.decode("1eB+ogdIs4G/+KvZBNI1Gzh6tQNsHn5BsFiDUhMPr3igf2Pnnm6bwRWlUlXYFUmi4LEr1mR9Jvc/5QUA9zm/CQ==");
		var keys = keyList();
		var client = new AuthenticatorClient((c, p, f, t, bt, e, fl) -> sig, (c, p) -> keys, sequentialRng());
		client.enableDebug();
		client.setSupportedAlgorithms(Arrays.asList("ssh-ed25519"));
		assertTrue(client.authenticate("test").verify());
	}

	@Test
	void testFailEd25519SequentialRandomBytes() throws Exception {
		var sig = new byte[64];
		var keys = keyList();
		var client = new AuthenticatorClient((c, p, f, t, bt, e, fl) -> sig, (c, p) -> keys, sequentialRng());
		client.enableDebug();
		client.setSupportedAlgorithms(Arrays.asList("ssh-ed25519"));
		assertFalse(client.authenticate("test").verify());
	}

	static List<String> keyList() {
		return Arrays.asList(
				"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0ISnrIwtSbFr9oRTZNHJfaWcHH7xYKeCRJx8O3N+7+ LogonBox Key",
				"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDbu8Ihw4x/B6+V/1W7IRNb08cF7VoAm/4kdwi8ltnu7VrfKxXt6zeKg/x27MkJoy8ei051f797iamoPrNPdrh3E6nfRJoZda9ybqoOFFxunkk5ezT1V/Ai57iZunLyYxmDJfAdz3Ul8jTbMVjQusFV8rCacLBRa9t+hc5cErKcsRqYvVEpHuJYRnsApLBpW6bdqZ+jXiiRe17KW/aWq530ZlbsNhyN0jHalWpOxOiuFELVsO+TUGborY4wekyhwe5AWi29tqKj2p67ApFUDv6x8Y71pYLxfF4XrDD8ydGgFRES3sa+IogaTqN/PZgfamKQ+3DNW/SKpxdc0jzlBtX0V+E3q49a6t8k9277YnkDkTSFUYCUepPX5+Kjs4X0+dFTOFhO9fOCm7WDOesW6UPN0NIpndDUSY5654B8qqzW57/Nw7AQOVwzSvqrhP6yJS7qL2uZ8rN4UrjD4IY9T3QirZmq3ZBAeCuAdZ4+mcPgcv4eoXBQqGcC14J4q0MZrFs= Legacy RSA");
	}

	static RandomGenerator sequentialRng() {
		return new RandomGenerator() {
			private AtomicInteger v = new AtomicInteger();

			@Override
			public byte[] bytes(int count) {
				var b = new byte[count];
				for (int i = 0; i < b.length; i++) {
					if (v.get() == 255)
						v.set(0);
					b[i] = (byte) v.incrementAndGet();
				}
				return b;
			}
		};
	}
}
