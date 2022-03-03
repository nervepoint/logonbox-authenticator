package com.logonbox.authenticator;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Builder;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

public class AuthenticatorClient {

	private String remoteName = "LogonBox Authenticator API";
	private String promptText = "{username} wants to authenticate from {remoteName} using your {hostname} credentials.";
	private String authorizeText = "Authorize";
	private boolean debug = false;
	private Logger log = new Logger() {
	};
	private final SignatureGenerator signatureGenerator;
	private final KeySource keySource;
	private final RandomGenerator randomGenerator;
	private List<String> supportedAlgorithms;

	final static byte[] ED25519_ASN_HEADER = { 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00 };

	AuthenticatorClient() {
		this((c, p, f, t, bt, e, fl) -> {
			throw new UnsupportedOperationException();
		}, (c, p) -> {
			throw new UnsupportedOperationException();
		}, defaultRandomGenerator());
	}

	protected static RandomGenerator defaultRandomGenerator() {
		return new RandomGenerator() {
			private SecureRandom rnd = new SecureRandom();

			@Override
			public byte[] bytes(int count) {
				var b = new byte[count];
				rnd.nextBytes(b);
				return b;
			}
		};
	}

	public AuthenticatorClient(String hostname) {
		this(hostname, 443);
	}

	public AuthenticatorClient(String hostname, int port) {
		signatureGenerator = new DefaultSignatureGenerator(hostname, port);
		keySource = new DefaultKeySource(hostname, port);
		randomGenerator = defaultRandomGenerator();
	}

	public AuthenticatorClient(SignatureGenerator signatureGenerator, KeySource keySource,
			RandomGenerator randomGenerator) {
		super();
		this.signatureGenerator = signatureGenerator;
		this.keySource = keySource;
		this.randomGenerator = randomGenerator;
	}

	public List<String> getSupportedAlgorithms() {
		return supportedAlgorithms;
	}

	public void setSupportedAlgorithms(List<String> supportedAlgorithms) {
		this.supportedAlgorithms = supportedAlgorithms;
	}

	public KeySource getKeySource() {
		return keySource;
	}

	public SignatureGenerator getSignatureGenerator() {
		return signatureGenerator;
	}

	public void enableDebug() {
		this.debug = true;
	}

	public void enableDebug(Logger log) {
		this.log = log;
		this.debug = true;
	}

	public boolean isDebug() {
		return debug;
	}

	public Logger getLog() {
		return log;
	}

	public String getRemoteName() {
		return remoteName;
	}

	public void setRemoteName(String remoteName) {
		this.remoteName = remoteName;
	}

	public String getPromptText() {
		return promptText;
	}

	public void setPromptText(String promptText) {
		this.promptText = promptText;
	}

	public String getAuthorizeText() {
		return authorizeText;
	}

	public void setAuthorizeText(String authorizeText) {
		this.authorizeText = authorizeText;
	}

	public AuthenticatorResponse authenticate(String principal) {
		return authenticate(principal, randomGenerator.bytes(128));
	}

	public Collection<PublicKey> getUserKeys(String principal) {

		List<PublicKey> publicKeys = new ArrayList<>();
		for (var key : keySource.listKeys(this, principal)) {
			try {
				if (debug) {
					log.info(String.format("Parsing key %s", key));
				}

				var pub = decodeKey(key);

				if (debug) {
					log.info(String.format("Decoded %s public key", pub.getAlgorithm()));
				}

				var algo = getAlgorithm(pub);
				if (supportedAlgorithms == null || supportedAlgorithms.contains(algo)) {
					publicKeys.add(pub);
				} else {
					if (debug) {
						log.info(
								String.format("Skipping %s public key, not an enabled algorithm.", pub.getAlgorithm()));
					}
				}

			} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
				log.error(e.getMessage());
				continue;
			}
		}
		return publicKeys;
	}

	public AuthenticatorResponse authenticate(String principal, byte[] payload) {
		for (var key : keySource.listKeys(this, principal)) {
			try {
				return authenticate(principal, payload, key);
			} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
				log.error(e.getMessage());
				continue;
			} catch (IllegalArgumentException e) {
				if (debug) {
					log.info("Skipping disabled algorithm.");
				}
			}
		}
		throw new IllegalArgumentException(String.format("No suitable key found for %s", principal));
	}

	private AuthenticatorResponse authenticate(String principal, byte[] payload, String key)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		var pub = decodeKey(key);

		if (debug) {
			log.info(String.format("Decoded %s public key", pub.getAlgorithm()));
		}

		var algo = getAlgorithm(pub);
		if (supportedAlgorithms == null || supportedAlgorithms.contains(algo)) {
			return signPayload(principal, pub, replaceVariables(promptText, principal), authorizeText, payload);
		} else {
			throw new IllegalArgumentException();
		}
	}

	private String replaceVariables(String promptText, String principal) {
		return promptText.replace("{username}", principal).replace("{remoteName}", remoteName).replace("{hostname}",
				signatureGenerator.getHostname());
	}

	private AuthenticatorResponse signPayload(String principal, PublicKey key, String text, String buttonText,
			byte[] payload) throws IOException {

		var fingerprint = generateFingerprint(key);

		if (debug) {
			log.info(String.format("Key fingerprint is %s", fingerprint));
		}

		var encodedPayload = Base64.getUrlEncoder().encodeToString(payload);
		int flags = 0;
		if (key instanceof RSAPublicKey) {
			/**
			 * Tell the server we want a RSAWithSHA512 signature
			 */
			flags = 4;
		}

		var sig = signatureGenerator.requestSignature(this, principal, fingerprint, text, buttonText, encodedPayload,
				flags);
		if (debug) {
			log.info(String.format("Request signature is %s", Base64.getEncoder().encodeToString(sig)));
		}

		return new AuthenticatorResponse(key, payload, sig, flags);
	}

	private String generateFingerprint(PublicKey key) throws IOException {

		try {
			var md = MessageDigest.getInstance("SHA-256");
			md.update(encodeKey(key));
			var digest = md.digest();
			var buf = new StringBuffer();
			buf.append("SHA256");
			buf.append(":");
			buf.append(Base64.getEncoder().encodeToString(digest));
			while (buf.charAt(buf.length() - 1) == '=') {
				buf.delete(buf.length() - 1, buf.length());
			}

			return buf.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e.getMessage(), e);
		}
	}

	private String getAlgorithm(PublicKey key) throws IOException {
		switch (key.getAlgorithm()) {
		case "RSA":
			return "ssh-rsa";
		case "Ed25519":
		case "EdDSA":
			return "ssh-ed25519";
		default:
			throw new IOException(String.format("Unsupported JCE key type %s", key.getAlgorithm()));
		}
	}

	private byte[] encodeKey(PublicKey key) throws IOException {

		try (var writer = new ByteArrayWriter()) {
			writer.writeString(getAlgorithm(key));

			switch (key.getAlgorithm()) {
			case "RSA":
				var rsa = (RSAPublicKey) key;
				writer.writeBigInteger(rsa.getPublicExponent());
				writer.writeBigInteger(rsa.getModulus());
				break;
			case "Ed25519":
			case "EdDSA":
				var encoded = key.getEncoded();
				var seed = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
				writer.writeBinaryString(seed);
				break;
			}

			return writer.toByteArray();
		}
	}

	private PublicKey decodeKey(String key) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

		int idx = key.indexOf(' ');
		@SuppressWarnings("unused")
		var algorithm = key.substring(0, idx);
		int idx2 = key.indexOf(' ', idx + 1);
		var base64 = key.substring(idx + 1, idx2);
		@SuppressWarnings("unused")
		var comments = key.substring(idx2 + 1);

		var data = Base64.getDecoder().decode(base64);

		var reader = new ByteArrayReader(data);
		var algorithm2 = reader.readString();

		switch (algorithm2) {
		case "ssh-rsa":
			return decodeRSA(reader);
		case "ssh-ed25519":
			return decodeEd25519(reader);
		default:
			throw new IOException(String.format("Unknown key type %s", algorithm2));
		}
	}

	private PublicKey decodeEd25519(ByteArrayReader reader)
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("Ed25519");
		} catch (NoSuchAlgorithmException e) {
			keyFactory = KeyFactory.getInstance("EdDSA");
		}

		var pk = reader.readBinaryString();

		var encoded = new byte[ED25519_ASN_HEADER.length + pk.length];
		System.arraycopy(ED25519_ASN_HEADER, 0, encoded, 0, ED25519_ASN_HEADER.length);
		System.arraycopy(pk, 0, encoded, ED25519_ASN_HEADER.length, pk.length);
		var x509KeySpec = new X509EncodedKeySpec(encoded);
		return keyFactory.generatePublic(x509KeySpec);

	}

	private PublicKey decodeRSA(ByteArrayReader reader)
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		var e = reader.readBigInteger();
		var n = reader.readBigInteger();
		var rsaKey = new RSAPublicKeySpec(n, e);

		var kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(rsaKey);

	}

	public PublicKey getUserKey(String username, String fingerprint) throws IOException {
		for (var key : getUserKeys(username)) {
			var thisFingerprint = generateFingerprint(key);
			if (thisFingerprint.equals(fingerprint)) {
				return key;
			}
		}
		throw new IllegalArgumentException(String.format("No suitable key found for fingerprint %s", fingerprint));
	}

	public PublicKey getDefaultKey(String email) throws IOException {

		var keys = getUserKeys(email);
		PublicKey selected = null;
		for (var key : keys) {
			if (!key.getAlgorithm().equals("RSA")) {
				selected = key;
				break;
			}
		}

		if (!keys.isEmpty() && Objects.isNull(selected)) {
			selected = keys.iterator().next();
		}

		return selected;

	}

	public int getFlags(PublicKey key) {
		switch (key.getAlgorithm()) {
		case "RSA":
			return 4;
		default:
			return 0;
		}
	}

	public AuthenticatorResponse processResponse(byte[] payload, byte[] sig) throws IOException {

		try (var reader = new ByteArrayReader(sig)) {

			var success = reader.readBoolean();
			if (success) {
				var username = reader.readString();
				var fingerprint = reader.readString();
				int flags = (int) reader.readInt();
				var signature = reader.readBinaryString();

				return new AuthenticatorResponse(getUserKey(username, fingerprint), payload, signature, flags);
			} else {
				throw new IOException(reader.readString());
			}

		}
	}

	public AuthenticatorRequest generateRequest(String email, String redirectURL) throws IOException {

		try (var request = new ByteArrayWriter()) {

			var key = getDefaultKey(email);

			if (Objects.isNull(key)) {
				throw new IOException(
						String.format("%s is not registered in the LogonBox Authenticator directory!", email));
			}
			var fingerprint = generateFingerprint(key);
			var flags = getFlags(key);

			request.writeString(email);
			request.writeString(fingerprint);
			request.writeString(getRemoteName());
			request.writeString(getPromptText());
			request.writeString(getAuthorizeText());
			request.writeInt(flags);
			request.write(randomGenerator.bytes(4));
			request.writeString(redirectURL);
			request.write(randomGenerator.bytes(16));

			var encoded = Base64.getUrlEncoder().encodeToString(request.toByteArray());

			return new AuthenticatorRequest(this, encoded);
		}
	}

	protected Builder newHttpClientBuilder() {
		/**
		 * Override to create a custom http client, used by by {@link DefaultKeySourcce}
		 * and {@link DefaultSignatureGenerator}.
		 */
		return HttpClient.newBuilder();
	}
}
