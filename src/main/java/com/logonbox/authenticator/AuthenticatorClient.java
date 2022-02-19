package com.logonbox.authenticator;

/*
 * #%L
 * LogonBox Authenticator API
 * %%
 * Copyright (C) 2022 LogonBox Limited
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
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

import com.fasterxml.jackson.databind.ObjectMapper;

public class AuthenticatorClient {

	private final String hostname;
	private final int port;
	private String remoteName = "LogonBox Authenticator API";
	private String promptText = "{username} wants to authenticate from {remoteName} using your {hostname} credentials.";
	private String authorizeText = "Authorize";
	private boolean debug = false; 
	private Logger log = new Logger() { };

	final static byte[] ED25519_ASN_HEADER = { 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21,
			0x00 };

	public AuthenticatorClient(String hostname) {
		this(hostname, 443);
	}

	public AuthenticatorClient(String hostname, int port) {
		this.hostname = hostname;
		this.port = port;
	}
	
	public void enableDebug() {
		this.debug = true;
	}
	
	public void enableDebug(Logger log) {
		this.log = log;
		this.debug = true;
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

	public AuthenticatorResponse authenticate(String principal) throws IOException {
		var tmp = new byte[128];
		var rnd = new SecureRandom();
		rnd.nextBytes(tmp);

		return authenticate(principal, tmp);
	}

	public Collection<PublicKey> getUserKeys(String principal) throws IOException {

		try {
			var request = HttpRequest.newBuilder()
					.uri(new URI(String.format("https://%s:%d/authorizedKeys/%s", hostname, port, principal))).GET()
					.build();

			var client = HttpClient.newHttpClient();
			var response = client.send(request, BodyHandlers.ofString());

			if(debug) {
				log.info(String.format("Received authorized keys from %s", hostname));
				log.info(response.body());
			}
			
			List<PublicKey> keys = new ArrayList<>();
			try (var reader = new BufferedReader(new StringReader(response.body()))) {

				var key = reader.readLine();
				if(!key.startsWith("# Authorized")) {
					throw new IOException(String.format("Unable to list users authorized keys from %s", hostname));
				}

				while ((key = reader.readLine()) != null) {
					if (key.trim().startsWith("#")) {
						continue;
					}
					try {
						
						if(debug) {
							log.info(String.format("Parsing key %s", key));
						}
						
						var pub = decodeKey(key);
						keys.add(pub);
						
						if(debug) {
							log.info(String.format("Decoded %s public key", pub.getAlgorithm()));
						}
						
					} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
						log.error(e.getMessage());
						continue;
					}
				}
			}

			return keys;
		} catch (InterruptedException | URISyntaxException e) {
			throw new IOException(e.getMessage(), e);
		}
	}
	
	public AuthenticatorResponse authenticate(String principal, byte[] payload) throws IOException {

		try {
			var request = HttpRequest.newBuilder()
					.uri(new URI(String.format("https://%s:%d/authorizedKeys/%s", hostname, port, principal))).GET()
					.build();

			var client = HttpClient.newHttpClient();
			var response = client.send(request, BodyHandlers.ofString());

			if(debug) {
				log.info(String.format("Received authorized keys from %s", hostname));
				log.info(response.body());
			}
			
			try (var reader = new BufferedReader(new StringReader(response.body()))) {

				String key = reader.readLine();
				
				if(!key.startsWith("# Authorized")) {
					throw new IOException(String.format("Unable to list users authorized keys from %s", hostname));
				}
				while ((key = reader.readLine()) != null) {
					if (key.trim().startsWith("#")) {
						continue;
					}

					if(debug) {
						log.info(String.format("Parsing key %s", key));
					}

					PublicKey pub = null;
					try {
						
						pub = decodeKey(key);
						
						if(debug) {
							log.info(String.format("Decoded %s public key", pub.getAlgorithm()));
						}
						
					} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
						log.error(e.getMessage());
						continue;
					}
					
					return signPayload(principal, pub, replaceVariables(promptText, principal), authorizeText, payload);
				}
			}

			throw new IOException(String.format("No suitbale key found for %s", principal));
		} catch (InterruptedException | URISyntaxException e) {
			throw new IOException(e.getMessage(), e);
		}
	}

	private String replaceVariables(String promptText, String principal) {
		return promptText.replace("{username}", principal)
				.replace("{remoteName}", remoteName)
				.replace("{hostname}", hostname);
	}

	private AuthenticatorResponse signPayload(String principal, PublicKey key, String text, String buttonText,
			byte[] payload) throws IOException {

		var fingerprint = generateFingerprint(key);
		
		if(debug) {
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

		return new AuthenticatorResponse(key, payload,
						requestSignature(principal, fingerprint, text, 
								buttonText, encodedPayload, flags), flags);

	}

	private byte[] requestSignature(String principal, String fingerprint, String text, String buttonText,
			String encodedPayload, int flags) throws IOException {

		try {
			
			var builder = new StringBuilder();
			builder.append("username=");
			builder.append(URLEncoder.encode(principal, StandardCharsets.UTF_8));
			builder.append("&fingerprint=");
			builder.append(URLEncoder.encode(fingerprint, StandardCharsets.UTF_8));
			builder.append("&remoteName=");
			builder.append(URLEncoder.encode(remoteName, StandardCharsets.UTF_8));
			builder.append("&text=");
			builder.append(URLEncoder.encode(text, StandardCharsets.UTF_8));
			builder.append("&authorizeText=");
			builder.append(URLEncoder.encode(buttonText, StandardCharsets.UTF_8));
			builder.append("&flags=");
			builder.append(String.valueOf(flags));
			builder.append("&payload=");
			builder.append(encodedPayload);

			var request = HttpRequest.newBuilder()
					.uri(new URI(String.format("https://%s:%d/app/api/authenticator/signPayload", hostname, port)))
					.header("Content-Type", "application/x-www-form-urlencoded")
					.POST(HttpRequest.BodyPublishers.ofString(builder.toString())).build();

			var client = HttpClient.newHttpClient();
			
			var response = client.send(request, BodyHandlers.ofString());

			if(debug) {
				log.info(String.format("Received %s response", response.statusCode()));
				log.info(response.body());
			}
			var result = new ObjectMapper().readValue(response.body(), SignatureResponse.class);
			
			if(!result.isSuccess()) {
				throw new IOException(result.getMessage());
			}
			
			if("".equals(result.getSignature())) {
				try(var reader = new ByteArrayReader(Base64.getUrlDecoder().decode(result.getResponse()))) {
					var success = reader.readBoolean();
					if(!success) {
						throw new IOException(reader.readString());
					}
				}
				throw new IOException("The server did not respond with a valid response!");
			}

			return Base64.getUrlDecoder().decode(result.getSignature());
		} catch (URISyntaxException | InterruptedException e) {
			throw new IOException(e.getMessage(), e);
		}
	}

	public String generateFingerprint(PublicKey key) throws IOException {

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
		} catch(NoSuchAlgorithmException e) {
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
		for(var key : getUserKeys(username)) {
			var thisFingerprint = generateFingerprint(key);
			if(thisFingerprint.equals(fingerprint)) {
				return key;
			}
		}
		throw new IllegalArgumentException(String.format("No suitable key found for fingerprint %s", fingerprint));
	}
	
	public PublicKey getDefaultKey(String email) throws IOException {
		
		var keys = getUserKeys(email);
		PublicKey selected = null;
		for(var key : keys) {
			if(!key.getAlgorithm().equals("RSA")) {
				selected = key;
				break;
			}
		}
		
		if(Objects.isNull(selected)) {
			selected = keys.iterator().next();
		}
		
		return selected;
		
	}
	
	public int getFlags(PublicKey key) {
		switch(key.getAlgorithm()) {
		case "RSA":
			return 4;
		default:
			return 0;
		}
	}

	public AuthenticatorResponse processResponse(byte[] payload, byte[] sig) throws IOException {
		
		try(var reader = new ByteArrayReader(sig)) {
			
			var success = reader.readBoolean();
			if(success) {
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
		
		try(var request = new ByteArrayWriter()) {
			

			var key = getDefaultKey(email);
			var fingerprint = generateFingerprint(key);
			var flags = getFlags(key);

			var rnd = new SecureRandom();
			var nonce = rnd.nextInt();
			var noise = new byte[16];
			
			rnd.nextBytes(noise);
			request.writeString(email);
			request.writeString(fingerprint);
			request.writeString(getRemoteName());
			request.writeString(getPromptText());
			request.writeString(getAuthorizeText());
			request.writeInt(flags);
			request.writeInt(nonce);
			request.writeString(redirectURL);
			request.write(noise);
		
			var encoded = Base64.getUrlEncoder().encodeToString(request.toByteArray());

			return new AuthenticatorRequest(this, encoded);
		} 
	}

	public String getHostname() {
		return hostname;
	}
	
	public int getPort() {
		return port;
	}

}
