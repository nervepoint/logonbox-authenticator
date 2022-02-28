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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.fasterxml.jackson.databind.ObjectMapper;

public class DefaultSignatureGenerator implements SignatureGenerator {
	
	private final String host;
	private final int port;

	public DefaultSignatureGenerator(String host) {
		this(host, 443);
	}

	public DefaultSignatureGenerator(String host, int port) {
		this.host = host;
		this.port = port;
	}
	
	@Override
	public String getHostname() {
		return host;
	}

	@Override
	public int getPort() {
		return port;
	}

	public byte[] requestSignature(AuthenticatorClient client, String principal, String fingerprint, String text,
			String buttonText, String encodedPayload, int flags) throws IOException {

		try {
			var builder = new StringBuilder();
			builder.append("username=");
			builder.append(URLEncoder.encode(principal, StandardCharsets.UTF_8));
			builder.append("&fingerprint=");
			builder.append(URLEncoder.encode(fingerprint, StandardCharsets.UTF_8));
			builder.append("&remoteName=");
			builder.append(URLEncoder.encode(client.getRemoteName(), StandardCharsets.UTF_8));
			builder.append("&text=");
			builder.append(URLEncoder.encode(text, StandardCharsets.UTF_8));
			builder.append("&authorizeText=");
			builder.append(URLEncoder.encode(buttonText, StandardCharsets.UTF_8));
			builder.append("&flags=");
			builder.append(String.valueOf(flags));
			builder.append("&payload=");
			builder.append(encodedPayload);

			if (client.isDebug()) {
				client.getLog().info(String.format("Request data \"%s\"", builder.toString()));
			}

			var request = client.newHttpRequestBuilder()
					.uri(new URI(String.format("https://%s:%d/app/api/authenticator/signPayload", host,
							port)))
					.header("Content-Type", "application/x-www-form-urlencoded")
					.POST(HttpRequest.BodyPublishers.ofString(builder.toString())).build();

			var httpClient = HttpClient.newHttpClient();
			var response = httpClient.send(request, BodyHandlers.ofString());

			if (client.isDebug()) {
				client.getLog().info(String.format("Received %s response", response.statusCode()));
				client.getLog().info(response.body());
			}
			var result = new ObjectMapper().readValue(response.body(), SignatureResponse.class);

			if (!result.isSuccess()) {
				throw new IOException(result.getMessage());
			}

			if ("".equals(result.getSignature())) {
				try (var reader = new ByteArrayReader(Base64.getUrlDecoder().decode(result.getResponse()))) {
					var success = reader.readBoolean();
					if (!success) {
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
}
