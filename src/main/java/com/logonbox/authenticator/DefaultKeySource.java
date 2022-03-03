package com.logonbox.authenticator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Iterator;

public class DefaultKeySource implements KeySource {

	private final String hostname;
	private final int port;

	public DefaultKeySource(String hostname, int port) {
		this.hostname = hostname;
		this.port = port;
	}

	public String getHostname() {
		return hostname;
	}

	public int getPort() {
		return port;
	}

	@Override
	public Iterable<String> listKeys(AuthenticatorClient client, String principal) {
		return new Iterable<String>() {
			@Override
			public Iterator<String> iterator() {
				try {

					var request = HttpRequest.newBuilder()
							.uri(new URI(String.format("https://%s:%d/app/api/authenticator/keys/%s", hostname, port, principal)))
							.GET().build();

					var httpClient = client.newHttpClientBuilder().build();
					var response = httpClient.send(request, BodyHandlers.ofString());

					if (client.isDebug()) {
						client.getLog().info(String.format("Received authorized keys from %s", hostname));
						client.getLog().info(response.body());
					}
					var body = response.body();
					System.out.println(body);
					var reader = new BufferedReader(new StringReader(body));
					var key = reader.readLine();
					if (!key.startsWith("# Authorized")) {
						throw new IOException(String.format("Unable to list users authorized keys from %s", hostname));
					}
					return new Iterator<String>() {

						private String next = null;

						void checkNext() {
							if (next == null) {
								String line;
								try {
									while ((line = reader.readLine()) != null) {
										line = line.trim();
										if (line.equals("") || line.startsWith("#"))
											continue;
										next = line;
										break;
									}
								} catch (IOException ioe) {
									// Will never happen, entire response is read into a string
								}
							}
						}

						@Override
						public boolean hasNext() {
							checkNext();
							return next != null;
						}

						@Override
						public String next() {
							try {
								checkNext();
								return next;
							} finally {
								next = null;
							}
						}

					};
				} catch (IOException | InterruptedException | URISyntaxException e) {
					throw new IllegalStateException("Failed to list keys.", e);
				}
			}
		};

	}

}
