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
import java.util.Base64;

public class AuthenticatorRequest {

	private final AuthenticatorClient client;
	private final String encodedPayload;

	AuthenticatorRequest(AuthenticatorClient client, String encodedPayload) {
		this.client = client;
		this.encodedPayload = encodedPayload;
	}

	public String getUrl() {
		if (client.getKeySource().getPort() != 443) {
			return String.format("https://%s:%d/authenticator/sign/%s", client.getKeySource().getHostname(),
					client.getKeySource().getPort(), encodedPayload);
		} else {
			return String.format("https://%s/authenticator/sign/%s", client.getKeySource().getHostname(),
					encodedPayload);
		}
	}
	
	public String getEncodedPayload() {
		return encodedPayload;
	}

	public AuthenticatorClient getClient() {
		return client;
	}

	public AuthenticatorResponse processResponse(String response) throws IOException {

		var payload = Base64.getUrlDecoder().decode(encodedPayload);
		var signature = Base64.getUrlDecoder().decode(response);

		return client.processResponse(payload, signature);

	}

}
