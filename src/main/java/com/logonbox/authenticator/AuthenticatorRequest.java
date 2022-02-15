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
import java.security.PublicKey;
import java.util.Base64;

public class AuthenticatorRequest {

	AuthenticatorClient client;
	PublicKey key;
	String username;
	String fingerprint;
	String encodedPayload;
	
	AuthenticatorRequest(AuthenticatorClient client, PublicKey key, String username, String fingerprint, int flags,
			String encodedPayload) {
		this.client = client;
		this.key = key;
		this.username = username;
		this.fingerprint = fingerprint;
		this.encodedPayload = encodedPayload;
	}
	
	public String getUrl() {
		if(client.getPort()!=443) {
			return String.format("https://%s:%d/authenticator/sign/%s", 
					client.getHostname(), client.getPort(), encodedPayload);
		} else {
			return String.format("https://%s/authenticator/sign/%s", client.getHostname(), encodedPayload);
		}
	}

	public AuthenticatorClient getClient() {
		return client;
	}

	public AuthenticatorResponse processResponse(String response) throws IOException {
		
		byte[] payload = Base64.getUrlDecoder().decode(encodedPayload);
		byte[] signature = Base64.getUrlDecoder().decode(response);
		
		return client.processResponse(payload, signature);
		
	}
	
	
}
