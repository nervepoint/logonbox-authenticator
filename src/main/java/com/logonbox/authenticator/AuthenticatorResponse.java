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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class AuthenticatorResponse {

	private final byte[] payload;
	private final byte[] signature;
	private final PublicKey key;
	private final int flags;
	
	AuthenticatorResponse(PublicKey key, byte[] payload, byte[] signature, int flags) {
		this.key = key;
		this.signature = signature;
		this.payload = payload;
		this.flags = flags;
	}
	
	public boolean verify() throws IOException {
		
		boolean verified = false;
		
		switch(key.getAlgorithm()) {
		case "RSA":
			return verifyRSASignature();
		case "Ed25519":
			return verifyEd25519Signature();
		}
		
		return verified;
	}

	private boolean verifyRSASignature() throws IOException {
		
		try {
			Signature sgr = Signature.getInstance(getRSASignatureAlgorithm(flags));
			sgr.initVerify(key);
			sgr.update(payload);
			return sgr.verify(signature);
		} catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
			throw new IOException(e.getMessage(), e);
		}
	}

	private String getRSASignatureAlgorithm(int flags2) {
		
		switch(flags) {
		case 4:
			return "SHA512WithRSA";
		case 2:
			return "SHA256WithRSA";
		default:
			return "SHA1WithRSA";
		}
	}

	private boolean verifyEd25519Signature() throws IOException {
		
		try {
			Signature sgr = Signature.getInstance("Ed25519");
			sgr.initVerify(key);
			sgr.update(payload);
			return sgr.verify(signature);
		} catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
			throw new IOException(e.getMessage(), e);
		}
	}

	public byte[] getSignature() {
		return signature;
	}
}
