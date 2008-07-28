/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.sp.model;

import java.security.cert.Certificate;

import javax.crypto.SecretKey;

import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;

import dk.itst.oiosaml.error.ValidationException;
import dk.itst.oiosaml.sp.service.session.LoggedInHandler;
import dk.itst.oiosaml.sp.util.BRSUtil;

/**
 * Base class for all SAML responses.
 * 
 * 
 * @author Joakim Recht <jre@trifork.com>
 *
 */
public class OIOResponse extends OIOAbstractResponse {
	private static final Logger log = Logger.getLogger(OIOResponse.class);
	
	private final Response response;

	public OIOResponse(Response response) {
		super(response);
		
		this.response = response;
	}

	/**
	 * Get the id of the issuing entity.
	 * @param handler Handler which holds sent request ids. This is used if the response has a InResponseTo.
	 * 
	 * @throws ValidationException If the response is unsolicited and does not contain an issuer.
	 */
	public String getOriginatingIdpEntityId(LoggedInHandler handler) {
		if (response.getInResponseTo() == null) {
			Issuer issuer = null;
			if (!response.getAssertions().isEmpty()) {
				issuer = response.getAssertions().get(0).getIssuer();
			}
			if (issuer == null) {
				issuer = response.getIssuer();
			}
			
			if (issuer == null)  {
				throw new ValidationException("SAML Response does not contain a issuer, this is required for unsolicited Responses");
			}
			return issuer.getValue();
		} else {
			return handler.removeEntityIdForRequest(response.getInResponseTo());
		}
	}
	
	public void validateResponse(String expectedDestination, Certificate certificate, boolean allowPassive) throws ValidationException {
		validateResponse(null, expectedDestination, allowPassive);
		
		if (response.getAssertions().isEmpty() && !isPassive()) {
			throw new ValidationException("Response must contain an Assertion. If the Response contains an encrypted Assertion, decrypt it before calling validate.");
		}
		
		if (hasSignature() || isPassive()) {
			 if (!verifySignature(certificate.getPublicKey())) {
				 throw new ValidationException("The response is not signed correctly");
			 }
		} else {
			if (!response.getAssertions().isEmpty() && !getAssertion().verifySignature(certificate.getPublicKey())) {
				throw new ValidationException("The assertion is not signed correctly");
			}
		}
	}
	
	/**
	 * Get the response assertion.
	 */
	public OIOAssertion getAssertion() {
		return OIOAssertion.fromResponse(response);
	}
	
	
	public void decryptAssertion(Credential credential, boolean allowUnencrypted) {
		if (response.getEncryptedAssertions().size() > 0) {
			KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(credential);
			EncryptedAssertion enc = response.getEncryptedAssertions().get(0);
			EncryptedKey key = enc.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0);
			
	        Decrypter decrypter = new Decrypter(null, keyResolver, null);

	        try {
	        	if (log.isDebugEnabled()) log.debug("Assertion encrypted: " + enc);
	        	
		        SecretKey dkey = (SecretKey) decrypter.decryptKey(key, enc.getEncryptedData().getEncryptionMethod().getAlgorithm());
			       
		        Credential scred = SecurityHelper.getSimpleCredential(dkey);
		        
		        decrypter = new Decrypter(new StaticKeyInfoCredentialResolver(scred), null, null);
		        
		        // due to a bug in OpenSAML, we have to convert the assertion to and from xml
		        // otherwise the signature will not validate later on
				Assertion assertion = decrypter.decrypt(enc);
				OIOAssertion res = new OIOAssertion(assertion);
				assertion = (Assertion) BRSUtil.unmarshallElementFromString(res.toXML());
				if (log.isDebugEnabled()) log.debug("Decrypted assertion: " + res.toXML());
				
				response.getAssertions().add(assertion);
			} catch (DecryptionException e) {
				throw new ValidationException(e);
			}
		} else {
			if (!allowUnencrypted && !response.getAssertions().isEmpty()) {
				throw new ValidationException("Assertion is not encrypted");
			}
		}
	}
	
	public Response getResponse() {
		return response;
	}
	
	public boolean isPassive() {
		return StatusCode.RESPONDER_URI.equals(response.getStatus().getStatusCode().getValue()) && 
			response.getStatus().getStatusCode().getStatusCode() != null &&
			StatusCode.NO_PASSIVE_URI.equals(response.getStatus().getStatusCode().getStatusCode().getValue());
	}
}
