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
 * created by Trifork A/S are Copyright (C) 2009 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *
 */
package dk.itst.oiosaml.sp.model;

import javax.crypto.SecretKey;

import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.RetrievalMethod;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.validation.ValidationException;

public class OIOEncryptedAssertion {
	private static final Logger log = Logger.getLogger(OIOEncryptedAssertion.class);
	
	private final EncryptedAssertion encrypted;

	public OIOEncryptedAssertion(EncryptedAssertion assertion) {
		this.encrypted = assertion;
	}

	public OIOAssertion decryptAssertion(Credential credential, boolean allowUnencrypted) {
		KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(credential);
		EncryptedKey key = getEncryptedKey(encrypted);

		Decrypter decrypter = new Decrypter(null, keyResolver, null);

		try {
			if (log.isDebugEnabled()) log.debug("Assertion encrypted: " + encrypted);

			SecretKey dkey = (SecretKey) decrypter.decryptKey(key, encrypted.getEncryptedData().getEncryptionMethod().getAlgorithm());

			Credential scred = SecurityHelper.getSimpleCredential(dkey);

			decrypter = new Decrypter(new StaticKeyInfoCredentialResolver(scred), null, null);

			// due to a bug in OpenSAML, we have to convert the assertion to and from xml
			// otherwise the signature will not validate later on
			Assertion assertion = decrypter.decrypt(encrypted);
			OIOAssertion res = new OIOAssertion(assertion);
			assertion = (Assertion) SAMLUtil.unmarshallElementFromString(res.toXML());
			if (log.isDebugEnabled()) log.debug("Decrypted assertion: " + res.toXML());

			return new OIOAssertion(assertion);
		} catch (DecryptionException e) {
			throw new ValidationException(e);
		}
	}

	private EncryptedKey getEncryptedKey(EncryptedAssertion enc) {
		KeyInfo keyInfo = enc.getEncryptedData().getKeyInfo();
		if (!keyInfo.getEncryptedKeys().isEmpty()) {
			return keyInfo.getEncryptedKeys().get(0);
		} else if (!keyInfo.getRetrievalMethods().isEmpty()) {
			RetrievalMethod rm = keyInfo.getRetrievalMethods().get(0);

			if (!OIOSAMLConstants.RETRIEVAL_METHOD_ENCRYPTED_KEY.equals(rm.getType())) {
				throw new UnsupportedOperationException("Retrieval type " + rm.getType() + " is not supported");
			}
			Element key = enc.getDOM().getOwnerDocument().getElementById(rm.getURI().substring(1));
			return (EncryptedKey) SAMLUtil.unmarshallElement(key);
		}
		
		throw new RuntimeException("No supported EncryptedKeys found");
	}

}
