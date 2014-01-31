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
 * created by Trifork A/S are Copyright (C) 2014 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.sp.configuration;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.log4j.Logger;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.BasicX509Credential;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.security.CredentialRepository;

public class ConfigurationGenerator {
	private static final Logger log = Logger.getLogger(ConfigurationGenerator.class);

	public static Credential loadKeystore(byte[] keystore, String password) {
		try {
			KeyStore ks=KeyStore.getInstance("JKS");
			ks.load(new ByteArrayInputStream(keystore), password.toCharArray());
			return CredentialRepository.createCredential(ks, password);
		}catch (Exception e) {
			log.error("Unable to use/load keystore", e);
			throw new RuntimeException("Unable to use/load keystore", e);
		}
	}

	public static KeystoreCredentialsHolder generateKeystoreAndCredentials(String password, String entityId) {
		try {
			BasicX509Credential cred = new BasicX509Credential();
			KeyPair kp = dk.itst.oiosaml.security.SecurityHelper.generateKeyPairFromURI("http://www.w3.org/2001/04/xmlenc#rsa-1_5", 1024);
			cred.setPrivateKey(kp.getPrivate());
			cred.setPublicKey(kp.getPublic());
			Credential credential = cred;

			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(null, null);
			X509Certificate cert = dk.itst.oiosaml.security.SecurityHelper.generateCertificate(credential, entityId);
			cred.setEntityCertificate(cert);

			ks.setKeyEntry("oiosaml", credential.getPrivateKey(), password.toCharArray(), new Certificate[] { cert });
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ks.store(bos, password.toCharArray());

			byte[] keystore = bos.toByteArray();
			bos.close();

			return new KeystoreCredentialsHolder(keystore, credential);
		} catch (Exception e) {
			log.error("Unable to generate credential", e);
			throw new RuntimeException("Unable to generate credential", e);
		}
	}

	public static final class KeystoreCredentialsHolder {
		private final byte[] keystore;
		private final Credential credential;

		public KeystoreCredentialsHolder(byte[] keystore, Credential credential) {
			super();
			this.keystore = keystore;
			this.credential = credential;
		}

		public byte[] getKeystore() {
			return keystore;
		}

		public Credential getCredential() {
			return credential;
		}
	}

	public static EntityDescriptor generateSPDescriptor(String baseUrl, String entityId, Credential credential, String orgName, String orgUrl, String email, boolean enableArtifact, boolean enableRedirect, boolean enableSoap, boolean enablePostSLO, boolean supportOCESAttributes) {
		EntityDescriptor descriptor = SAMLUtil.buildXMLObject(EntityDescriptor.class);
		descriptor.setEntityID(entityId);

		SPSSODescriptor spDescriptor = SAMLUtil.buildXMLObject(SPSSODescriptor.class);
		spDescriptor.setAuthnRequestsSigned(true);
		spDescriptor.setWantAssertionsSigned(true);

		ContactPerson contact = SAMLUtil.buildXMLObject(ContactPerson.class);
		contact.getEmailAddresses().add(SAMLUtil.createEmail(email));
		contact.setCompany(SAMLUtil.createCompany(orgName));
		contact.setType(ContactPersonTypeEnumeration.TECHNICAL);

		descriptor.getContactPersons().add(contact);
		descriptor.setOrganization(SAMLUtil.createOrganization(orgName, orgName, orgUrl));

		KeyDescriptor signingDescriptor = SAMLUtil.buildXMLObject(KeyDescriptor.class);
		signingDescriptor.setUse(UsageType.SIGNING);
		KeyDescriptor encryptionDescriptor = SAMLUtil.buildXMLObject(KeyDescriptor.class);
		encryptionDescriptor.setUse(UsageType.ENCRYPTION);

		try {
			KeyInfoGenerator gen = SecurityHelper.getKeyInfoGenerator(credential, org.opensaml.xml.Configuration.getGlobalSecurityConfiguration(), null);
			signingDescriptor.setKeyInfo(gen.generate(credential));
			encryptionDescriptor.setKeyInfo(gen.generate(credential));
		} catch (SecurityException e1) {
			throw new WrappedException(Layer.BUSINESS, e1);
		}
		spDescriptor.getKeyDescriptors().add(signingDescriptor);
		spDescriptor.getKeyDescriptors().add(encryptionDescriptor);

		spDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		spDescriptor.getAssertionConsumerServices().add(SAMLUtil.createAssertionConsumerService(baseUrl + "/SAMLAssertionConsumer", SAMLConstants.SAML2_POST_BINDING_URI, 0, true));
		if (enableArtifact) {
			spDescriptor.getAssertionConsumerServices().add(SAMLUtil.createAssertionConsumerService(baseUrl + "/SAMLAssertionConsumer", SAMLConstants.SAML2_ARTIFACT_BINDING_URI, 1, false));
		}
		if (enableRedirect) {
			spDescriptor.getAssertionConsumerServices().add(SAMLUtil.createAssertionConsumerService(baseUrl + "/SAMLAssertionConsumer", SAMLConstants.SAML2_REDIRECT_BINDING_URI, 2, false));
		}

		spDescriptor.getSingleLogoutServices().add(SAMLUtil.createSingleLogoutService(baseUrl + "/LogoutServiceHTTPRedirect", baseUrl + "/LogoutServiceHTTPRedirectResponse", SAMLConstants.SAML2_REDIRECT_BINDING_URI));

		if (enableSoap) {
			spDescriptor.getSingleLogoutServices().add(SAMLUtil.createSingleLogoutService(baseUrl + "/LogoutServiceSOAP", null, SAMLConstants.SAML2_SOAP11_BINDING_URI));
		}

		if(enablePostSLO) {
			spDescriptor.getSingleLogoutServices().add(SAMLUtil.createSingleLogoutService(baseUrl + "/LogoutServiceHTTPPost", baseUrl + "/LogoutServiceHTTPRedirectResponse", SAMLConstants.SAML2_POST_BINDING_URI));
		}

		NameIDFormat x509SubjectNameIDFormat = SAMLUtil.createNameIDFormat(OIOSAMLConstants.NAMEIDFORMAT_X509SUBJECTNAME);
		List<NameIDFormat> nameIDFormats = spDescriptor.getNameIDFormats();
		nameIDFormats.add(x509SubjectNameIDFormat);

		if (enableArtifact) {
			spDescriptor.getArtifactResolutionServices().add(SAMLUtil.createArtifactResolutionService(baseUrl + "/SAMLAssertionConsumer"));
		}

		if (supportOCESAttributes) {
			addAttributeConsumerService(spDescriptor, entityId);
		}

		descriptor.getRoleDescriptors().add(spDescriptor);
		return descriptor;
	}

	private static void addAttributeConsumerService(SPSSODescriptor spDescriptor, String serviceName) {
		AttributeConsumingService service = SAMLUtil.createAttributeConsumingService(serviceName);

		String[] required = {
				OIOSAMLConstants.ATTRIBUTE_SURNAME_NAME,
				OIOSAMLConstants.ATTRIBUTE_COMMON_NAME_NAME,
				OIOSAMLConstants.ATTRIBUTE_UID_NAME,
				OIOSAMLConstants.ATTRIBUTE_MAIL_NAME,
				OIOSAMLConstants.ATTRIBUTE_ASSURANCE_LEVEL_NAME,
				OIOSAMLConstants.ATTRIBUTE_SPECVER_NAME,
				OIOSAMLConstants.ATTRIBUTE_SERIAL_NUMBER_NAME,
				OIOSAMLConstants.ATTRIBUTE_YOUTH_CERTIFICATE_NAME,
				OIOSAMLConstants.ATTRIBUTE_CERTIFICATE_ISSUER,
		};

		String[] optional = {
				OIOSAMLConstants.ATTRIBUTE_UNIQUE_ACCOUNT_KEY_NAME,
				OIOSAMLConstants.ATTRIBUTE_CVR_NUMBER_IDENTIFIER_NAME,
				OIOSAMLConstants.ATTRIBUTE_ORGANISATION_NAME_NAME,
				OIOSAMLConstants.ATTRIBUTE_ORGANISATION_UNIT_NAME,
				OIOSAMLConstants.ATTRIBUTE_TITLE_NAME,
				OIOSAMLConstants.ATTRIBUTE_POSTAL_ADDRESS_NAME,
				OIOSAMLConstants.ATTRIBUTE_PSEUDONYM_NAME,
				OIOSAMLConstants.ATTRIBUTE_USER_CERTIFICATE_NAME,
				OIOSAMLConstants.ATTRIBUTE_PID_NUMBER_IDENTIFIER_NAME,
				OIOSAMLConstants.ATTRIBUTE_CPR_NUMBER_NAME,
				OIOSAMLConstants.ATTRIBUTE_RID_NUMBER_IDENTIFIER_NAME,
		};
		for (String attr : required) {
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute(attr, OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, true));
		}
		for (String attr : optional) {
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute(attr, OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
		}

		spDescriptor.getAttributeConsumingServices().add(service);
	}
}
