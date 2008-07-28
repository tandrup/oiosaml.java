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
package dk.itst.oiosaml.sp.service.util;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.Base64;

import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.sp.model.BRSSAMLConstants;

/**
 * Utility class used for signing SAML documents and verifying the signed
 * documents received from the Login Site
 * 
 */
public final class Utils {

	public static final String VERSION = "$Id: Utils.java 3197 2008-07-25 07:47:33Z jre $";
	private static final Logger log = Logger.getLogger(Utils.class);


	/**
	 * @return The {@link Credential} associated with the certificate of the
	 *         service provider (SP)
	 */
	public static BasicX509Credential getCredential(String location, String password) {
		try {
			FileInputStream is = new FileInputStream(location);
			return createCredential(is, password);
		} catch (FileNotFoundException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}
	}

	/**
	 * Read credentials from a inputstream.
	 * 
	 * The stream can either point to a PKCS12 keystore or a JKS keystore.
	 * The store is converted into a {@link Credential} including the private key.
	 * @param input Stream pointing to the certificate store.
	 * @param password Password for the store. The same password is also used for the certificate.
	 * 
	 * @return The {@link Credential}
	 */
	public static BasicX509Credential createCredential(InputStream input, String password) {
		BasicX509Credential credential = new BasicX509Credential();

		try {
			input = new BufferedInputStream(input);
			input.mark(1024*1024);
			KeyStore ks;
			try {
				ks = loadStore(input, password, "PKCS12");
			} catch (IOException e) {
				input.reset();
				ks = loadStore(input, password, "JKS");
			}

			Enumeration<String> eAliases = ks.aliases();
			while (eAliases.hasMoreElements()) {
				String strAlias = eAliases.nextElement();

				if (ks.isKeyEntry(strAlias)) {
					PrivateKey privateKey = (PrivateKey) ks.getKey(strAlias, password.toCharArray());
					credential.setPrivateKey(privateKey);
					credential.setEntityCertificate((X509Certificate) ks.getCertificate(strAlias));
					PublicKey publicKey = ks.getCertificate(strAlias).getPublicKey();
					if (log.isDebugEnabled())
						log.debug("publicKey..:" + publicKey + ", privateKey: " + privateKey);
					credential.setPublicKey(publicKey);
				}
			}
		} catch (GeneralSecurityException e) {
			throw new WrappedException(Layer.CLIENT, e);
		} catch (IOException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}
		return credential;
	}

	private static KeyStore loadStore(InputStream input, String password, String type) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		KeyStore ks = KeyStore.getInstance(type);
		char[] jksPassword = password.toCharArray();
		ks.load(input, jksPassword);
		input.close();
		return ks;
	}

	/**
	 * Making nice XML for output in browser, i.e. converting &lt; to &amp;lt;, &gt; to
	 * &amp;gt; etc.
	 */
	public static String makeXML(String param) {
		String xml = param;
		if (xml != null && !"".equals(xml)) {
			xml = xml.replaceAll("><", ">\n<");
			xml = xml.replaceAll("<", "&lt;");
			xml = xml.replaceAll(">", "&gt;");
			xml = xml.replaceAll("\n", "<br />");
		}
		return xml;
	}

	/**
	 * @return true if the queryString in the request has been signed correctly
	 *         by the Login Site
	 */
	public static boolean verifySignature(String signature, String queryString, String firstQueryParameter, PublicKey publicKey) {
		// Verifying the signature....
		if (log.isDebugEnabled())
			log.debug("signature..:" + signature);
		if (signature == null) {
			return false;
		}

		byte[] buffer = Base64.decode(signature);
		if (log.isDebugEnabled())
			log.debug("buffer.....:" + buffer);

        String data = queryString.substring(queryString.indexOf(firstQueryParameter), queryString.lastIndexOf("&"));
		if (log.isDebugEnabled())
			log.debug("data.......:" + data);

		if (log.isDebugEnabled())
			log.debug("Verifying Signature...");
		
		return verifySignature(data.getBytes(), publicKey, buffer);
	}

	/**
	 * Check if a SAML HTTP Redirect has been signed by the expected certificate
	 * 
	 * @param data
	 *            The query parameters in the HTTP Redirect, which has been
	 *            signed
	 * @param key
	 *            The public key of the certificate from the expected sender
	 * @param sig
	 *            The signature generated by the sender after it has been base64
	 *            decoded
	 * @return true, if the signature is valid, otherwise false
	 */
	public static boolean verifySignature(byte[] data, PublicKey key, byte[] sig) {

		if (log.isDebugEnabled())
			log.debug("data...:" + data);
		if (log.isDebugEnabled())
			log.debug("sig....:" + sig);
		if (log.isDebugEnabled())
			log.debug("key....:" + key.toString());

		try {
			Signature signer = Signature.getInstance(BRSSAMLConstants.SHA1_WITH_RSA);
			signer.initVerify(key);
			signer.update(data);
			return signer.verify(sig);
		} catch (InvalidKeyException e) {
			throw new WrappedException(Layer.CLIENT, e);
		} catch (NoSuchAlgorithmException e) {
			throw new WrappedException(Layer.CLIENT, e);
		} catch (SignatureException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}
	}

	/**
	 * @return A beautified xml string
	 */
	public static String beautifyAndHtmlXML(String xml, String split) {
		return makeXML(beautifyXML(xml, split));
	}

	/**
	 * @return A beautified xml string
	 */
	public static String beautifyXML(String xml, String split) {
		String s = "";
		if (split != null)
			s = ".:split:.";

		if (xml == null || "".equals(xml))
			return xml;

		String result = "";

		String[] results = xml.split("<");
		for (int i = 1; i < results.length; i++) {
			results[i] = "<" + results[i].trim();
			if (results[i].endsWith("/>")) {
				result += results[i] + s;
			} else if (results[i].startsWith("</")) {
				result += results[i] + s;
			} else if (results[i].endsWith(">")) {
				result += results[i] + s;
			} else {
				result += results[i];
			}
		}
		result = result.trim();

		if (split == null)
			return result;

		String newResult = "";
		String ident = "";
		results = result.split(s);
		for (int i = 0; i < results.length; i++) {
			if (results[i].startsWith("</"))
				ident = ident.substring(split.length());

			newResult += ident + results[i] + "\n";

			if (!results[i].startsWith("<!") && !results[i].startsWith("<?")
					&& results[i].indexOf("</") == -1
					&& results[i].indexOf("/>") == -1)
				ident += split;
		}
		return newResult;
	}
	
	/**
	 * Generate a valid xs:ID string.
	 */
	public static String generateUUID() {
		return "_" + UUID.randomUUID().toString();
	}
}
