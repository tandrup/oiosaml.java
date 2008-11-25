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
package dk.itst.oiosaml.security;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.log4j.Logger;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;

import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;

/**
 * Class for managing credentials.
 * 
 * Credentials can be loaded from the file system. When loaded, credentials are cached, so they are only loaded once.
 * 
 * This class is thread-safe, and can be shared across threads.
 * 
 * @author recht
 *
 */
public class CredentialRepository {
	private static final Logger log = Logger.getLogger(CredentialRepository.class);
	
	private final Map<Key, BasicX509Credential> credentials = new ConcurrentHashMap<Key, BasicX509Credential>();
	
	/**
	 * Load credentials from a keystore.
	 * 
	 * The first private key is loaded from the keystore.
	 * 
	 * @param location keystore file location
	 * @param password Keystore and private key password. 
	 */
	public BasicX509Credential getCredential(String location, String password) {
		Key key = new Key(location, password);
		BasicX509Credential credential = credentials.get(key);
		if (credential == null) {
			try {
				FileInputStream is = new FileInputStream(location);
				credential = createCredential(is, password);
				credentials.put(key, credential);
			} catch (FileNotFoundException e) {
				throw new WrappedException(Layer.CLIENT, e);
			}
		}
		return credential;
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
			KeyStore ks = loadKeystore(input, password);

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

	private static KeyStore loadKeystore(InputStream input, String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		input = new BufferedInputStream(input);
		input.mark(1024*1024);
		KeyStore ks;
		try {
			ks = loadStore(input, password, "PKCS12");
		} catch (IOException e) {
			input.reset();
			ks = loadStore(input, password, "JKS");
		}
		return ks;
	}

	/**
	 * Get a x509certificate from a keystore.
	 * 
	 * @param location Keystore file location.
	 * @param password Password for the keystore.
	 * @param alias Alias to retrieve. If <code>null</code>, the first certificate in the keystore is retrieved.
	 * @return The certificate.
	 */
	public X509Certificate getCertificate(String location, String password, String alias) {
		Key key = new Key(location, password, alias);
		BasicX509Credential credential = credentials.get(key);
		if (credential == null) {
			try {
				KeyStore keystore = loadKeystore(new FileInputStream(location), password);
				
				if (alias == null) {
					Enumeration<String> eAliases = keystore.aliases();
					while (eAliases.hasMoreElements()) {
						String strAlias = eAliases.nextElement();
						log.debug("Trying " + strAlias);
						if (keystore.isCertificateEntry(strAlias)) {
							alias = strAlias;
						}
					}			
				}
				log.debug("Getting certificate from alias " + alias);
				if (alias == null) {
					throw new NullPointerException("No valid certificate alias found in " + location);
				}
				X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
				if (certificate == null) {
					throw new RuntimeException("Keystore " + location + " does not contain a certificate with alias " + alias);
				}
				credential = new BasicX509Credential();
				credential.setEntityCertificate(certificate);
				credentials.put(key, credential);
			} catch (GeneralSecurityException e) {
				throw new WrappedException(Layer.CLIENT, e);
			} catch (IOException e) {
				throw new WrappedException(Layer.CLIENT, e);
			}
		}
		return credential.getEntityCertificate();
	}

	private static KeyStore loadStore(InputStream input, String password, String type) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		KeyStore ks = KeyStore.getInstance(type);
		char[] jksPassword = password.toCharArray();
		ks.load(input, jksPassword);
		input.close();
		return ks;
	}

	private static class Key {
		private final String location;
		private final String password;
		private final String alias;
		
		public Key(String location, String password) {
			this.location = location;
			this.password = password;
			this.alias = null;
		}
		
		public Key(String location, String password, String alias) {
			this.location = location;
			this.password = password;
			this.alias = alias;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((alias == null) ? 0 : alias.hashCode());
			result = prime * result + ((location == null) ? 0 : location.hashCode());
			result = prime * result + ((password == null) ? 0 : password.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) return true;
			if (obj == null) return false;
			if (getClass() != obj.getClass()) return false;
			Key other = (Key) obj;
			if (alias == null) {
				if (other.alias != null) return false;
			} else if (!alias.equals(other.alias)) return false;
			if (location == null) {
				if (other.location != null) return false;
			} else if (!location.equals(other.location)) return false;
			if (password == null) {
				if (other.password != null) return false;
			} else if (!password.equals(other.password)) return false;
			
			return true;
		}
		
		
	}

}
