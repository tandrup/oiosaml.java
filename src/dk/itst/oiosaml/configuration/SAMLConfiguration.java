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
 * created by Trifork A/S are Copyright (C) 2013 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Aage Nielsen <ani@openminds.dk>
 *   Carsten Larsen <cas@schultz.dk>
 *
 */
package dk.itst.oiosaml.configuration;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;

import org.apache.commons.configuration.Configuration;
import org.opensaml.xml.XMLObject;

import dk.itst.oiosaml.error.WrappedException;

/**
 * Interface defining a configuration.
 * 
 * @author Aage Nielsen <ani@openminds.dk>
 * @author Carsten Larsen <cas@schultz.dk>
 * 
 */
public abstract class SAMLConfiguration {

	String home = null;

	public abstract boolean isConfigured();

	public abstract Configuration getSystemConfiguration();

	public abstract KeyStore getKeystore() throws WrappedException, NoSuchAlgorithmException, CertificateException, IllegalStateException, IOException, KeyStoreException;

	public abstract List<XMLObject> getListOfIdpMetadata();

	public abstract XMLObject getSPMetaData();

	public abstract Configuration getCommonConfiguration() throws IOException;

	public abstract InputStream getLoggerConfiguration() throws WrappedException;

	public abstract void setConfiguration(Configuration configuration);

	public abstract void setInitConfiguration(Map<String, String> params);
}
