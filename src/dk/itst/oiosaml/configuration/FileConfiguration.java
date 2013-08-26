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
 *   Aage Nielsen <ani@openminds.dk>
 *   Carsten Larsen <cas@schultz.dk>
 *
 */
package dk.itst.oiosaml.configuration;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.log4j.Logger;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.XMLObject;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.sp.service.SPFilter;
import dk.itst.oiosaml.sp.service.util.Constants;

/**
 * Utility class to obtain a handle to all property values within the current project.
 * 
 * @author Joakim Recht <jre@trifork.com>
 * @author Rolf Njor Jensen <rolf@trifork.com>
 * @author Aage Nielsen <ani@openminds.dk>
 * @author Carsten Larsen <cas@schultz.dk>
 * 
 */
public class FileConfiguration extends SAMLConfiguration {
	private static final Logger log = Logger.getLogger(FileConfiguration.class);
	private String homeDir;
	private String configurationFileName;
	private Configuration systemConfiguration;

	/**
	 * Get the current system configuration. The configuration is stored in
	 * {@link SAMLUtil#OIOSAML_HOME}. The property is normally set in
	 * {@link SPFilter}.
	 * 
	 * @throws IllegalStateException
	 *             When the system has not been configured properly yet.
	 */
	public Configuration getSystemConfiguration() throws IllegalStateException {
		if (systemConfiguration != null)
			return systemConfiguration;
		if (homeDir == null || !isConfigured()) {
			throw new IllegalStateException("System not configured");
		}

		CompositeConfiguration conf = new CompositeConfiguration();
		conf.setProperty("oiosaml.home", homeDir);

		try {
			conf.addConfiguration(new PropertiesConfiguration(new File(homeDir, configurationFileName)));
			conf.addConfiguration(getCommonConfiguration());

			systemConfiguration = conf;
			return systemConfiguration;
		} catch (ConfigurationException e) {
			log.error("Cannot load the configuration file", e);
			throw new WrappedException(Layer.DATAACCESS, e);
		} catch (IOException e) {
			log.error("Unable to load oiosaml-common.propeties from classpath", e);
			throw new WrappedException(Layer.DATAACCESS, e);
		}		
	}

	public Configuration getCommonConfiguration() throws IOException {
		CompositeConfiguration conf = new CompositeConfiguration();
		Enumeration<URL> resources = SAMLConfiguration.class.getClassLoader().getResources("oiosaml-common.properties");
		while (resources.hasMoreElements()) {
			URL u = resources.nextElement();
			log.debug("Loading config from " + u);
			try {
				conf.addConfiguration(new PropertiesConfiguration(u));
			} catch (ConfigurationException e) {
				log.error("Cannot load the configuration file", e);
				throw new WrappedException(Layer.DATAACCESS, e);
			}
		}

		return conf;
	}

	public boolean isConfigured() {
		if (homeDir == null)
			return false;

		log.info("Config filename: " + homeDir + configurationFileName);
		File config = new File(homeDir + configurationFileName);

		log.info("Looking in : " + config.getAbsolutePath());
		return config.exists();
	}

	public KeyStore getKeystore() throws WrappedException {
		KeyStore keystore=null;		

		String keystoreFileName = (homeDir==null) ? getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_LOCATION):homeDir + getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_LOCATION);
		try {
			InputStream input=new FileInputStream(keystoreFileName);
			input = new BufferedInputStream(input);
			input.mark(1024*1024);
			try {
				keystore = loadStore(input, getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_PASSWORD), "PKCS12");
			} catch (IOException e) {
				log.debug("Keystore is not of type 'PCKS12' Trying type 'JKS'." );
				try {
					input.reset();
					keystore = loadStore(input, getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_PASSWORD), "JKS");
				} catch (IOException ioe) {
					log.error("Unable to find keystore file. Looking for: " + keystoreFileName);
					throw new WrappedException(Layer.DATAACCESS, ioe);
				} catch (Exception ec) {
					log.error("Exception occured while processing keystore: " + keystoreFileName);
					throw new WrappedException(Layer.DATAACCESS, ec);
				} 
			} catch (Exception ex) {
				log.error("Exception occured while processing keystore: " + keystoreFileName);
				throw new WrappedException(Layer.DATAACCESS, ex);
			}

		} catch (FileNotFoundException e) {
			log.error("Unable to find keystore file. Looking for: " + keystoreFileName);
			throw new WrappedException(Layer.DATAACCESS, e);
		}
		return keystore;
	}

	private KeyStore loadStore(InputStream input, String password, String type) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore ks = KeyStore.getInstance(type);
		char[] jksPassword = password.toCharArray();
		ks.load(input, jksPassword);
		input.close();
		return ks;
	}

	public InputStream getLoggerConfiguration() throws WrappedException {
		InputStream logConfigurationFile = null;
		String logFileName = homeDir + getSystemConfiguration().getString(Constants.PROP_LOG_FILE_NAME);
		try {
			logConfigurationFile = new FileInputStream(logFileName);
		} catch (FileNotFoundException e) {
			log.error("Unable to find log file. Tries to look for: " + logFileName);
			throw new WrappedException(Layer.DATAACCESS, e);
		}
		return logConfigurationFile;
	}

	public XMLObject getSPMetaData() throws WrappedException {
		String filename= getSystemConfiguration().getString(Constants.SP_METADATA_FILE);
		String directory = homeDir + getSystemConfiguration().getString(Constants.SP_METADATA_DIRECTORY);
		String spMetadataFileName= directory + "/" + filename;

		XMLObject unmarshallElementFromFile = null;
		try {
			unmarshallElementFromFile = SAMLUtil.unmarshallElementFromFile(spMetadataFileName);
		} catch (Exception e) {
			log.error("Unable to find SP metadata file. Tries to look for: " + spMetadataFileName);
			throw new WrappedException(Layer.DATAACCESS, e);
		}
		return unmarshallElementFromFile;
	}	

	public List<XMLObject> getListOfIdpMetadata() throws WrappedException {
		List<XMLObject> descriptors = new ArrayList<XMLObject>();
		String protocol = getSystemConfiguration().getString(Constants.PROP_PROTOCOL);
		if (getSystemConfiguration().getString(Constants.IDP_METADATA_FILE)!= null) {
			String idpFileName = homeDir + getSystemConfiguration().getString(Constants.IDP_METADATA_DIRECTORY)+"/"+getSystemConfiguration().getString(Constants.IDP_METADATA_FILE);
			File md = new File(idpFileName);
			log.info("Loading " + protocol + " metadata from " + md);
			try {
				XMLObject descriptor = SAMLUtil.unmarshallElementFromFile(md.getAbsolutePath());
				if (descriptor instanceof EntityDescriptor) {
					descriptors.add((EntityDescriptor) descriptor);
				} else if (descriptor instanceof EntitiesDescriptor) {
					EntitiesDescriptor desc = (EntitiesDescriptor) descriptor;
					descriptors.addAll(desc.getEntityDescriptors());
				} else {
					throw new RuntimeException("Metadata file " + md + " does not contain an EntityDescriptor. Found " + descriptor.getElementQName() + ", expected " + EntityDescriptor.ELEMENT_QNAME);
				}
			} catch (RuntimeException e) {
				log.error("Unable to load metadata from " + md + ". File must contain valid XML and have EntityDescriptor as top tag", e);
				throw e;
			}
		} else {
			String directory = homeDir + getSystemConfiguration().getString(Constants.IDP_METADATA_DIRECTORY);
			File idpDir = new File(directory);
			File[] files = idpDir.listFiles(new FilenameFilter() {
				public boolean accept(File dir, String name) {
					return name.toLowerCase().endsWith(".xml");
				}
			});
			if (files != null) {
				for (File md : files) {
					log.info("Loading " + protocol + " metadata from " + md);
					try {
						XMLObject descriptor = SAMLUtil.unmarshallElementFromFile(md.getAbsolutePath());
						if (descriptor instanceof EntityDescriptor) {
							descriptors.add((EntityDescriptor) descriptor);
						} else if (descriptor instanceof EntitiesDescriptor) {
							EntitiesDescriptor desc = (EntitiesDescriptor) descriptor;
							descriptors.addAll(desc.getEntityDescriptors());
						} else {
							throw new RuntimeException("Metadata file " + md + " does not contain an EntityDescriptor. Found " + descriptor.getElementQName() + ", expected " + EntityDescriptor.ELEMENT_QNAME);
						}
					} catch (RuntimeException e) {
						log.error("Unable to load metadata from " + md + ". File must contain valid XML and have EntityDescriptor as top tag", e);
						throw e;
					}
				}
			}
		}
		if (descriptors.isEmpty()) {
			throw new IllegalStateException("No IdP descriptors found in ! At least one file is required.");
		}
		return descriptors;
	}

	public void setInitConfiguration(Map<String, String> params) {
		systemConfiguration=null;
		if (params != null) {
			if (params.containsKey(Constants.INIT_OIOSAML_FILE)) {
				setupHomeAndFile(params.get(Constants.INIT_OIOSAML_FILE));
			} else {
				String p = params.get(Constants.INIT_OIOSAML_HOME);
				if ((p!=null) && (!p.endsWith("/")))
					p = p + "/";
				homeDir = p;
				configurationFileName = params.get(Constants.INIT_OIOSAML_NAME);
			}
		}
	}

	private void setupHomeAndFile(String configurationFile) {
		if (configurationFile != null) {
			int lastPathSeperatorIndex = configurationFile.lastIndexOf("/") + 1;
			configurationFileName = configurationFile.substring((lastPathSeperatorIndex), configurationFile.length());
			homeDir = configurationFile.substring(0, lastPathSeperatorIndex);
		}
	}

	public void setConfiguration(Configuration configuration) {
		systemConfiguration=configuration;
	}
}