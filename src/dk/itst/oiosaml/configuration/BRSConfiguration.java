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
package dk.itst.oiosaml.configuration;

import java.io.File;
import java.net.URL;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.ConfigurationFactory;
import org.apache.log4j.Logger;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.sp.service.SPFilter;

/**
 * Utility class to obtain a handle to all property values within the current project.
 * 
 * 
 * @author Joakim Recht <jre@trifork.com>
 * @author Rolf Njor Jensen <rolf@trifork.com>
 *
 */
public class BRSConfiguration {
	private static final String CONFIGURATION_FILE = "/config.xml";
	private static final Logger log = Logger.getLogger(BRSConfiguration.class);
	public static final String VERSION = "$Id: BRSConfiguration.java 2941 2008-05-26 09:14:03Z jre $";
	private static Configuration systemConfiguration;
	
	/**
	 * Get the current system configuration. 
	 * The configuration is stored in {@link SAMLUtil#OIOSAML_HOME}. The property is normally set in {@link SPFilter}.
	 * @throws IllegalStateException When the system has not been configured properly yet.
	 */
	public static Configuration getSystemConfiguration() throws IllegalStateException {
		if (systemConfiguration != null) return systemConfiguration;

		if (System.getProperty(SAMLUtil.OIOSAML_HOME) == null || !isConfigured(System.getProperty(SAMLUtil.OIOSAML_HOME))) {
			throw new IllegalStateException("System not configured");
		}
		ConfigurationFactory factory = new ConfigurationFactory();
		URL configURL = BRSConfiguration.class.getResource(CONFIGURATION_FILE);
		factory.setConfigurationURL(configURL);
		try {
			systemConfiguration = factory.getConfiguration();
			return systemConfiguration;
		} catch (ConfigurationException e) {
			log.error("Cannot load the configuration file: "+CONFIGURATION_FILE);
			throw new WrappedException(Layer.DATAACCESS, e);
		}		
	}
	
	public static String getStringPrefixedWithBRSHome(Configuration conf, String key) {
		return conf.getString(SAMLUtil.OIOSAML_HOME)+"/"+conf.getString(key);
	}

	public static boolean setHomeProperty(String home) {
		if (home != null) {
			System.setProperty(SAMLUtil.OIOSAML_HOME, home);
			return true;
		} else {
			home = System.getProperty("user.home") + "/.oiosaml";
			System.setProperty(SAMLUtil.OIOSAML_HOME, home);
			File h = new File(home);
			if (h.exists() && !h.isDirectory()) {
				throw new IllegalStateException(home + " is not a directory");
			} else if (!h.exists()) {
				log.info("Creating empty config dir in " + home);
				if (!h.mkdir()) {
					throw new IllegalStateException(h + " could not be created");
				}
			}
			
			return false;
		}
	}

	public static boolean isConfigured(String home) {
		if(home == null) return false;
		File homeDir = new File(home);
		if(homeDir.exists() && homeDir.isDirectory()) {
			String[] files = homeDir.list();
			if (files == null || files.length > 0) {
				return true;
			}
		}
		return false;
	}
	
	public static void setSystemConfiguration(Configuration conf) {
		systemConfiguration = conf;
	}
}