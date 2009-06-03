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
import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.io.FileUtils;
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
public class SAMLConfiguration {
	private static String name = "oiosaml-sp";
	
	private static final Logger log = Logger.getLogger(SAMLConfiguration.class);
	private static Configuration systemConfiguration;
	
	private static String home;
	
	/**
	 * Get the current system configuration. 
	 * The configuration is stored in {@link SAMLUtil#OIOSAML_HOME}. The property is normally set in {@link SPFilter}.
	 * @throws IllegalStateException When the system has not been configured properly yet.
	 */
	public static Configuration getSystemConfiguration() throws IllegalStateException {
		if (systemConfiguration != null) return systemConfiguration;

		if (home == null || !isConfigured()) {
			throw new IllegalStateException("System not configured");
		}
		
		CompositeConfiguration conf = new CompositeConfiguration();
		conf.setProperty("oiosaml.home", home);
		
		try {
			conf.addConfiguration(new PropertiesConfiguration(new File(home, name + ".properties")));
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
	
	public static Configuration getCommonConfiguration() throws IOException {
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
	
	public static String getStringPrefixedWithBRSHome(Configuration conf, String key) {
		return conf.getString(SAMLUtil.OIOSAML_HOME)+"/"+conf.getString(key);
	}

	public static void setHomeProperty(String home) {
		if (home == null){
			home = System.getProperty("user.home") + "/.oiosaml";
		}
		
		File h = new File(home);
		if (h.exists() && !h.isDirectory()) {
			throw new IllegalStateException(home + " is not a directory");
		} else if (!h.exists()) {
			log.info("Creating empty config dir in " + home);
			try {
				FileUtils.forceMkdir(h);
			} catch (IOException e) {
				throw new IllegalStateException(h + " could not be created");
			}
		}
		log.info("oiosaml.home set to " + home);
		SAMLConfiguration.home = home;
	}

	public static boolean isConfigured() {
		if(home == null) return false;
		log.info("Config filename: "+name+".properties");
		File config = new File(home, name+".properties");
		return config.exists();
	}
	
	public static void setSystemConfiguration(Configuration conf) {
		systemConfiguration = conf;
	}
	
	public static void setConfigurationName(String name) {
		SAMLConfiguration.name = name;
	}
}