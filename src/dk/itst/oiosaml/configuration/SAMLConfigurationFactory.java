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
 *  2012 Danish National IT and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Aage Nielsen <ani@openminds.dk>
 *
 */
package dk.itst.oiosaml.configuration;

import java.util.Iterator;
import java.util.ServiceLoader;

import org.apache.log4j.Logger;

/**
 * This factory returns the configuration from the META-INF/services/dk.itst.oiosaml.configuration.SAMLConfiguration file. Default is {@link #FileConfiguration}.
 * 
 * To change what implementation to use - just change the file from above with another classname.
 * 
 * @author Aage Nielsen <ani@openminds.dk>
 *
 */
public class SAMLConfigurationFactory {
	private static final Logger log = Logger.getLogger(SAMLConfigurationFactory.class);

	private static SAMLConfiguration configuration;
	
	public static SAMLConfiguration getConfiguration() {
		if (configuration==null) {
			ServiceLoader<SAMLConfiguration> configurationImplementations = ServiceLoader.load(SAMLConfiguration.class);
			for (Iterator iterator = configurationImplementations.iterator(); iterator.hasNext();) {
				configuration = (SAMLConfiguration) iterator.next();
				if (iterator.hasNext()) {
					log.error("Appears to be more than one configuration implementation. Please check META-INF/services for occurencies. Choosing the implementation: "+configuration.getClass().getName());
					break;
				}
			}
		}
		return configuration;
	}
}
