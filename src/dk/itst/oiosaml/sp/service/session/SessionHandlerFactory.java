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
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.sp.service.session;

import org.apache.commons.configuration.Configuration;
import org.apache.log4j.Logger;

import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;

public class SessionHandlerFactory {
	private static final Logger log = Logger.getLogger(SessionHandlerFactory.class);

	public static SessionHandler newInstance(Configuration configuration) {
		if (configuration == null) return null;
		
		String name = configuration.getString(Constants.PROP_SESSION_HANDLER);
		if (log.isDebugEnabled()) log.debug("Using session handler class: " + name);
		
		SessionHandler handler = (SessionHandler) Utils.newInstance(configuration, Constants.PROP_SESSION_HANDLER);
		return handler;
	}
}
