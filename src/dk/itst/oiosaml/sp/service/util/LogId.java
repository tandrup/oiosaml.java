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

import java.io.Serializable;

import dk.itst.oiosaml.logging.LogUtil;

/**
 * Utility structure for storing a SAML id and an optional associated timer
 * object {@link LogUtil} associated with the id. The timer object is used to
 * measure the time from a given HTTP Redirect call is sent to the response is
 * received by the relevant servlet.
 * 
 * @author Kim Kenneth Moes, Capgemini
 */
public class LogId implements Serializable {

	private static final long serialVersionUID = -7103043020587344707L;
	public static final String VERSION = "$Id: LogId.java 2829 2008-05-13 12:11:31Z jre $";

	private final String id;
	private final LogUtil lu;

	/**
	 * Create the association between a SAML id and a timer object
	 * 
	 * @param id
	 *            The SAML id
	 * @param lu
	 *            The timer object
	 */
	public LogId(String id, LogUtil lu) {
		super();
		this.id = id;
		this.lu = lu;
	}

	public String getId() {
		return id;
	}

	public LogUtil getLu() {
		return lu;
	}
}
