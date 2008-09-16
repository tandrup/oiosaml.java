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
package dk.itst.oiosaml.sp;

import java.io.Serializable;

public class UserAttribute implements Serializable{

	private static final long serialVersionUID = 7213348395041737852L;

	private final String name;
	private final String friendlyName;
	private final String value;
	private final String format;
	
	public UserAttribute(String name, String friendlyName, String value, String format) {
		super();
		this.name = name;
		this.friendlyName = friendlyName;
		this.value = value;
		this.format = format;
	}

	public String getName() {
		return name;
	}

	public String getFriendlyName() {
		return friendlyName;
	}

	public String getValue() {
		return value;
	}
	
	public String getFormat() {
		return format;
	}
	
	public static UserAttribute create(String name, String format) {
		if (format != null && format.trim().equals("")) {
			format = null;
		}
		return new UserAttribute(name, null, null, format);
	}

	@Override
	public String toString() {
		return name + " (" + friendlyName + "): " + value;
	}
}
