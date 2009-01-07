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

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

public class Request {
	
	private final String requestURI;
	private final String queryString;
	private final String method;
	private final Map<String, String[]> parameters;

	public Request(String requestURI, String queryString, String method, Map<String, String[]> parameters) {
		this.requestURI = requestURI;
		this.queryString = queryString;
		this.method = method;
		this.parameters = parameters;
	}
	
	@SuppressWarnings("unchecked")
	public static Request fromHttpRequest(HttpServletRequest req) {
		return new Request(req.getRequestURI(), req.getQueryString(), req.getMethod(), req.getParameterMap());
	}
	

	public String getMethod() {
		return method;
	}
	
	public Map<String, String[]> getParameters() {
		return parameters;
	}
	
	public String getQueryString() {
		return queryString;
	}
	
	public String getRequestURI() {
		return requestURI;
	}
}
