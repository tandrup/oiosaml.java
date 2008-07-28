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

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.configuration.Configuration;

/**
 * Utility class for handling HTTP requests and responses.
 * 
 * @author Joakim Recht <jre@trifork.com>
 *
 */
public class HTTPUtils {
	
	private HTTPUtils() {}

	
	/**
	 * Send a redirect using a meta tag.
	 * 
	 * @param res Http response object.
	 * @param url URL to redirect to.
	 * @throws IOException
	 */
	public static void sendMetaRedirect(HttpServletResponse res, String url, String query) throws IOException {
		res.setContentType("text/html");

		PrintWriter w = res.getWriter();
		w.write("<html><head>");
		w.write("<meta http-equiv=\"refresh\" content=\"0;url=");
		w.write(url);
		if (query != null) {
			if (url.contains("?")) {
				w.write("&");
			} else {
				w.write("?");
			}
			w.write(query);
		}
		w.write("\">");
		w.write("</head><body></body></html>");
	}
	
	/**
	 * Build the original request uri, as set when the user was redirected to the IdP.
	 * @param session Session object containing {@link Constants#SESSION_REQUESTURI} and {@link Constants#SESSION_QUERYSTRING}.
	 * @param config Configuration where default url is read at {@link Constants#PROP_HOME}.
	 */
	public static String buildRedirectUrl(HttpSession session, Configuration config) {
		// Redirect the user to the original URI
		String redirectURI = (String) session.getAttribute(Constants.SESSION_REQUESTURI);
		String queryString = (String) session.getAttribute(Constants.SESSION_QUERYSTRING);
		if (null != queryString && !"".equals(queryString)) {
			redirectURI += "?" + queryString;
		}

		if (redirectURI == null) { 
			redirectURI = config.getString(Constants.PROP_HOME);
		}
		return redirectURI;
	}
}
