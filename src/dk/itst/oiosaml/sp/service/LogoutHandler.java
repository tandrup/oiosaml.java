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
package dk.itst.oiosaml.sp.service;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;

import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.model.OIOLogoutRequest;
import dk.itst.oiosaml.sp.service.session.LoggedInHandler;
import dk.itst.oiosaml.sp.service.util.Constants;

public class LogoutHandler implements SAMLHandler{

	private static final long serialVersionUID = 3843822219113371749L;
	public static final String VERSION = "$Id: LogoutHandler.java 2950 2008-05-28 08:22:34Z jre $";
	private static final Logger log = Logger.getLogger(LogoutHandler.class);
		
	/**
	 * Send a &lt;LogoutRequest&gt; to the Login Site and start a SLO.
	 */
	public void handleGet(RequestContext context) throws ServletException, IOException {

		HttpSession session = context.getSession();
		context.getLogUtil().audit("sessionId", session.getId());

		// Check that user is logged in...
		if (!LoggedInHandler.getInstance().isLoggedIn(session)) {
			String homeUrl = context.getConfiguration().getString(Constants.PROP_HOME, context.getRequest().getContextPath());
			context.getResponse().sendRedirect(homeUrl);
			return;
		}
		String entityID = LoggedInHandler.getInstance().getAuthenticatingEntityID(session.getId());
		Metadata metadata = context.getIdpMetadata().getMetadata(entityID);

		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, context.getLogUtil(), metadata.getSingleLogoutServiceLocation(), context.getSpMetadata().getEntityID());
		String redirectURL = lr.getRedirectRequestURL(context.getCredential(), context.getLogUtil());

		LoggedInHandler.getInstance().registerRequest(lr.getID(), metadata.getEntityID());
		LoggedInHandler.getInstance().logOut(session);

		if (log.isDebugEnabled()) log.debug("Redirect to..:" + redirectURL);
		context.getLogUtil().audit("User logged out locally");

		context.getResponse().sendRedirect(redirectURL);
	}

	public void handlePost(RequestContext context) throws ServletException, IOException {
		throw new UnsupportedOperationException();
	}

}
