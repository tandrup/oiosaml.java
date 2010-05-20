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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.opensaml.saml2.core.StatusCode;

import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.AuthenticationHandler;
import dk.itst.oiosaml.sp.LogoutAuthenticationHandler;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.OIOLogoutRequest;
import dk.itst.oiosaml.sp.model.OIOLogoutResponse;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.sp.util.LogoutRequestValidationException;

/**
 * Receive a LogoutRequest via HTTP  Redirect.
 * 
 * @author Joakim Recht <jre@trifork.com>
 *
 */
public class LogoutServiceHTTPRedirectHandler implements SAMLHandler {

	private static final long serialVersionUID = -6035256219067030678L;
	public static final String VERSION = "$Id: LogoutServiceHTTPRedirectHandler.java 2890 2008-05-16 16:18:56Z jre $";
	private static final Logger log = Logger.getLogger(LogoutServiceHTTPRedirectHandler.class);

	public void handleGet(RequestContext ctx) throws ServletException, IOException {
		HttpServletRequest request = ctx.getRequest();
		HttpSession session = ctx.getSession();

		String samlRequest = request.getParameter(Constants.SAML_SAMLREQUEST);
		String relayState = request.getParameter(Constants.SAML_RELAYSTATE);
		String sigAlg = request.getParameter(Constants.SAML_SIGALG);
		String sig = request.getParameter(Constants.SAML_SIGNATURE);

		if (log.isDebugEnabled()) {
			log.debug("samlRequest...:" + samlRequest);
			log.debug("relayState....:" + relayState);
			log.debug("sigAlg........:" + sigAlg);
			log.debug("signature.....:" + sig);
		}

		OIOLogoutRequest logoutRequest = OIOLogoutRequest.fromRedirectRequest(request);
		if (log.isDebugEnabled())
			log.debug("Got InboundSAMLMessage..:" + logoutRequest.toXML());
		
		Audit.log(Operation.LOGOUTREQUEST, false, logoutRequest.getID(), logoutRequest.toXML());

		String statusCode = StatusCode.SUCCESS_URI;
		String consent = null;

		OIOAssertion assertion = ctx.getSessionHandler().getAssertion(session.getId());
		String idpEntityId = null;
		if (assertion != null) {
			idpEntityId = assertion.getIssuer();
		}
		if (idpEntityId == null) {
			log.warn("LogoutRequest received but user is not logged in");
			idpEntityId = logoutRequest.getIssuer();
		}
		if (idpEntityId == null) {
			throw new RuntimeException("User is not logged in, and there is no Issuer in the LogoutRequest. Unable to continue.");
		} else {
			Metadata metadata = ctx.getIdpMetadata().getMetadata(idpEntityId);

			try {
				logoutRequest.validateRequest(sig, request.getQueryString(), metadata.getPublicKeys(), ctx.getSpMetadata().getSingleLogoutServiceHTTPRedirectLocation(), metadata.getEntityID());

				// Logging out
				if (assertion != null) {
					log.info("Logging user out via SLO HTTP Redirect: " + assertion.getSubjectNameIDValue());
				} else {
					log.info("Logging user out via SLO HTTP Redirect without active session");
				}
				ctx.getSessionHandler().logOut(session);
				invokeAuthenticationHandler(ctx);
			} catch (LogoutRequestValidationException e1) {
				consent = e1.getMessage();
				statusCode = StatusCode.AUTHN_FAILED_URI;
			}

			if (log.isDebugEnabled()) log.debug("Logout status: " + statusCode + ", message: " + consent);
			// Returning.....

			OIOLogoutResponse res = OIOLogoutResponse.fromRequest(logoutRequest, statusCode, consent, ctx.getSpMetadata().getEntityID(), metadata.getSingleLogoutServiceResponseLocation());
			String url = res.getRedirectURL(ctx.getCredential(), relayState);
			
			Audit.log(Operation.LOGOUTRESPONSE, true, res.getID(), res.toXML());

			if (log.isDebugEnabled())
				log.debug("sendRedirect to..:" + url);
			ctx.getResponse().sendRedirect(url);
			return;
		}
	}

	public void handlePost(RequestContext ctx) throws ServletException, IOException {
		throw new UnsupportedOperationException();
	}
	
	private void invokeAuthenticationHandler(RequestContext ctx) {
		String handlerClass = ctx.getConfiguration().getString(Constants.PROP_AUTHENTICATION_HANDLER, null);
		if (handlerClass != null) {
			log.debug("Authentication handler: " + handlerClass);
			
			AuthenticationHandler handler = (AuthenticationHandler) Utils.newInstance(ctx.getConfiguration(), Constants.PROP_AUTHENTICATION_HANDLER);
			if (handler instanceof LogoutAuthenticationHandler) {
				((LogoutAuthenticationHandler)handler).userLoggedOut(ctx.getRequest(), ctx.getResponse());
			}
		} else {
			log.debug("No authentication handler configured");
		}
	}

}
