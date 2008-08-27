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
package dk.itst.oiosaml.sp.model;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.validation.ValidationException;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.service.session.LoggedInHandler;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.sp.util.LogoutRequestValidationException;

public class OIOLogoutRequest extends OIORequest {
	private static final Logger log = Logger.getLogger(OIOLogoutRequest.class);

	private final LogoutRequest request;

	public OIOLogoutRequest(LogoutRequest request) {
		super(request);
		this.request = request;
	}
	
	/**
	 * Extract a LogoutRequest from a HTTP redirect request. 
	 * 
	 * @return The extracted request. Never <code>null</code>.
	 * @throws WrappedException If the extraction fails.
	 */
	public static OIOLogoutRequest fromRedirectRequest(HttpServletRequest request) {
		// Unpack the <LogoutRequest> from the request
		BasicSAMLMessageContext<LogoutRequest, ?, ?> messageContext = new BasicSAMLMessageContext<LogoutRequest, SAMLObject, SAMLObject>();
		messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));

		HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();

		try {
			decoder.decode(messageContext);
		} catch (MessageDecodingException e) {
			throw new WrappedException(Layer.CLIENT, e);
		} catch (SecurityException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}
		return new OIOLogoutRequest(messageContext.getInboundSAMLMessage());
	}

	/**
	 * Get session index for a LogoutRequest.
	 * 
	 * @return The value. <code>null</code>, if the logout request does not
	 *         contain any session indeces.
	 */
	public String getSessionIndex() {
		String retVal = null;
		if (request.getSessionIndexes() != null && request.getSessionIndexes().size() > 0) {
			SessionIndex sessionIndexStructure = request.getSessionIndexes().get(0);

			retVal = sessionIndexStructure.getSessionIndex();
		}
		return retVal;
	}

	/**
	 * 
	 * @param sessionIndex The sessionIndex 
	 * @return true, if the sessionIndex of the LogoutRequest match the sessionIndex
	 */
	public boolean isSessionIndexOK(String sessionIndex) {
		String sessionIndex2 = getSessionIndex();
		return sessionIndex2 != null && sessionIndex2.equals(sessionIndex);
	}
	
	public void validateRequest(String signature, String queryString, PublicKey publicKey, String destination, String issuer) throws LogoutRequestValidationException {
		List<String> errors = new ArrayList<String>();
		validateRequest(issuer, destination, publicKey, errors);
		
		if (signature != null) {
			// Verifying the signature....
			if (!Utils.verifySignature(signature, queryString, Constants.SAML_SAMLREQUEST, publicKey)) {
				errors.add("Invalid signature");
			}
		}

		if (request.getNotOnOrAfter() != null && !request.getNotOnOrAfter().isAfterNow()) {
			errors.add("LogoutRequest is expired. NotOnOrAfter; " + request.getNotOnOrAfter());
		}
		if (!errors.isEmpty()) {
			throw new LogoutRequestValidationException(errors);
		}
	}

	/**
	 * Generate a new LogoutRequest.
	 * 
	 * @param session The session containing the active assertion.
	 * @param logoutServiceLocation Destination for the logout request.
	 * @param issuerEntityId Entity ID of the issuing entity.
	 */
	public static OIOLogoutRequest buildLogoutRequest(HttpSession session, LogUtil lu, String logoutServiceLocation, String issuerEntityId) {
		LogoutRequest logoutRequest = new LogoutRequestBuilder().buildObject();

		logoutRequest.setID(LoggedInHandler.getInstance().getID(session, lu));
		logoutRequest.setIssueInstant(new DateTime(DateTimeZone.UTC));
		logoutRequest.addNamespace(OIOSAMLConstants.SAML20_NAMESPACE);
		logoutRequest.setDestination(logoutServiceLocation);

		logoutRequest.setIssuer(SAMLUtil.createIssuer(issuerEntityId));

		SessionIndex sessionIndex = new SessionIndexBuilder().buildObject();
		sessionIndex.setSessionIndex(LoggedInHandler.getInstance().getSessionIndexFromAssertion(session.getId()));
		logoutRequest.getSessionIndexes().add(sessionIndex);

		logoutRequest.setNameID(SAMLUtil.createNameID(LoggedInHandler.getInstance().getNameIdFromAssertion(session.getId())));

		try {
			if (log.isDebugEnabled())
				log.debug("Validate the logoutRequest...");
			logoutRequest.validate(true);
			if (log.isDebugEnabled())
				log.debug("...OK");
		} catch (ValidationException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}

		return new OIOLogoutRequest(logoutRequest);
	}


	/**
	 * Generate a redirect request url from the request.
	 * 
	 * The url will be signed and formatted correctly according to the HTTP Redirect SAML binding.
	 *
	 * @param signingCredential Credential to use for signing the url.
	 * @return A URL containing an &lt;LogoutRequest&gt; for the current user.
	 */
	public String getRedirectRequestURL(Credential signingCredential, LogUtil lu) {
		lu.setRequestId(getID());
		lu.audit(Constants.SERVICE_LOGOUT_REQUEST, toXML());

		Encoder enc = new Encoder();

		// Start timer
		lu.beforeService("", request.getDestination(),Constants.SERVICE_LOGOUT_REQUEST, "ID=" + getID());

		try {
			return enc.buildRedirectURL(signingCredential);
		} catch (MessageEncodingException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}
	}

}
