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

import org.opensaml.xml.signature.Signature;

import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.service.session.SessionHandler;

/**
 * Basic constants used within the library.
 * 
 */
public interface Constants {
	
	/**
	 * Session attribute for holding the user's current assertion. The value of the
	 * attribute should be a {@link UserAssertion}.
	 */
	static final String SESSION_USER_ASSERTION = "dk.itst.oiosaml.userassertion";
	

	// URI in the reference implementation
	static final String PROP_HOME = "oiosaml-sp.uri.home";
	static final String PROP_CERTIFICATE_LOCATION = "oiosaml-sp.certificate.location";
	static final String PROP_CERTIFICATE_PASSWORD = "oiosaml-sp.certificate.password";
	static final String PROP_IGNORE_CERTPATH = "oiosaml-sp.resolve.ignorecert";
	static final String PROP_RESOLVE_USERNAME = "oiosaml-sp.resolve.username";
	static final String PROP_RESOLVE_PASSWORD = "oiosaml-sp.resolve.password";
	static final String PROP_ASSURANCE_LEVEL = "oiosaml-sp.assurancelevel";
	static final String PROP_CRL = "oiosaml-sp.crl.";
	static final String PROP_CRL_CHECK_PERIOD = "oiosaml-sp.crl.period";
	static final String PROP_REQUIRE_ENCRYPTION = "oiosaml-sp.encryption.force";
	static final String PROP_NUM_TRACKED_ASSERTIONIDS = "common.saml2.loggedinhandler.numusedassertionids";
	static final String PROP_VALIDATOR = "oiosaml-sp.assertion.validator";
	
	static final String PROP_NAMEID_POLICY = "oiosaml-sp.nameid.policy";
	static final String PROP_NAMEID_POLICY_ALLOW_CREATE = "oiosaml-sp.nameid.allowcreate";
	
	static final String PROP_ERROR_SERVLET = "oiosaml-sp.errors";
	
	/**
	 * Property pointing to a class which implements {@link SessionHandler}.
	 */
	static final String PROP_SESSION_HANDLER_FACTORY = "oiosaml-sp.sessionhandler.factory";
	
	/**
	 * Property indicating if IsPassive should be set to true or false.
	 */
	static final String PROP_PASSIVE = "oiosaml-sp.passive";
	
	/**
	 * Property for setting the username used for the anonymous user. The anonymous user is used when
	 * IsPassive is true, and the user is not signed in at the IdP.
	 */
	static final String PROP_PASSIVE_USER_ID = "oiosaml-sp.passive.user";
	
	/**
	 * A comma separated list of urls for which ForceAuthn should be set to true. 
	 * Each url is treated as a regular expression against the request (without the servlet path).
	 */
	static final String PROP_FORCE_AUTHN_URLS = "oiosaml-sp.authn.force";

	/**
	 * Path to the saml dispatcher servlet.
	 */
	static final String PROP_SAML_SERVLET = "oiosaml-sp.servlet";
	
	static final String PROP_AUTHENTICATION_HANDLER = "oiosaml-sp.authenticationhandler";
	
	static final String PROP_SUPPORTED_BINDINGS = "oiosaml-sp.bindings";
	
	/**
	 * Path to a servlet handling re-posts after authentication.
	 */
	static final String PROP_REPOST_SERVLET = "oiosaml-sp.repost";

	// Known SAML services
	static final String SERVICE_AUTHN_REQUEST = "<AuthnRequest>";
	static final String SERVICE_LOGOUT_REQUEST = "<LogoutRequest>";
	static final String SERVICE_LOGOUT_RESPONSE = "<LogoutResponse>";
	static final String SERVICE_ARTIFACT_RESOLVE = "<ArtifactResolve>";

	/**
	 * Standard request parameter for holding relay state.
	 */
	static final String SAML_RELAYSTATE = "RelayState";
	
	/**
	 * Standard request parameter for holding a saml request.
	 */
	static final String SAML_SAMLREQUEST = "SAMLRequest";
	
	/**
	 * Standard request parameter for holding a saml response.
	 */
	static final String SAML_SAMLRESPONSE = "SAMLResponse";
	
	/**
	 * Standard request parameter for holding a saml signature algorithm uri.
	 */
	static final String SAML_SIGALG = "SigAlg";
	
	/**
	 * Standard request parameter for holding a saml signature.
	 */
	static final String SAML_SIGNATURE = Signature.DEFAULT_ELEMENT_LOCAL_NAME;
	
	/**
	 * Standard request parameter for holding a saml artifact.
	 */
	static final String SAML_SAMLART = "SAMLart";

	static final String SHA1_WITH_RSA = "SHA1withRSA";
	
	static final String INIT_OIOSAML_HOME = "oiosaml-j.home";
	
	/**
	 * Configuration parameter pointing to the URL for the discovery service.
	 */
	static final String DISCOVERY_LOCATION = "oiosaml-sp.discovery";
	
	/**
	 * Session and url parameter holding the current saml idp discovery value.
	 */
	static final String DISCOVERY_ATTRIBUTE = "_saml_idp";
		
	
	static final String PROP_LOG_FILE_NAME = "oiosaml-sp.log";
	
	static final String ATTRIBUTE_ERROR = "error";
	static final String ATTRIBUTE_EXCEPTION = "exception";
}
