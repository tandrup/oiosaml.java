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
package dk.itst.oiosaml.sp.bindings;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.xml.security.credential.Credential;

import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.model.OIOAuthnRequest;

/**
 * Generate AuthnRequest using the HTTP POST binding.
 * 
 * <p>The {@link #handle(HttpServletRequest, HttpServletResponse, Credential, String, String)} method generates a web form
 * with the necessary form elements. The form is configured using the POSTDispatchPath configuration key, which must
 * point to a local servlet. The value can be overwritten in {@link #PostBindingHandler(String)}.</p>
 * 
 * <p>If a new servlet is written, the following request attributes can be used for the form: 
 * <ul>
 * <li><strong>action</strong>: Form action to use</li>
 * <li><strong>RelayState</strong>: Value of the RelayState attribute</li>
 * <li><strong>SAMLRequest</strong>: Value of the SAMLRequest form attribute</li>
 * </ul>
 * All the values are properly form encoded and signed. Use {@link #createContext(HttpSession, Credential, String, String, LogUtil)} if a new
 * SAMLRequest must be generated, but without sending it directly to the browser.
 * </p>
 * 
 * @author Joakim Rech <jre@trifork.com>
 * @author Rolf Njor Jensen <rolf@trifork.com>
 *
 */
public class PostBindingHandler implements BindingHandler {
	private String dispatchPath;
	public static final String VERSION = "$Id: ClientSSOEngine.java 2546 2008-04-11 13:29:25Z jre $";

	public PostBindingHandler() {
		dispatchPath = SAMLConfiguration.getSystemConfiguration().getString("POSTDispatchPath", null);
	}

	public PostBindingHandler(String dispatchPath) {
		this.dispatchPath = dispatchPath;
	}

	public String getBindingURI() {
		return SAMLConstants.SAML2_POST_BINDING_URI;
	}
	
	public void handle(HttpServletRequest req, HttpServletResponse response, Credential credential, OIOAuthnRequest request, LogUtil lu) throws IOException, ServletException {
		request.sign(credential);
		String encodedMessage = request.toBase64();

		req.setAttribute("action", request.getDestination());
		req.setAttribute("RelayState", request.getRelayState());
		req.setAttribute("SAMLRequest", encodedMessage);
		RequestDispatcher dispatcher = req.getRequestDispatcher(dispatchPath);
		if(dispatcher == null) {
			lu.audit("No request dispatcher found for path: " + dispatchPath);
			throw new RuntimeException("No request dispatcher found for path: " + dispatchPath);
		}
		lu.audit("Dispatching request to: " + dispatchPath);
		dispatcher.forward(req, response);
	}
}
