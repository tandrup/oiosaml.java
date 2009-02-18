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
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.configuration.Configuration;
import org.apache.log4j.Logger;
import org.apache.velocity.VelocityContext;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.xml.util.Base64;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.bindings.BindingHandler;
import dk.itst.oiosaml.sp.bindings.BindingHandlerFactory;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.model.OIOAuthnRequest;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.HTTPUtils;

public class LoginHandler implements SAMLHandler {
	private static final Logger log = Logger.getLogger(LoginHandler.class);
	private final BindingHandlerFactory bindingHandlerFactory;
	
	public LoginHandler(BindingHandlerFactory bindingHandlerFactory) {
		this.bindingHandlerFactory = bindingHandlerFactory;
	}

	public void handleGet(RequestContext context) throws ServletException, IOException {
		if (log.isDebugEnabled()) log.debug("Go to login...");
		
		IdpMetadata idpMetadata = context.getIdpMetadata();
		Configuration conf = context.getConfiguration();
		HttpServletRequest request = context.getRequest();
		HttpServletResponse response = context.getResponse();
		
		Metadata metadata;
		if (idpMetadata.enableDiscovery()) {
			log.debug("Discovery profile is active");
			String samlIdp = request.getParameter(Constants.DISCOVERY_ATTRIBUTE);
			if (samlIdp == null) {
				String discoveryLocation = conf.getString(Constants.DISCOVERY_LOCATION);
				log.debug("No _saml_idp discovery value found, redirecting to discovery service at " + discoveryLocation);
				String url = request.getRequestURL().toString();
				if (request.getQueryString() != null) {
					url += "?" + request.getQueryString();
				}
				HTTPUtils.sendMetaRedirect(response, discoveryLocation, "r=" + URLEncoder.encode(url, "UTF-8"), true);
				return;
			} else if ("".equals(samlIdp)) {
				String defaultIdP = conf.getString(Constants.PROP_DISCOVERY_DEFAULT_IDP, null);
				if (defaultIdP != null) {
					log.debug("No IdP discovered, using default IdP from configuration: " + defaultIdP);
					metadata = idpMetadata.getMetadata(defaultIdP);
				} else {
					if (conf.getBoolean(Constants.PROP_DISCOVERY_PROMPT, false)) {
						String url = request.getRequestURL().toString();
						url += "?RelayState=" + request.getParameter(Constants.SAML_RELAYSTATE);
						promptIdp(context, url);
						
						return;
					} else {
						log.debug("No IdP discovered, using first from metadata");
						metadata = idpMetadata.getFirstMetadata();
					}
				}
			} else {
				String[] entityIds = SAMLUtil.decodeDiscoveryValue(samlIdp);
				metadata = idpMetadata.findSupportedEntity(entityIds);
				log.debug("Discovered idp " + metadata.getEntityID());
			}
		} else {
			metadata = idpMetadata.getFirstMetadata();
		}
		Endpoint signonLocation = metadata.findLoginEndpoint(conf.getStringArray(Constants.PROP_SUPPORTED_BINDINGS));
		if (signonLocation == null) {
			String msg = "Could not find a valid IdP signon location. Supported bindings: " + conf.getString(Constants.PROP_SUPPORTED_BINDINGS) + ", available: " + metadata.getSingleSignonServices();
			log.error(msg);
			throw new RuntimeException(msg);
		}
		log.debug("Signing on at " + signonLocation);
		
		BindingHandler bindingHandler = bindingHandlerFactory.getBindingHandler(signonLocation.getBinding());
		log.info("Using idp " + metadata.getEntityID() + " at " + signonLocation.getLocation() + " with binding " + signonLocation.getBinding());

		HttpSession session = context.getSession();
		UserAssertion ua = (UserAssertion) session.getAttribute(Constants.SESSION_USER_ASSERTION);
		session.removeAttribute(Constants.SESSION_USER_ASSERTION);
		UserAssertionHolder.set(null);

		LogUtil lu = new LogUtil(getClass(), "", "Authn");
		String relayState = context.getRequest().getParameter(Constants.SAML_RELAYSTATE);
		OIOAuthnRequest authnRequest = OIOAuthnRequest.buildAuthnRequest(signonLocation.getLocation(), context.getSpMetadata().getEntityID(), context.getSpMetadata().getDefaultAssertionConsumerService().getBinding(), context.getSessionHandler(), relayState);
		authnRequest.setNameIDPolicy(conf.getString(Constants.PROP_NAMEID_POLICY, null), conf.getBoolean(Constants.PROP_NAMEID_POLICY_ALLOW_CREATE, false));
		authnRequest.setForceAuthn(isForceAuthnEnabled(request, conf));

		if (ua == null) {
			authnRequest.setPasive(conf.getBoolean(Constants.PROP_PASSIVE, false));
		}
		
		lu.audit(Constants.SERVICE_AUTHN_REQUEST, authnRequest.toXML());

		bindingHandler.handle(request, response, context.getCredential(), authnRequest, lu);
		context.getSessionHandler().registerRequest(authnRequest.getID(), metadata.getEntityID());
	}

	public void handlePost(RequestContext context) throws ServletException, IOException {
		handleGet(context);
	}

	private boolean isForceAuthnEnabled(HttpServletRequest servletRequest, Configuration conf) {
		String[] urls = conf.getStringArray(Constants.PROP_FORCE_AUTHN_URLS);
		if (urls == null) return false;
		
		String path = servletRequest.getPathInfo();
		if (path == null) {
			path = "/";
		}
		if (log.isDebugEnabled()) log.debug("ForceAuthn urls: " + Arrays.toString(urls) + "; path: " + path);
		
		
		for (String url : urls) {
			if (path.matches(url.trim())) {
				if (log.isDebugEnabled()) log.debug("Requested url " + path + " is in forceauthn list " + Arrays.toString(urls));
				return true;
			}
		}
		return false;
	}
	
	private void promptIdp(RequestContext context, String returnUrl) throws ServletException, IOException {
		log.debug("Prompting user for IdP");
		
		Map<String, String> idps = new HashMap<String, String>();
		for (String id : context.getIdpMetadata().getEntityIDs()) {
			StringBuilder url = new StringBuilder(returnUrl);
			if (returnUrl.indexOf('?') > -1) {
				url.append("&");
			} else {
				url.append("?");
			}
			url.append(Constants.DISCOVERY_ATTRIBUTE).append("=");
			url.append(Base64.encodeBytes(id.getBytes(), Base64.DONT_BREAK_LINES));
			idps.put(id, url.toString());
		}

		String servlet = context.getConfiguration().getString(Constants.PROP_DISCOVERY_PROMPT_SERVLET, null);
		if (servlet != null) {
			HttpServletRequest request = context.getRequest();
			request.setAttribute("entityIds", idps);
			request.getRequestDispatcher(servlet).forward(request, context.getResponse());
		} else {
			VelocityContext vc = new VelocityContext();
			vc.put("entityIds", idps);
			
			try {
				HTTPUtils.getEngine().mergeTemplate("/dk/itst/oiosaml/sp/service/idp.vm", vc, context.getResponse().getWriter());
			} catch (Exception e) {
				log.error("Unable to render IdP list", e);
				throw new ServletException(e);
			}
		}
		
	}

}
