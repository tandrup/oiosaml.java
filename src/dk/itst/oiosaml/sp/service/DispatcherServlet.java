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
import java.util.HashMap;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.configuration.Configuration;
import org.apache.log4j.Logger;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.xml.security.credential.Credential;

import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.bindings.BindingHandlerFactory;
import dk.itst.oiosaml.sp.bindings.DefaultBindingHandlerFactory;
import dk.itst.oiosaml.sp.configuration.ConfigurationHandler;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.validation.AssertionValidator;
import dk.itst.oiosaml.sp.model.validation.OIOSAMLAssertionValidator;
import dk.itst.oiosaml.sp.service.session.SessionHandler;
import dk.itst.oiosaml.sp.service.session.SessionHandlerFactory;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;


/**
 * Main servlet for all SAML handling.
 * 
 * This servlet simply dispatches to {@link dk.itst.oiosaml.sp.model.OIOSamlObject}s based on the requested url.
 * 
 * @author Joakim Recht <jre@trifork.com>
 * @author Rolf Njor Jensen <rolf@trifork.com>
 *
 */
public class DispatcherServlet extends HttpServlet {
	private static final Logger log = Logger.getLogger(DispatcherServlet.class);

	final public static String SAMLAssertionConsumer = "/SAMLAssertionConsumer";
	final public static String LogoutServiceHTTPRedirect = "/LogoutServiceHTTPRedirect";
	final public static String LogoutServiceHTTPRedirectResponse = "/LogoutServiceHTTPRedirectResponse";
	final public static String Logout = "/Logout";
	final public static String LogoutServiceSOAP = "/LogoutServiceSOAP";
	final public static String Login  ="/login";

	private transient IdpMetadata idpMetadata;
	private transient SPMetadata spMetadata;
	private Configuration configuration;
	private Credential credential;

	private HashMap<String, SAMLHandler> handlers = new HashMap<String, SAMLHandler>();
	private boolean initialized = false;
	private transient VelocityEngine engine;

	private BindingHandlerFactory bindingHandlerFactory;

	@Override
	public final void init(ServletConfig config) throws ServletException {
		setHandler(new ConfigurationHandler(config.getServletContext()), "/configure");

		initServlet();
		engine = new VelocityEngine();
		engine.setProperty(VelocityEngine.RESOURCE_LOADER, "classpath");
		engine.setProperty("classpath.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
		try {
			engine.init();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private void initServlet() {
		try {
			if (initialized  == false) {
				setConfiguration(SAMLConfiguration.getSystemConfiguration());
				LogUtil.configureLog4j(SAMLConfiguration.getStringPrefixedWithBRSHome(configuration, Constants.PROP_LOG_FILE_NAME));
				
				setBindingHandler(new DefaultBindingHandlerFactory());
				setIdPMetadata(IdpMetadata.getInstance());
				setSPMetadata(SPMetadata.getInstance());
				setCredential(new CredentialRepository().getCredential(SAMLConfiguration.getStringPrefixedWithBRSHome(configuration, Constants.PROP_CERTIFICATE_LOCATION), 
						configuration.getString(Constants.PROP_CERTIFICATE_PASSWORD)));
				SessionHandlerFactory.newInstance(configuration).resetReplayProtection(SAMLConfiguration.getSystemConfiguration().getInt(Constants.PROP_NUM_TRACKED_ASSERTIONIDS));
				configuration.getString(Constants.PROP_VALIDATOR, OIOSAMLAssertionValidator.class.getName());

				AssertionValidator validator = (AssertionValidator) Utils.newInstance(configuration, Constants.PROP_VALIDATOR);
	
				setHandler(new SAMLAssertionConsumerHandler(validator), SAMLAssertionConsumer);
				setHandler(new LogoutServiceHTTPRedirectHandler(), LogoutServiceHTTPRedirect);
				setHandler(new LogoutHTTPResponseHandler(), LogoutServiceHTTPRedirectResponse);
				setHandler(new LogoutHandler(), Logout);
				setHandler(new LogoutServiceSOAPHandler(), LogoutServiceSOAP);
				setHandler(new LoginHandler(bindingHandlerFactory), Login);
				setHandler(new MetadataHandler(), "/metadata");
				
				initialized = true;
			}
		} catch (IllegalStateException e) {}
	}
	
	protected final void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		initServlet();
		String action = req.getRequestURI().substring(req.getRequestURI().lastIndexOf(("/")));
		if(handlers.containsKey(action)) {
			try {
				SAMLHandler handler = handlers.get(action);
				SessionHandler sessionHandler = SessionHandlerFactory.newInstance(configuration);
				RequestContext context = new RequestContext(req, res, idpMetadata, spMetadata, credential, configuration, getLogutil(action, handler, req, sessionHandler), sessionHandler); 
				handler.handleGet(context);
			} catch (Exception e) {
				handleError(req, res, e);
			}
		} else {
			throw new UnsupportedOperationException(action);
		}
	}
	
	protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		initServlet();
		String action = req.getRequestURI().substring(req.getRequestURI().lastIndexOf(("/")));
		if(handlers.containsKey(action)) {
			try {
				SAMLHandler handler = handlers.get(action);
				SessionHandler sessionHandler = SessionHandlerFactory.newInstance(configuration);
				RequestContext context = new RequestContext(req, res, idpMetadata, spMetadata, credential, configuration, getLogutil(action, handler, req, sessionHandler), sessionHandler); 
				handler.handlePost(context);
			} catch (Exception e) {
				handleError(req, res, e);
			}
		} else {
			throw new UnsupportedOperationException(action);
		}
	}
	
	private LogUtil getLogutil(String action, SAMLHandler handler, HttpServletRequest req, SessionHandler sessionHandler) {
		OIOAssertion assertion = sessionHandler == null ? null : sessionHandler.getAssertion(req.getSession().getId());
		return new LogUtil(handler.getClass(), null, action, assertion == null ? null : assertion.getSubjectNameIDValue());
	}
	
	public void setInitialized(boolean b) {
		initialized = b;
	}
	
	public boolean isInitialized() {
		return initialized;
	}
	
	public final void setCredential(Credential credential) {
		this.credential = credential;
	}

	public final void setConfiguration(Configuration systemConfiguration) {
		this.configuration = systemConfiguration;
	}

	public final void setSPMetadata(SPMetadata metadata) {
		this.spMetadata = metadata;
	}

	public final void setIdPMetadata(IdpMetadata metadata) {
		this.idpMetadata = metadata;
	}
	
	public void setHandler(SAMLHandler handler, String dispatchPath) {
		handlers.put(dispatchPath, handler);		
	}
	
	public void setBindingHandler(BindingHandlerFactory bindingHandlerFactory) {
		this.bindingHandlerFactory = bindingHandlerFactory;
	}
	
	private void handleError(HttpServletRequest request, HttpServletResponse response, Exception e) throws ServletException, IOException {
		log.error("Unable to validate Response", e);

		String err = null;
		if (configuration != null) {
			err = configuration.getString(Constants.PROP_ERROR_SERVLET, null);
		}
		if (err != null) {
			request.setAttribute(Constants.ATTRIBUTE_ERROR, e.getMessage());
			request.setAttribute(Constants.ATTRIBUTE_EXCEPTION, e);
			request.getRequestDispatcher(err).forward(request, response);
		} else {
			VelocityContext ctx = new VelocityContext();
			ctx.put(Constants.ATTRIBUTE_ERROR, e.getMessage());
			ctx.put(Constants.ATTRIBUTE_EXCEPTION, e);
			
			response.setContentType("text/html");
			response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

			String prefix = "/" + getClass().getPackage().getName().replace('.', '/') + "/";
			try {
				engine.mergeTemplate(prefix + "error.vm", ctx, response.getWriter());
			} catch (Exception e1) {
				log.error("Unable to render error template", e1);
				throw new ServletException(e1);
			}
		}

	}
}
