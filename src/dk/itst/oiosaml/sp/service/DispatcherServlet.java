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
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
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
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.bindings.BindingHandlerFactory;
import dk.itst.oiosaml.sp.bindings.DefaultBindingHandlerFactory;
import dk.itst.oiosaml.sp.configuration.ConfigurationHandler;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
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

	private transient IdpMetadata idpMetadata;
	private transient SPMetadata spMetadata;
	private Configuration configuration;
	private Credential credential;

	private Map<String, SAMLHandler> handlers = new HashMap<String, SAMLHandler>();
	private boolean initialized = false;
	private transient VelocityEngine engine;

	private BindingHandlerFactory bindingHandlerFactory;

	private SessionHandlerFactory sessionHandlerFactory;
	private ServletContext servletContext;

	@Override
	public final void init(ServletConfig config) throws ServletException {
		setHandler(new ConfigurationHandler(config.getServletContext()), "configure");
		
		servletContext = config.getServletContext();
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
				Audit.configureLog4j(SAMLConfiguration.getStringPrefixedWithBRSHome(configuration, Constants.PROP_LOG_FILE_NAME));
				
				setBindingHandler(new DefaultBindingHandlerFactory());
				setIdPMetadata(IdpMetadata.getInstance());
				setSPMetadata(SPMetadata.getInstance());
				setCredential(new CredentialRepository().getCredential(SAMLConfiguration.getStringPrefixedWithBRSHome(configuration, Constants.PROP_CERTIFICATE_LOCATION), 
						configuration.getString(Constants.PROP_CERTIFICATE_PASSWORD)));
				
				sessionHandlerFactory = SessionHandlerFactory.Factory.newInstance(configuration);
				sessionHandlerFactory.getHandler().resetReplayProtection(SAMLConfiguration.getSystemConfiguration().getInt(Constants.PROP_NUM_TRACKED_ASSERTIONIDS));

				handlers.putAll(Utils.getHandlers(configuration, servletContext));
				if (log.isDebugEnabled()) log.debug("Found handlers: " + handlers);
				
				setHandler(new MetadataHandler(), "metadata");
				setHandler(new IndexHandler(), "");
				
				initialized = true;
			}
		} catch (IllegalStateException e) {
			try {
				handlers.putAll(Utils.getHandlers(SAMLConfiguration.getCommonConfiguration(), servletContext));
			} catch (IOException e1) {
				log.error("Unable to load config", e);
			}
		}
	}
	
	protected final void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		initServlet();
		String action = req.getRequestURI().substring(req.getRequestURI().lastIndexOf("/") + 1);
		if(handlers.containsKey(action)) {
			try {
				SAMLHandler handler = handlers.get(action);
				SessionHandler sessionHandler = sessionHandlerFactory != null ? sessionHandlerFactory.getHandler() : null;
				RequestContext context = new RequestContext(req, res, idpMetadata, spMetadata, credential, configuration, sessionHandler, bindingHandlerFactory); 
				handler.handleGet(context);
			} catch (Exception e) {
				Audit.logError(action, false, e);
				handleError(req, res, e);
			}
		} else {
			throw new UnsupportedOperationException(action + ", allowed: " + handlers.keySet());
		}
	}
	
	protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		initServlet();
		String action = req.getRequestURI().substring(req.getRequestURI().lastIndexOf("/") + 1);
		if(handlers.containsKey(action)) {
			try {
				SAMLHandler handler = handlers.get(action);
				SessionHandler sessionHandler = sessionHandlerFactory != null ? sessionHandlerFactory.getHandler() : null;
				RequestContext context = new RequestContext(req, res, idpMetadata, spMetadata, credential, configuration, sessionHandler, bindingHandlerFactory); 
				handler.handlePost(context);
			} catch (Exception e) {
				Audit.logError(action, false, e);
				handleError(req, res, e);
			}
		} else {
			throw new UnsupportedOperationException(action);
		}
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
	
	public void setSessionHandlerFactory(SessionHandlerFactory sessionHandlerFactory) {
		this.sessionHandlerFactory = sessionHandlerFactory;
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
	
	@Override
	public void destroy() {
		if (sessionHandlerFactory != null) {
			sessionHandlerFactory.close();
		}
		SessionHandlerFactory.Factory.close();
	}
	
	private class IndexHandler implements SAMLHandler {
		public void handleGet(RequestContext context) throws ServletException, IOException {
			PrintWriter w = context.getResponse().getWriter();
			
			w.println("<html><head><title>SAML Endppoints</title></head><body><h1>SAML Endpoints</h1>");
			w.println("<ul>");
			for (Map.Entry<String, SAMLHandler> e : handlers.entrySet()) {
				w.println("<li><a href=\"");
				w.print(e.getKey());
				w.print("\">");
				w.print(e.getKey());
				w.print("</a>: ");
				w.print(e.getValue());
				w.println("</li>");
			}
			w.println("</ul>");
			w.println("</body></html>");
		}

		public void handlePost(RequestContext context) throws ServletException,
				IOException {
		}
		
	}
}
