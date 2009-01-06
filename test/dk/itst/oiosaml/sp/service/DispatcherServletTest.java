package dk.itst.oiosaml.sp.service;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.configuration.Configuration;
import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.validation.ValidationException;
import dk.itst.oiosaml.sp.service.session.SingleVMSessionHandler;
import dk.itst.oiosaml.sp.service.util.Constants;

public class DispatcherServletTest extends AbstractServiceTests {

	private SAMLHandler handler;
	private Configuration configuration;
	private DispatcherServlet servlet;
	private HashMap<String, String> conf;

	@Before
	public void setUp() throws Exception {
		handler = context.mock(SAMLHandler.class);
		servlet = new DispatcherServlet();
		conf = new HashMap<String, String>() {{
			put(SAMLUtil.OIOSAML_HOME, "/test");
			put(Constants.PROP_SESSION_HANDLER, SingleVMSessionHandler.class.getName());
		}};
		configuration = TestHelper.buildConfiguration(conf);
		servlet.setConfiguration(configuration);
		servlet.setCredential(credential);
		servlet.setIdPMetadata(idpMetadata);
		servlet.setSPMetadata(spMetadata);
		servlet.setInitialized(true);
	}

	@Test(expected=UnsupportedOperationException.class)
	public void failGetOnNoHandler() throws Exception {
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("/void"));
		}});
		servlet.doGet(req, res);		
	}
	
	@Test(expected=UnsupportedOperationException.class)
	public void failPostOnNoHandler() throws Exception {
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("/void"));
		}});
		servlet.doGet(req, res);		
	}

	@Test
	public void samlAssertionConsumerHandler() throws Exception {
		handlePostAndGetForSpecific(DispatcherServlet.SAMLAssertionConsumer);
	}

	@Test
	public void logoutServiceHTTPRedirectHandler() throws Exception {
		handlePostAndGetForSpecific(DispatcherServlet.LogoutServiceHTTPRedirect);
	}

	@Test
	public void logoutHTTPResponseHandler() throws Exception {
		handlePostAndGetForSpecific(DispatcherServlet.LogoutServiceHTTPRedirectResponse);
	}

	@Test
	public void logoutHandler() throws Exception {
		handlePostAndGetForSpecific(DispatcherServlet.Logout);
	}

	@Test
	public void logoutServiceSoapHandler() throws Exception {
		handlePostAndGetForSpecific(DispatcherServlet.LogoutServiceSOAP);
	}
	
	@Test
	public void testDefaultErrorPage() throws Exception {
		final ServletConfig config = context.mock(ServletConfig.class);
		context.checking(new Expectations() {{
			allowing(config).getServletContext(); will(returnValue(null));
			allowing(req).getRequestURI(); will(returnValue("/base/test"));
			one(handler).handleGet(with(any(RequestContext.class))); will(throwException(new ValidationException("test")));
			
			one(res).setContentType("text/html");
			one(res).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			one(res).getWriter(); will(returnValue(new PrintWriter(new StringWriter())));
			
		}});
		
		servlet.init(config);
		servlet.setHandler(handler, "/test");
		servlet.doGet(req, res);
	}
	
	@Test
	public void testCustomErrorPage() throws Exception {
		final ServletConfig config = context.mock(ServletConfig.class);
		final RequestDispatcher dispatcher = context.mock(RequestDispatcher.class);
		context.checking(new Expectations() {{
			allowing(config).getServletContext(); will(returnValue(null));
			allowing(req).getRequestURI(); will(returnValue("/base/test"));
			one(handler).handleGet(with(any(RequestContext.class))); will(throwException(new ValidationException("test")));

			one(req).setAttribute(with(equal(Constants.ATTRIBUTE_ERROR)), with(any(String.class)));
			one(req).setAttribute(with(equal(Constants.ATTRIBUTE_EXCEPTION)), with(any(Expectations.class)));
			one(req).getRequestDispatcher("/error.jsp"); will(returnValue(dispatcher));
			one(dispatcher).forward(req, res);
		}});
		
		conf.put(Constants.PROP_ERROR_SERVLET, "/error.jsp");
		servlet.init(config);
		servlet.setHandler(handler, "/test");
		servlet.doGet(req, res);
	}

	private void handlePostAndGetForSpecific(final String servletPath) throws Exception {
		servlet.setHandler(handler, servletPath);
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("/base" + servletPath));
			one(handler).handleGet(with(any(RequestContext.class)));
		}});
		servlet.doGet(req, res);

		servlet.setHandler(handler, servletPath);
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("/base" + servletPath));
			one(handler).handlePost(with(any(RequestContext.class)));
		}});
		servlet.doPost(req, res);
	}
}