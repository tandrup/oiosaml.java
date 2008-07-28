package dk.itst.oiosaml.sp.service;

import static dk.itst.oiosaml.sp.service.TestHelper.getParameter;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.configuration.Configuration;
import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.StatusCode;

import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.model.OIOLogoutRequest;
import dk.itst.oiosaml.sp.model.OIOLogoutResponse;
import dk.itst.oiosaml.sp.service.LogoutHTTPResponseHandler;
import dk.itst.oiosaml.sp.service.session.LoggedInHandler;
import dk.itst.oiosaml.sp.service.util.Constants;

public class LogoutHTTPResponseHandlerTest extends AbstractServiceTests {
	
	private LogoutHTTPResponseHandler handler;
	private Configuration configuration;
	private RequestContext ctx;

	@Before
	public void setUp() throws NoSuchAlgorithmException, NoSuchProviderException {
		handler = new LogoutHTTPResponseHandler();

		configuration = TestHelper.buildConfiguration(new HashMap<String, String>() {{
			put(Constants.PROP_HOME, "url");
		}});
		ctx = new RequestContext(req, res, idpMetadata, spMetadata, credential, configuration, logUtil);
	}

	@Test
	public void testReceiveResponseNotLoggedIn() throws Exception {
		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, logUtil, "http://slo", idpEntityId);
		LoggedInHandler.getInstance().registerRequest(lr.getID(), idpEntityId);

		OIOLogoutResponse resp = OIOLogoutResponse.fromRequest(lr, StatusCode.SUCCESS_URI, "consent", idpEntityId, spMetadata.getSingleLogoutServiceHTTPRedirectResponseLocation());
		String responseUrl = resp.getRedirectURL(credential, "relayState", logUtil);
		setExpectations(req, responseUrl);
		
		context.checking(new Expectations() {{
			one(res).sendRedirect("url");
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		handler.handleGet(ctx);
	} 
	
	@Test(expected=IllegalArgumentException.class)
	public void testReceiveResponseLoggedIn() throws Exception{
		
		LogUtil lu = new LogUtil(getClass(), "test");
		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, lu, "http://slo", idpEntityId);
		LoggedInHandler.getInstance().registerRequest(lr.getID(), idpMetadata.getFirstMetadata().getEntityID());
		
		OIOLogoutResponse resp = OIOLogoutResponse.fromRequest(lr, StatusCode.SUCCESS_URI, "consent", idpEntityId, spMetadata.getSingleLogoutServiceHTTPRedirectResponseLocation());
		
		String responseUrl = resp.getRedirectURL(credential, "relayState", logUtil);
		setExpectations(req, responseUrl);
		
		context.checking(new Expectations() {{
			one(res).sendRedirect("url");
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		handler.handleGet(ctx);
		
		LoggedInHandler.getInstance().removeEntityIdForRequest(lr.getID());
	}

	private void setExpectations(final HttpServletRequest req,
			final String responseUrl) throws UnsupportedEncodingException {
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("/"));
			allowing(req).getQueryString(); will(returnValue(responseUrl.substring(responseUrl.indexOf('?') + 1)));
			allowing(req).getParameter("SAMLResponse"); will(returnValue(URLDecoder.decode(getParameter("SAMLResponse", responseUrl), "UTF-8")));
			allowing(req).getParameter("SAMLRequest"); will(returnValue(null));
			allowing(req).getParameter("RelayState"); will(returnValue(URLDecoder.decode(getParameter("RelayState", responseUrl), "UTF-8")));
			allowing(req).getParameter("SigAlg"); will(returnValue(URLDecoder.decode(getParameter("SigAlg", responseUrl), "UTF-8")));
			allowing(req).getParameter("Signature"); will(returnValue(URLDecoder.decode(getParameter("Signature", responseUrl), "UTF-8")));
			allowing(req).getMethod(); will(returnValue("GET"));
			allowing(req).getRequestURL(); will(returnValue(new StringBuffer(spMetadata.getSingleLogoutServiceHTTPRedirectResponseLocation())));
		}});
	}
	
}
