package dk.itst.oiosaml.sp.service;

import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jmock.Expectations;
import org.junit.Before;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.security.credential.Credential;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.AbstractTests;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.session.LoggedInHandler;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.LogId;

public abstract class AbstractServiceTests extends AbstractTests {

	protected HttpServletRequest req;
	protected HttpServletResponse res;
	protected HttpSession session;
	protected Assertion assertion;
	protected LoggedInHandler handler;
	protected HashMap<String, LogId> ids;

	protected Credential credential;
	protected IdpMetadata idpMetadata;
	protected SPMetadata spMetadata;

	protected String idpEntityId;
	protected LogUtil logUtil = new LogUtil(getClass(), "test");

	@Before
	public void setUpTests() throws Exception {
		credential = TestHelper.getCredential();
		ids = new HashMap<String, LogId>();
		req = context.mock(HttpServletRequest.class);
		res = context.mock(HttpServletResponse.class);
		session = context.mock(HttpSession.class);
		context.checking(new Expectations() {{
			allowing(session).getId(); will(returnValue("" + System.currentTimeMillis()));
			allowing(session).setAttribute(Constants.SESSION_ID_LIST, ids);
			allowing(req).getSession(); will(returnValue(session));
			allowing(session).getAttribute(Constants.SESSION_ID_LIST); will(returnValue(ids));
		}});
		assertion = (Assertion) SAMLUtil.unmarshallElement("../sp/model/assertion.xml");

		handler = LoggedInHandler.getInstance();
		handler.resetReplayProtection(10);
		
		idpMetadata = new IdpMetadata(TestHelper.buildEntityDescriptor(credential));
		spMetadata = TestHelper.buildSPMetadata();
		idpEntityId = idpMetadata.getEntityIDs().iterator().next();
	}


	protected void setHandler() {
		handler.setAssertion(session, new OIOAssertion(assertion));
	}

}
