package dk.itst.oiosaml.sp.bindings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.jmock.Expectations;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.w3c.dom.Document;

import dk.itst.oiosaml.sp.model.OIOAuthnRequest;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.TestHelper;


public class RedirectBindingHandlerTest extends AbstractServiceTests {

	
	@Test
	public void testHandle() throws Exception {
		RedirectBindingHandler handler = new RedirectBindingHandler();
		
		final StringWriter sw = new StringWriter();
		context.checking(new Expectations() {{
			one(res).setContentType("text/html");
			one(res).getWriter(); will(returnValue(new PrintWriter(sw)));
		}});
		OIOAuthnRequest request = OIOAuthnRequest.buildAuthnRequest("http://ssoServiceLocation", "spEntityId", SAMLConstants.SAML2_ARTIFACT_BINDING_URI, session, logUtil);

		handler.handle(req, res, credential, request, logUtil);
		
		String url = sw.toString().substring(sw.toString().indexOf("url=") + 4, sw.toString().indexOf(">", sw.toString().indexOf("url=")) - 1);
		String r = TestHelper.getParameter("SAMLRequest", url);
		TestHelper.validateUrlSignature(credential, url, r, "SAMLRequest");
		
		Document document = TestHelper.parseBase64Encoded(r);
		AuthnRequest ar = (AuthnRequest) Configuration.getUnmarshallerFactory().getUnmarshaller(document.getDocumentElement()).unmarshall(document.getDocumentElement());
		assertEquals("http://ssoServiceLocation", ar.getDestination());
		assertEquals("spEntityId", ar.getIssuer().getValue());
		assertNotNull(ar.getID());
	}
}
