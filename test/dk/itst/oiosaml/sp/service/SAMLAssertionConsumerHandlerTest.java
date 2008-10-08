package dk.itst.oiosaml.sp.service;

import static dk.itst.oiosaml.sp.service.TestHelper.buildAssertion;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;

import javax.servlet.ServletException;

import org.apache.commons.configuration.Configuration;
import org.hamcrest.Description;
import org.jmock.Expectations;
import org.jmock.api.Action;
import org.jmock.api.Invocation;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.PassiveUserAssertion;
import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.service.session.LoggedInHandler;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.LogId;
import dk.itst.oiosaml.sp.service.util.SOAPClient;

public class SAMLAssertionConsumerHandlerTest extends AbstractServiceTests {

	private SAMLAssertionConsumerHandler handler;
	private Configuration configuration;
	private RequestContext ctx;
	private HashMap<String, String> conf;

	@SuppressWarnings("serial")
	@Before
	public void setUp() throws NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException, InvalidKeyException, SignatureException {
		ids = new HashMap<String, LogId>();
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("http://test"));
			allowing(req).getQueryString(); will(returnValue(""));
		}});
		handler = new SAMLAssertionConsumerHandler();
		conf = new HashMap<String, String>() {{
			put(Constants.PROP_IGNORE_CERTPATH, "false");
		}};
		configuration = TestHelper.buildConfiguration(conf);
		ctx = new RequestContext(req, res, idpMetadata, spMetadata, credential, configuration, logUtil);
	}
	
	@Test
	public void failWhenMissingSAMLart() throws IOException, ServletException {
		context.checking(new Expectations() {{
			allowing(req).getParameter(with(any(String.class))); will(returnValue(null));
		}});
		try {
			handler.handleGet(ctx);
			fail("SAMLArt not set");
		} catch (IllegalArgumentException e) {}
	}
	
	@Test
	public void failWhenMissingRelayState() throws Exception {
		final ByteArrayOutputStream bos = generateArtifact();
		final SOAPClient client = context.mock(SOAPClient.class);
		
		context.checking(new Expectations() {{
			allowing(req).getParameter(Constants.SAML_SAMLART); will(returnValue(Base64.encodeBytes(bos.toByteArray())));
			allowing(req).getParameter(with(any(String.class))); will(returnValue(null));
			allowing(client).wsCall(with(any(XMLObject.class)), with(any(LogUtil.class)), with(any(String.class)), with(any(String.class)), with(any(String.class)), with(any(Boolean.class)));
			will(new Action() {
				public void describeTo(Description description) {}

				public Object invoke(Invocation invocation) throws Throwable {
					ArtifactResolve req = (ArtifactResolve) invocation.getParameter(0);
					return buildResponse(req.getID(), false, false, null);
				}
			});
		}});
		handler.setSoapClient(client);
		try {
			handler.handleGet(ctx);
			fail("RelayState not set");
		} catch (IllegalArgumentException e) {}
	}
	
	@Test
	public void failWhenResponseIsUnsigned() throws Exception {
		final ByteArrayOutputStream bos = generateArtifact();
		final SOAPClient client = context.mock(SOAPClient.class);
		
		context.checking(new Expectations() {{
			allowing(req).getParameter(Constants.SAML_SAMLART); will(returnValue(Base64.encodeBytes(bos.toByteArray())));
			allowing(req).getParameter(Constants.SAML_SAMLRESPONSE); will(returnValue(null));
			one(req).getParameter(Constants.SAML_RELAYSTATE); will(returnValue(LoggedInHandler.getInstance().getID(session, new LogUtil(getClass(), "test"))));

			one(client).wsCall(with(any(XMLObject.class)), with(any(LogUtil.class)), with(equal(idpMetadata.getMetadata("idp1.test.oio.dk").getArtifactResolutionServiceLocation(SAMLConstants.SAML2_SOAP11_BINDING_URI))), with(aNull(String.class)), with(aNull(String.class)), with(any(Boolean.class)));
//			one(ar).artifactResolve(with(equal(idpMetadata.getMetadata("idp1.test.oio.dk").getArtifactResolutionServiceLocation(SAMLConstants.SAML2_SOAP11_BINDING_URI))), with(equal(new Boolean(false))), with(aNull(String.class)), with(aNull(String.class)), with(any(String.class)));
			will(new Action() {
				public void describeTo(Description description) {}

				public Object invoke(Invocation invocation) throws Throwable {
					ArtifactResolve req = (ArtifactResolve) invocation.getParameter(0);
					return buildResponse(req.getID(), false, false, null);
				}
			});
		}});
		handler.setSoapClient(client);
		
		try {
			handler.handleGet(ctx);
			fail("Response is not signed");
		} catch (RuntimeException e) {}
		
		
	}
	
	@Test
	public void testResolveSuccess() throws Exception {
		final ByteArrayOutputStream bos = generateArtifact();
		final SOAPClient client = context.mock(SOAPClient.class);

		context.checking(new Expectations() {{
			allowing(req).getParameter(Constants.SAML_SAMLART); will(returnValue(Base64.encodeBytes(bos.toByteArray())));
			allowing(req).getParameter(Constants.SAML_SAMLRESPONSE); will(returnValue(null));
			one(req).getParameter(Constants.SAML_RELAYSTATE); will(returnValue(LoggedInHandler.getInstance().getID(session, new LogUtil(getClass(), "test"))));
			one(client).wsCall(with(any(XMLObject.class)), with(any(LogUtil.class)), with(equal(idpMetadata.getMetadata("idp1.test.oio.dk").getArtifactResolutionServiceLocation(SAMLConstants.SAML2_SOAP11_BINDING_URI))), with(aNull(String.class)), with(aNull(String.class)), with(any(Boolean.class)));
			will(new Action() {
				public void describeTo(Description description) {}

				public Object invoke(Invocation invocation) throws Throwable {
					ArtifactResolve req = (ArtifactResolve) invocation.getParameter(0);
					return buildResponse(req.getID(), true, false, null);
				}
			});
			atLeast(1).of(session).getAttribute(Constants.SESSION_REQUESTURI); will(returnValue("requesturi"));
			atLeast(1).of(session).getAttribute(Constants.SESSION_QUERYSTRING); will(returnValue("query"));
			one(session).setAttribute(with(equal(Constants.SESSION_USER_ASSERTION)), with(any(UserAssertion.class)));
			one(res).sendRedirect("requesturi?query");
		}});
		handler.setSoapClient(client);
		
		handler.handleGet(ctx);
	}
	
	@Test
	public void testPassive() throws Exception {
		final ByteArrayOutputStream bos = generateArtifact();
		final SOAPClient client = context.mock(SOAPClient.class);

		conf.put(Constants.PROP_PASSIVE, "true");
		conf.put(Constants.PROP_PASSIVE_USER_ID, "passive");
		final String reqId = LoggedInHandler.getInstance().getID(session, new LogUtil(getClass(), "test"));
		LoggedInHandler.getInstance().registerRequest(reqId, idpEntityId);
		
		context.checking(new Expectations() {{
			allowing(req).getParameter(Constants.SAML_SAMLART); will(returnValue(Base64.encodeBytes(bos.toByteArray())));
			allowing(req).getParameter(Constants.SAML_SAMLRESPONSE); will(returnValue(null));
			one(req).getParameter(Constants.SAML_RELAYSTATE); will(returnValue(LoggedInHandler.getInstance().getID(session, new LogUtil(getClass(), "test"))));
			one(client).wsCall(with(any(XMLObject.class)), with(any(LogUtil.class)), with(equal(idpMetadata.getMetadata("idp1.test.oio.dk").getArtifactResolutionServiceLocation(SAMLConstants.SAML2_SOAP11_BINDING_URI))), with(aNull(String.class)), with(aNull(String.class)), with(any(Boolean.class)));
			will(new Action() {
				public void describeTo(Description description) {}

				public Object invoke(Invocation invocation) throws Throwable {
					ArtifactResolve req = (ArtifactResolve) invocation.getParameter(0);
					return buildResponse(req.getID(), true, true, reqId);
				}
			});
			atLeast(1).of(session).getAttribute(Constants.SESSION_REQUESTURI); will(returnValue("requesturi"));
			atLeast(1).of(session).getAttribute(Constants.SESSION_QUERYSTRING); will(returnValue("query"));
			one(session).setAttribute(with(equal(Constants.SESSION_USER_ASSERTION)), with(any(PassiveUserAssertion.class)));
			one(res).sendRedirect("requesturi?query");
		}});
		handler.setSoapClient(client);
		
		handler.handleGet(ctx);
	}
		
	private Envelope buildResponse(String id, boolean sign, boolean passive, String reqId) throws Exception {
		ArtifactResponse res = SAMLUtil.buildXMLObject(ArtifactResponse.class);
		res.setDestination(spMetadata.getEntityID());
		res.setIssuer(SAMLUtil.createIssuer(idpEntityId));
		
		res.setInResponseTo(id);
		res.setStatus(SAMLUtil.createStatus(StatusCode.SUCCESS_URI));
		
		Response samlResponse = SAMLUtil.buildXMLObject(Response.class);
		samlResponse.setInResponseTo(reqId);
		
		if (!passive) {
			samlResponse.setStatus(SAMLUtil.createStatus(StatusCode.SUCCESS_URI));
			Assertion assertion = buildAssertion(spMetadata.getAssertionConsumerServiceLocation(0), spMetadata.getEntityID());
	
			samlResponse.getAssertions().add(assertion);
		} else {
			samlResponse.setStatus(SAMLUtil.createStatus(StatusCode.RESPONDER_URI));
			StatusCode status = SAMLUtil.buildXMLObject(StatusCode.class);
			status.setValue(StatusCode.NO_PASSIVE_URI);
			samlResponse.getStatus().getStatusCode().setStatusCode(status);
		}
		res.setMessage(samlResponse);
		
		if (sign) {
			Signature signature = SAMLUtil.createSignature("test");
			signature.setSigningCredential(credential);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			samlResponse.setSignature(signature);

			org.opensaml.xml.Configuration.getMarshallerFactory().getMarshaller(res).marshall(res);
			Signer.signObject(signature);			
		}
		
		Envelope env = SAMLUtil.buildXMLObject(Envelope.class);
		Body body = SAMLUtil.buildXMLObject(Body.class);
		env.setBody(body);
		body.getUnknownXMLObjects().add(res);
		return env;
	}

	private ByteArrayOutputStream generateArtifact() throws IOException,
			NoSuchAlgorithmException, UnsupportedEncodingException {
		final ByteArrayOutputStream bos = new ByteArrayOutputStream();
		bos.write(SAML2ArtifactType0004.TYPE_CODE);
		bos.write(0);
		bos.write(0);
		MessageDigest md = MessageDigest.getInstance(OIOSAMLConstants.SHA_HASH_ALGORHTM);
		bos.write(md.digest("idp1.test.oio.dk".getBytes("UTF-8")));
		bos.write("12345678901234567890".getBytes());
		return bos;
	}
}
