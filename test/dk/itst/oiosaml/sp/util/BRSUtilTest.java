package dk.itst.oiosaml.sp.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.List;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.AbstractXMLObject;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;

import dk.itst.oiosaml.sp.model.BRSSAMLConstants;
import dk.itst.oiosaml.sp.util.BRSUtil;

public class BRSUtilTest {

	static {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new RuntimeException(e);
		}
	}
	
	@Test
	public void testBuildXMLObject() {
		XMLObject o = BRSUtil.buildXMLObject(Assertion.class);
		assertNotNull(o);
		assertTrue(o instanceof Assertion);
		assertEquals(Assertion.DEFAULT_ELEMENT_NAME, o.getElementQName());
		try {
			BRSUtil.buildXMLObject(TestObject.class);
			fail("test should be unknown");
		} catch (InvalidParameterException e) {}
	}
	
	public static class TestObject extends AbstractXMLObject {
		public static QName DEFAULT_ELEMENT_NAME = new QName("uri:test", "name", "t");
		public TestObject() {
			super("uri:test", "name", "t");
		}
		
		public List<XMLObject> getOrderedChildren() {
			return null;
		}		
	}

	@Test
	public void testCreateIssuer() {
		Issuer issuer = BRSUtil.createIssuer("val");
		assertNotNull(issuer);
		assertEquals("val", issuer.getValue());
		
		issuer = BRSUtil.createIssuer(null);
		assertNull(issuer);
	}

	@Test
	public void testCreateNameID() {
		NameID name = BRSUtil.createNameID("name");
		assertNotNull(name);
		assertEquals("name", name.getValue());
		assertEquals(BRSSAMLConstants.PERSISTENT, name.getFormat());
	}

	@Test
	public void testCreateSessionIndex() {
		SessionIndex idx = BRSUtil.createSessionIndex("idx");
		assertNotNull(idx);
		assertEquals("idx", idx.getSessionIndex());
		
		idx = BRSUtil.createSessionIndex(null);
		assertNull(idx.getSessionIndex());
	}

	@Test
	public void testCreateSubject() {
		DateTime dateTime = new DateTime();
		Subject sub = BRSUtil.createSubject("name", "url", dateTime);
		assertNotNull(sub);
		assertEquals("name", sub.getNameID().getValue());
		assertEquals(1, sub.getSubjectConfirmations().size());
		assertEquals(BRSSAMLConstants.METHOD_BEARER, sub.getSubjectConfirmations().get(0).getMethod());
		assertEquals("url", sub.getSubjectConfirmations().get(0).getSubjectConfirmationData().getRecipient());
		assertEquals(dateTime.toDate().getTime(), sub.getSubjectConfirmations().get(0).getSubjectConfirmationData().getNotOnOrAfter().toDate().getTime());
		assertNull(sub.getSubjectConfirmations().get(0).getSubjectConfirmationData().getNotBefore());
		assertNull(sub.getSubjectConfirmations().get(0).getSubjectConfirmationData().getAddress());
		assertNotNull(sub.getSubjectConfirmations().get(0).getSubjectConfirmationData().getIDIndex());
	}

	@Test
	public void testCreateAuthnContext() {
		AuthnContext ac = BRSUtil.createAuthnContext("ref");
		assertNotNull(ac);
		assertNull(ac.getAuthContextDecl());
		assertTrue(ac.getAuthenticatingAuthorities().isEmpty());
		assertNull(ac.getAuthnContextDeclRef());
		
		AuthnContextClassRef cr = ac.getAuthnContextClassRef();
		assertNotNull(cr);
		assertEquals("ref", cr.getAuthnContextClassRef());
	}

	@Test
	public void testCreateAudienceCondition() {
		Conditions ac = BRSUtil.createAudienceCondition("uri");
		assertNotNull(ac);
		assertEquals(1, ac.getConditions().size());
		assertNull(ac.getNotBefore());
		assertNull(ac.getNotOnOrAfter());
		assertNull(ac.getProxyRestriction());
		assertNull(ac.getOneTimeUse());
		
		AudienceRestriction ar = ac.getAudienceRestrictions().get(0);
		assertEquals(1, ar.getAudiences().size());
		Audience audience = ar.getAudiences().get(0);
		assertEquals("uri", audience.getAudienceURI());
	}

	@Test
	public void testCreateArtifact() {
		Artifact a = BRSUtil.createArtifact("value");
		assertNotNull(a);
		assertEquals("value", a.getArtifact());
		
		a = BRSUtil.createArtifact(null);
		assertNull(a.getArtifact());
	}

	@Test
	public void testCreateStatus() {
		Status s = BRSUtil.createStatus("status");
		assertNotNull(s);
		assertNull(s.getStatusDetail());
		assertNull(s.getStatusMessage());
		assertNotNull(s.getStatusCode());
		
		assertEquals("status", s.getStatusCode().getValue());
	}

	@Test
	public void testCreateSignature() {
		Signature s = BRSUtil.createSignature("key");
		assertNotNull(s);
		assertNull(s.getCanonicalizationAlgorithm());
		assertTrue(s.getContentReferences().isEmpty());
		assertNull(s.getHMACOutputLength());
		assertNull(s.getSignatureAlgorithm());
		assertNull(s.getSigningCredential());
		
		KeyInfo ki = s.getKeyInfo();
		assertNotNull(ki);
		assertTrue(ki.getAgreementMethods().isEmpty());
		assertTrue(ki.getEncryptedKeys().isEmpty());
		assertNull(ki.getID());
		assertTrue(ki.getMgmtDatas().isEmpty());
		assertTrue(ki.getPGPDatas().isEmpty());
		assertTrue(ki.getRetrievalMethods().isEmpty());
		assertTrue(ki.getSPKIDatas().isEmpty());
		assertTrue(ki.getX509Datas().isEmpty());
		assertTrue(ki.getKeyValues().isEmpty());
		
		assertEquals(1, ki.getKeyNames().size());
		
		assertEquals("key", ki.getKeyNames().get(0).getValue());
	}

	@Test
	public void testUnmarshallElement() throws IOException {
		XMLObject xo = BRSUtil.unmarshallElement("../model/assertion.xml");
		assertTrue(xo instanceof Assertion);
		
		try {
			BRSUtil.unmarshallElement("test");
			fail("file should not be found");
		} catch (IllegalArgumentException e) {}
	}

	@Test
	public void testUnmarshallElementFromString() {
		XMLObject xo = BRSUtil.unmarshallElementFromString("<saml:Assertion Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"></saml:Assertion>");
		assertTrue(xo instanceof Assertion);
		
		try {
			BRSUtil.unmarshallElementFromString("<invalid>");
			fail("no unmarshaller should be available");
		} catch (IllegalArgumentException e) {}
	}

	@Test
	public void testUnmarshallElementFromFile() throws IOException {
		File file = File.createTempFile("test", ".xml");
		FileOutputStream os = new FileOutputStream(file);
		os.write("<saml:Assertion Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"></saml:Assertion>".getBytes());
		os.close();
		
		XMLObject xo = BRSUtil.unmarshallElementFromFile(file.getAbsolutePath());
		assertTrue(xo instanceof Assertion);
		
		assertNull(BRSUtil.unmarshallElementFromFile("/test/temp"));
	}

	@Test
	public void testGetSAMLObjectAsPrettyPrintXML() {
		Artifact a = BRSUtil.createArtifact("a");
		String pretty = BRSUtil.getSAMLObjectAsPrettyPrintXML(a);
		assertNotNull(pretty);
		assertEquals("<?xml version=\"1.0\" encoding=\"UTF-8\"?><samlp:Artifact xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">a</samlp:Artifact>", pretty.trim().replaceAll("\n", ""));
		
		try {
			BRSUtil.getSAMLObjectAsPrettyPrintXML(null);
		} catch (IllegalArgumentException e) {}
	}


}
