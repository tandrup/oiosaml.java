package dk.itst.oiosaml.sp.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.parsers.ParserConfigurationException;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.xml.io.UnmarshallingException;
import org.xml.sax.SAXException;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.ValidationException;
import dk.itst.oiosaml.sp.AbstractTests;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.util.AssertionStubImpl;
import dk.itst.oiosaml.sp.util.AudienceRestrictionStubImpl;
import dk.itst.oiosaml.sp.util.AudienceStubImpl;
import dk.itst.oiosaml.sp.util.AuthnContextClassRefStubImpl;
import dk.itst.oiosaml.sp.util.AuthnContextStubImpl;
import dk.itst.oiosaml.sp.util.AuthnStatementStubImpl;
import dk.itst.oiosaml.sp.util.ConditionsStubImpl;
import dk.itst.oiosaml.sp.util.NameIDStubImpl;
import dk.itst.oiosaml.sp.util.SubjectConfirmationDataStubImpl;
import dk.itst.oiosaml.sp.util.SubjectConfirmationStubImpl;
import dk.itst.oiosaml.sp.util.SubjectStubImpl;

public class OIOAssertionTest extends AbstractTests {
	private OIOAssertion assertion;
	private final String assertionConsumerURL = "http://jre-mac.trifork.com:8080/saml/SAMLAssertionConsumer";
	private final String serviceProviderEntityId = "poc3.eogs.capgemini.dk.spref";


	@Before
	public void setUp() throws SAXException, IOException, ParserConfigurationException, UnmarshallingException {
		Assertion assertion = (Assertion) SAMLUtil.unmarshallElement(getClass().getResourceAsStream("assertion.xml"));

		assertion.getAuthnStatements().get(0).setSessionNotOnOrAfter(new DateTime().plus(60000));
		assertion.getConditions().setNotOnOrAfter(new DateTime().plus(60000));
		assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(new DateTime().plus(60000));
		
		this.assertion = new OIOAssertion(assertion);
	}


	@Test
	public void getSubjectNameIDValue() {
		String expectedValue = "testvalue";

		NameID nameid = new NameIDStubImpl();
		nameid.setValue(expectedValue);

		Subject subject = new SubjectStubImpl();
		subject.setNameID(nameid);

		Assertion localAssertion = new AssertionStubImpl();
		localAssertion.setSubject(subject);

		assertEquals(expectedValue, new OIOAssertion(localAssertion).getSubjectNameIDValue());

		assertEquals("joetest", assertion.getSubjectNameIDValue());
	}

	@Test
	public void checkRecipient() {
		String requiredMethodBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

		assertFalse(assertion.checkRecipient(null));
		assertFalse(new OIOAssertion(new AssertionStubImpl()).checkRecipient(new String()));

		Assertion localAssertion = new AssertionStubImpl();
		localAssertion.setSubject(new SubjectStubImpl());

		assertFalse(assertion.checkRecipient(""));


		SubjectConfirmation subjectConfirmation = new SubjectConfirmationStubImpl();
		subjectConfirmation.setMethod(requiredMethodBearer);

		SubjectConfirmationData subConfData = new SubjectConfirmationDataStubImpl();
		String expectedRecipient = "recipient";
		subConfData.setRecipient(expectedRecipient);
		subjectConfirmation.setSubjectConfirmationData(subConfData);

		Subject subject = new SubjectStubImpl(Collections.singletonList(subjectConfirmation));
		localAssertion.setSubject(subject);
		OIOAssertion la = new OIOAssertion(localAssertion);

		assertTrue(la.checkRecipient(expectedRecipient));

		subConfData.setRecipient("something else");
		assertFalse(la.checkRecipient(expectedRecipient));

		subjectConfirmation.setMethod("not requiredBearer");
		assertFalse(la.checkRecipient(expectedRecipient));

		assertTrue(assertion.checkRecipient(assertionConsumerURL));
	}
	
	@Test(expected=ValidationException.class)
	public void checkConfirmationTimeFailOnNoSubject() {
		assertion.getAssertion().setSubject(null);
		assertion.checkConfirmationTime();
	}
	
	@Test(expected=ValidationException.class)
	public void checkConfirmationTimeFailOnNoSubjectConfirmation() {
		assertion.getAssertion().getSubject().getSubjectConfirmations().clear();
		assertion.checkConfirmationTime();
	}
	
	@Test(expected=ValidationException.class)
	public void checkConfirmationTimeFailOnExpired() {
		assertion.getAssertion().getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(new DateTime().minus(1000));
		assertion.checkConfirmationTime();
	}

	@Test(expected=ValidationException.class)
	public void checkConfirmationTimeFailOnNoDate() {
		assertion.getAssertion().getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(null);
		assertion.checkConfirmationTime();
	}

	@Test
	public void testCheckConfirmationTime() {
		assertion.getAssertion().getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(new DateTime().plus(10000));
		assertion.checkConfirmationTime();
	}
	
	@Test
	public void testCheckConditionTime() {
		assertion.getAssertion().getConditions().setNotOnOrAfter(new DateTime().plus(10000));
		assertion.checkConditionTime();
	}
	
	@Test(expected=ValidationException.class)
	public void checkConditionTimeFailOnNoTime() {
		assertion.getAssertion().getConditions().setNotOnOrAfter(null);
		assertion.checkConditionTime();
	}
	
	@Test(expected=ValidationException.class)
	public void checkConditionTimeFailOnExpired() {
		assertion.getAssertion().getConditions().setNotOnOrAfter(new DateTime().minus(1000));
		assertion.checkConditionTime();
	}
	
	@Test(expected=ValidationException.class)
	public void checkConditionTimeFailOnNoConditions() {
		assertion.getAssertion().setConditions(null);
		assertion.checkConditionTime();
	}

	@Test
	public void checkAudience() {
		String expectedServiceProviderEntityID = new String("someString");

		Audience audience = new AudienceStubImpl();
		audience.setAudienceURI(expectedServiceProviderEntityID);

		List<Audience> audiences = new ArrayList<Audience>();
		audiences.add(audience);

		AudienceRestriction audienceRestriction = new AudienceRestrictionStubImpl(audiences);

		List<AudienceRestriction> audienceRestrictions = new ArrayList<AudienceRestriction>();
		audienceRestrictions.add(audienceRestriction);

		Conditions conditions = new ConditionsStubImpl(audienceRestrictions);

		Assertion localAssertion = new AssertionStubImpl();
		localAssertion.setConditions(conditions);
		OIOAssertion la = new OIOAssertion(localAssertion);

		assertTrue(la.checkAudience(expectedServiceProviderEntityID));

		audience.setAudienceURI("unexpected string");
		assertFalse(la.checkAudience(expectedServiceProviderEntityID));

		assertFalse(la.checkAudience(null));

		assertTrue(assertion.checkAudience(serviceProviderEntityId));
	}

	@Test
	public void getSessionIndex() {
		String expectedSessionIndex = "expected SessionIndex";

		AuthnStatement authnStatement = new AuthnStatementStubImpl();
		authnStatement.setSessionIndex(expectedSessionIndex);

		List<AuthnStatement> authnStatements = new ArrayList<AuthnStatement>();
		authnStatements.add(authnStatement);

		Assertion assertion = new AssertionStubImpl(authnStatements);

		assertEquals(expectedSessionIndex, new OIOAssertion(assertion).getSessionIndex());
	}

	@Test
	public void hasSessionExpired() {
		AuthnStatement authnStatement= new AuthnStatementStubImpl();
		authnStatement.setSessionNotOnOrAfter(new DateTime().minus(10000));

		List<AuthnStatement> authnStatements = new ArrayList<AuthnStatement>();
		authnStatements.add(authnStatement);

		Assertion localAssertion = new AssertionStubImpl(authnStatements);

		assertTrue(new OIOAssertion(localAssertion).hasSessionExpired());

		assertFalse(new OIOAssertion(new AssertionStubImpl(new ArrayList<AuthnStatement>())).hasSessionExpired());

		assertion.getAssertion().getAuthnStatements().get(0).setSessionNotOnOrAfter(new DateTime().plus(60000));
		assertFalse(assertion.hasSessionExpired());

	}

	@Test
	public void getAuthnContextClassRef() {

		String expectedAuthnContextClassRefString = "expected string";
		AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefStubImpl();
		authnContextClassRef.setAuthnContextClassRef(expectedAuthnContextClassRefString);

		AuthnContext authnContext = new AuthnContextStubImpl();
		authnContext.setAuthnContextClassRef(authnContextClassRef);

		AuthnStatement authnStatement= new AuthnStatementStubImpl();
		authnStatement.setAuthnContext(authnContext);

		List<AuthnStatement> authnStatements = new ArrayList<AuthnStatement>();
		authnStatements.add(authnStatement);

		Assertion assertion = new AssertionStubImpl(authnStatements);

		assertEquals(expectedAuthnContextClassRefString, new OIOAssertion(assertion).getAuthnContextClassRef());
	}

	@Test
	public void validateAssertion() throws Exception {
		assertion.validateAssertion(serviceProviderEntityId, assertionConsumerURL);
	}

	@Test
	public void validateAssertionShouldFailForNoId() throws Exception {
		InvocationHandler handler = new InvocationHandler() {
			private int cnt = 0;
			public Object invoke(Object proxy, Method method, Object[] args)
			throws Throwable {
				if(method.getName().equals("getID")) {
					if(cnt == 0) {
						cnt++;
						return null;
					} else {
						return "";
					}
				}
				return method.invoke(assertion, args);
			}};

			try {
				OIOAssertion ah = new OIOAssertion(getProxiedAssertion(handler));
				ah.validateAssertion(serviceProviderEntityId, assertionConsumerURL);
				fail("Assertion util should have failed");
			} catch(Exception e) {}
	}

	@Test
	public void validateAssertionShouldFailForNoIssueInstant() throws Exception {
		InvocationHandler handler = new InvocationHandler() {
			public Object invoke(Object proxy, Method method, Object[] args)
			throws Throwable {
				if(method.getName().equals("getIssueInstant")) {
						return null;
				}
				return method.invoke(assertion, args);
			}};

			try {
				OIOAssertion ah = new OIOAssertion(getProxiedAssertion(handler));
				ah.validateAssertion(serviceProviderEntityId, assertionConsumerURL);
				fail("Assertion util should have failed");
			} catch(Exception e) {}
	}
	
	@Test
	public void validateAssertionShouldFailForWrongSamlVersion() throws Exception {
		assertion.validateAssertion(serviceProviderEntityId, assertionConsumerURL);
		
		InvocationHandler handler = new InvocationHandler() {
			private int cnt = 0;
			public Object invoke(Object proxy, Method method, Object[] args)
			throws Throwable {
				if(method.getName().equals("getVersion")) {
					if(cnt == 0) {
						cnt++;
						return SAMLVersion.VERSION_10;
					} else {
						return SAMLVersion.VERSION_11;
					}
				}
				return method.invoke(assertion, args);
			}};

			OIOAssertion ah = new OIOAssertion(getProxiedAssertion(handler));
			try {
				ah.validateAssertion(serviceProviderEntityId, assertionConsumerURL);
				fail("Assertion util should not accept saml 1.0");
			} catch(Exception e) {}
			
			ah = new OIOAssertion(getProxiedAssertion(handler));
			try {
				ah.validateAssertion(serviceProviderEntityId, assertionConsumerURL);
				fail("Assertion util should not accept saml 1.1");
			} catch(Exception e) {}
	}


	@Test
	public void validateAssertionShouldFailForNoIssuer() throws Exception {
		InvocationHandler handler = new InvocationHandler() {
			private int aCnt =0, iCnt = 0;
			private Issuer issuer =  (Issuer)Proxy.newProxyInstance(getClass().getClassLoader(), new Class[]{Issuer.class}, new InvocationHandler() {
				public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
					if(iCnt == 0) {
						iCnt++;
						return null;
					} else {
						return "";
					}
				}
				
			});
			public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
				if (method.getName().equals("getIssuer")) {
						if(aCnt == 0) {
							aCnt++;
							return null;
						} else {
							return issuer;
						}
				} else {
					return method.invoke(assertion, args);
				}
			}
		};
		
		try {
			OIOAssertion ah = new OIOAssertion(getProxiedAssertion(handler));
			ah.validateAssertion(serviceProviderEntityId, assertionConsumerURL);
			fail("Assertion util should have failed");
		} catch(Exception e) {}
	}

	@Test
	public void validateAssertionShouldFailForNoSubjectNameIdValue() {
		NameID nameid = new NameIDStubImpl();
		nameid.setValue(null);

		Subject subject = new SubjectStubImpl();
		subject.setNameID(nameid);

		assertion.getAssertion().setSubject(subject);
				
		try {
			assertion.validateAssertion(serviceProviderEntityId, assertionConsumerURL);
			fail("Assertion util should have failed");
		} catch(Exception e) {}
		
		nameid.setValue("");
		
		try {
			assertion.validateAssertion(serviceProviderEntityId, assertionConsumerURL);
			fail("Assertion util should have failed");
		} catch(Exception e) {}

	}

	@Test
	public void testGetAssuranceLevel() throws Exception {
		assertEquals(2, assertion.getAssuranceLevel());

		assertion.getAssertion().getAttributeStatements().get(0).getAttributes().clear();
		
		assertEquals(0, assertion.getAssuranceLevel());
	}
	

	private Assertion getProxiedAssertion(InvocationHandler handler) {
		return (Assertion)Proxy.newProxyInstance(
				this.getClass().getClassLoader(), 
				new Class[]{Assertion.class},
				handler);
	}

}
