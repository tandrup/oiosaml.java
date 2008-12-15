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
package dk.itst.oiosaml.sp.model.validation;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.ParserConfigurationException;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.xml.io.UnmarshallingException;
import org.xml.sax.SAXException;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.AbstractTests;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.OIOAssertionTest;
import dk.itst.oiosaml.sp.util.AssertionStubImpl;
import dk.itst.oiosaml.sp.util.AudienceRestrictionStubImpl;
import dk.itst.oiosaml.sp.util.AudienceStubImpl;
import dk.itst.oiosaml.sp.util.ConditionsStubImpl;

public class OIOSAMLAssertionValidatorTest extends AbstractTests {
	private static final String serviceProviderEntityId = "poc3.eogs.capgemini.dk.spref";

	private OIOAssertion assertion;
	private OIOSAMLAssertionValidator validator;

	@Before
	public void setUp() throws SAXException, IOException, ParserConfigurationException, UnmarshallingException {
		Assertion assertion = (Assertion) SAMLUtil.unmarshallElement(OIOAssertionTest.class.getResourceAsStream("assertion.xml"));

		assertion.getAuthnStatements().get(0).setSessionNotOnOrAfter(new DateTime().plus(60000));
		assertion.getConditions().setNotOnOrAfter(new DateTime().plus(60000));
		assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(new DateTime().plus(60000));
		
		this.assertion = new OIOAssertion(assertion);
		validator = new OIOSAMLAssertionValidator();
	}

	@Test(expected=ValidationException.class)
	public void checkConfirmationTimeFailOnNoSubject() {
		assertion.getAssertion().setSubject(null);
		validator.checkConfirmationTime(assertion.getAssertion());
	}
	
	@Test(expected=ValidationException.class)
	public void checkConfirmationTimeFailOnNoSubjectConfirmation() {
		assertion.getAssertion().getSubject().getSubjectConfirmations().clear();
		validator.checkConfirmationTime(assertion.getAssertion());
	}
	
	@Test(expected=ValidationException.class)
	public void checkConfirmationTimeFailOnExpired() {
		assertion.getAssertion().getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(new DateTime().minus(1000));
		validator.checkConfirmationTime(assertion.getAssertion());
	}

	@Test(expected=ValidationException.class)
	public void checkConfirmationTimeFailOnNoDate() {
		assertion.getAssertion().getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(null);
		validator.checkConfirmationTime(assertion.getAssertion());
	}

	@Test
	public void testCheckConfirmationTime() {
		assertion.getAssertion().getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(new DateTime().plus(10000));
		validator.checkConfirmationTime(assertion.getAssertion());
	}
	
	@Test
	public void testCheckConditionTime() {
		assertion.getAssertion().getConditions().setNotOnOrAfter(new DateTime().plus(10000));
		validator.checkConditionTime(assertion.getAssertion());
	}
	
	@Test(expected=ValidationException.class)
	public void checkConditionTimeFailOnNoTime() {
		assertion.getAssertion().getConditions().setNotOnOrAfter(null);
		validator.checkConditionTime(assertion.getAssertion());
	}
	
	@Test(expected=ValidationException.class)
	public void checkConditionTimeFailOnExpired() {
		assertion.getAssertion().getConditions().setNotOnOrAfter(new DateTime().minus(1000));
		validator.checkConditionTime(assertion.getAssertion());
	}
	
	@Test(expected=ValidationException.class)
	public void checkConditionTimeFailOnNoConditions() {
		assertion.getAssertion().setConditions(null);
		validator.checkConditionTime(assertion.getAssertion());
	}

	@Test
	public void checkAudience() {
		String expectedServiceProviderEntityID = "someString";

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

		assertTrue(validator.checkAudience(expectedServiceProviderEntityID, localAssertion));

		audience.setAudienceURI("unexpected string");
		assertFalse(validator.checkAudience(expectedServiceProviderEntityID, localAssertion));

		assertFalse(validator.checkAudience(null, localAssertion));

		assertTrue(validator.checkAudience(serviceProviderEntityId, assertion.getAssertion()));
	}


}
