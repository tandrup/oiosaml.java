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

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnStatement;

import dk.itst.oiosaml.sp.model.OIOAssertion;

public class BasicAssertionValidator implements AssertionValidator {

	public void validate(OIOAssertion assertion, String spEntityId, String spAssertionConsumerURL) throws ValidationException {
		Assertion a = assertion.getAssertion();
		
    	// There must be an IssueInstant
    	if (a.getIssueInstant() == null) {  
    		throw new ValidationException("The assertion must contain a IssueInstant");
    	}

    	// There must be an Issuer
    	if (a.getIssuer() == null ||
    		a.getIssuer().getValue() == null) {  
    		throw new ValidationException("The assertion must contain an Issuer");
    	}

    	// There must be a Subject/NameID
    	if (assertion.getSubjectNameIDValue() == null) {  
    		throw new ValidationException("The assertion must contain a Subject/NameID");
    	}
    	// There must be a valid recipient
    	if (!assertion.checkRecipient(spAssertionConsumerURL)) {
    		throw new ValidationException("The assertion must contain the recipient "+ spAssertionConsumerURL);
    	}
		
    	// There must be a valid audience
    	if (!checkAudience(spEntityId, a)) {
    		throw new ValidationException("The assertion must contain the service provider "+spEntityId+" within the Audience");
    	}

    	checkConditionTime(a);
    	
    	// Session must not have expired
    	AuthnStatement authnStatement = (AuthnStatement) a.getAuthnStatements().get(0);
    	if (authnStatement.getSessionNotOnOrAfter() != null &&
    		!authnStatement.getSessionNotOnOrAfter().isAfterNow()) {  
    		throw new ValidationException("The assertion must have a AuthnStatement@SessionNotOnOrAfter and it must not have expired. SessionNotOnOrAfter: " + authnStatement.getSessionNotOnOrAfter());
    	}
	}

	/**
	 * Check whether an assertion has a given serviceProviderEntityID as
	 * Audience
	 * 
	 * @param serviceProviderEntityID
	 *            The entityID of the service provider which has to appear as
	 *            Audience
	 * @return <code>true</code>, if the assertion contains the
	 *         serviceProviderEntityID as Audience. <code>false</code>
	 *         otherwise.
	 */
	public boolean checkAudience(String serviceProviderEntityID, Assertion assertion) {
		if (serviceProviderEntityID == null) return false;
		if (assertion.getConditions() == null) return false;
		
		for (AudienceRestriction audienceRestriction : assertion.getConditions().getAudienceRestrictions()) {
			for (Audience audience : audienceRestriction.getAudiences()) {
				if (serviceProviderEntityID.equals(audience.getAudienceURI())) {
					return true;
				}
			}
		}
		return false;
	}
	
	public void checkConditionTime(Assertion assertion) {
		if (assertion.getConditions() == null) throw new ValidationException("No conditions");
		DateTime notOnOrAfter = assertion.getConditions().getNotOnOrAfter();
		if (notOnOrAfter == null) throw new ValidationException("No NotOnOrAfter time");
		if (!notOnOrAfter.isAfterNow()) {
			throw new ValidationException("Condition NotOnOrAfter is after now: " + notOnOrAfter);
		}
	}

	

}


