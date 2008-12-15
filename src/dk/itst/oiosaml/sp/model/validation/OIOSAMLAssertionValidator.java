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

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.sp.model.AssuranceLevel;
import dk.itst.oiosaml.sp.model.OIOAssertion;

public class OIOSAMLAssertionValidator implements AssertionValidator {
	private static final Logger log = Logger.getLogger(OIOSAMLAssertionValidator.class);

	public void validate(OIOAssertion assertion, String spEntityId, String spAssertionConsumerURL) throws ValidationException {
		Assertion a = assertion.getAssertion();
    	try {
			a.validate(false);
		} catch (org.opensaml.xml.validation.ValidationException e) {
			throw new ValidationException(e);
		}
    	// There must be an ID
    	if (a.getID() == null) {  
    		throw new ValidationException("The assertion must contain a ID");
    	}
    	// There must be an IssueInstant
    	if (a.getIssueInstant() == null) {  
    		throw new ValidationException("The assertion must contain a IssueInstant");
    	}

    	// The SAML versioni must be 2.0
    	if (!SAMLVersion.VERSION_20.equals(a.getVersion())) {  
    		throw new ValidationException("The assertion must be version 2.0. Was " + a.getVersion());
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
    	checkConfirmationTime(a);
    	checkConditionTime(a);

    	// There must be a valid audience
    	if (!checkAudience(spEntityId, a)) {
    		throw new ValidationException("The assertion must contain the service provider "+spEntityId+" within the Audience");
    	}
    	// There must be only be one AuthnStatement within the assertion
    	if (a.getAuthnStatements().size() != 1) {  
    		throw new ValidationException("The assertion must contain exactly one AuthnStatement. Was " + a.getAuthnStatements().size());
    	}
    	// AssuranceLevel and AuthnStatement/AuthnContext/AuthnContextClassRef must be consistent
    	int assuranceLevel = assertion.getAssuranceLevel();
    	String authnContextClassRefValue = null;
    	AuthnStatement authnStatement = (AuthnStatement) a.getAuthnStatements().get(0);
    	AuthnContext authnContext = authnStatement.getAuthnContext();
    	if (authnContext != null) {
    		AuthnContextClassRef authnContextClassRef = authnContext.getAuthnContextClassRef();
    		if (authnContextClassRef != null) {
    			authnContextClassRefValue = authnContextClassRef.getAuthnContextClassRef();
    		}
    	}
    	if (assuranceLevel == AssuranceLevel.PASSWORD_ASSURANCE_LEVEL && 
    		!OIOSAMLConstants.PASSWORD_AUTHN_CONTEXT_CLASS_REF.equals(authnContextClassRefValue)) {
    		log.warn("The assuranceLevel attribute " + assuranceLevel + "  in the assertion does not correspond with the value of AuthnStatement/AuthnContext/AuthnContextClassRef: " + authnContextClassRefValue);
    	} else if (assuranceLevel == AssuranceLevel.CERTIFICATE_ASSURANCE_LEVEL && 
    		!OIOSAMLConstants.X509_AUTHN_CONTEXT_CLASS_REF.equals(authnContextClassRefValue)) {
    		log.warn("The assuranceLevel attribute " + assuranceLevel + "  in the assertion does not correspond with the value of AuthnStatement/AuthnContext/AuthnContextClassRef: " + authnContextClassRefValue);
       	}
    	
    	// There must be a SessionIndex
    	if (assertion.getSessionIndex() == null) {  
    		throw new ValidationException("The assertion must contain a AuthnStatement@SessionIndex");
    	}
    	// Session must not have expired
    	if (authnStatement.getSessionNotOnOrAfter() != null &&
    		!authnStatement.getSessionNotOnOrAfter().isAfterNow()) {  
    		throw new ValidationException("The assertion must have a AuthnStatement@SessionNotOnOrAfter and it must not have expired. SessionNotOnOrAfter: " + authnStatement.getSessionNotOnOrAfter());
    	}
    	// There must be exactly one AttributeStatement within the assertion
    	if (a.getAttributeStatements().size() != 1) {  
    		throw new ValidationException("The assertion must contain exactly one AttributeStatement. Contains " + a.getAttributeStatements().size());
    	}
    	// There must not be a AttributeStatement within the assertion
    	if (a.getAuthzDecisionStatements().size() != 0) {  
    		throw new ValidationException("The assertion must not contain a AuthzDecisionStatement. Contains " + a.getAuthzDecisionStatements().size());
    	}

	}

	public void checkConfirmationTime(Assertion assertion) throws ValidationException {
		if (assertion.getSubject() == null) throw new ValidationException("No subject");
		if (assertion.getSubject().getSubjectConfirmations() == null || 
				assertion.getSubject().getSubjectConfirmations().isEmpty()) throw new ValidationException("No subject confirmations");
		
		for (SubjectConfirmation subjectConfirmation : assertion.getSubject().getSubjectConfirmations()) {
			SubjectConfirmationData data = subjectConfirmation.getSubjectConfirmationData();
			
			if (data != null && data.getNotOnOrAfter() != null) {
				if (!data.getNotOnOrAfter().isAfterNow()) {
					throw new ValidationException("Subject Confirmation Data is expired: " + data.getNotOnOrAfter() + " before " + new DateTime());
				}
			} else {
				throw new ValidationException("No Subject Confirmation Date");
			}
		}
	}

	public void checkConditionTime(Assertion assertion) {
		if (assertion.getConditions() == null) throw new ValidationException("No conditions");
		DateTime notOnOrAfter = assertion.getConditions().getNotOnOrAfter();
		if (notOnOrAfter == null) throw new ValidationException("No NotOnOrAfter time");
		if (!notOnOrAfter.isAfterNow()) {
			throw new ValidationException("Condition NotOnOrAfter is after now: " + notOnOrAfter);
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
	
}
