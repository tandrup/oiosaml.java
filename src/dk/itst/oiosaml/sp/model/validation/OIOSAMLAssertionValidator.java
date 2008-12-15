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
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.sp.model.AssuranceLevel;
import dk.itst.oiosaml.sp.model.OIOAssertion;

public class OIOSAMLAssertionValidator extends BasicAssertionValidator {
	private static final Logger log = Logger.getLogger(OIOSAMLAssertionValidator.class);

	public void validate(OIOAssertion assertion, String spEntityId, String spAssertionConsumerURL) throws ValidationException {
		super.validate(assertion, spEntityId, spAssertionConsumerURL);
		
		Assertion a = assertion.getAssertion();
    	checkConfirmationTime(a);

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

}
