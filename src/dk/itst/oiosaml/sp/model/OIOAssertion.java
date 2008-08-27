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
package dk.itst.oiosaml.sp.model;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.error.ValidationException;
import dk.itst.oiosaml.sp.util.AttributeUtil;

public class OIOAssertion extends OIOSamlObject {
	private static final Logger log = Logger.getLogger(OIOAssertion.class);
	
	private final Assertion assertion;

	public OIOAssertion(Assertion assertion) {
		super(assertion);
		this.assertion = assertion;
	}
	
	public static OIOAssertion fromResponse(Response response) {
		if (response.getAssertions().isEmpty()) {
			throw new RuntimeException("Didn't get an assertion in ArtifactResponse");
		}
		Assertion assertion = response.getAssertions().get(0);
		return new OIOAssertion(assertion);
	}

	/**
	 * Return the value of the /Subject/NameID element in an assertion
	 * 
	 * @return The value. <code>null</code>, if the assertion does not
	 *         contain the element.
	 */
	public String getSubjectNameIDValue() {
		String retVal = null;
    	if (assertion.getSubject() != null && 
        	assertion.getSubject().getNameID() != null) {
        		retVal =  assertion.getSubject().getNameID().getValue();
        }
    	return retVal;
	}
	
	
	/**
	 * Check whether an assertion contains an assertionConsumerURL
	 * within a subjectConfirmationData having the
	 * subjectConfirmationMethod=urn:oasis:names:tc:SAML:2.0:cm:bearer
	 * 
	 * @return <code>true</code>, if the assertion contains the
	 *         assertionConsumerURL. <code>false</code>
	 *         otherwise.
	 */
	public boolean checkRecipient(String assertionConsumerURL) {
		if (assertionConsumerURL == null) return false;
		if (assertion.getSubject() == null) return false;
		if (assertion.getSubject().getSubjectConfirmations() == null) return false;
		
		
		for (SubjectConfirmation subjectConfirmation : assertion.getSubject().getSubjectConfirmations()) {
			if (!OIOSAMLConstants.METHOD_BEARER.equals(subjectConfirmation.getMethod())) continue;

			SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
			if (subjectConfirmationData == null) continue;
			
			if (assertionConsumerURL.equals(subjectConfirmationData.getRecipient())) {
				return true;
			}
		}
		return false;
	}
	
	public void checkConfirmationTime() {
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
	public boolean checkAudience(String serviceProviderEntityID) {
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
	
	public void checkConditionTime() {
		if (assertion.getConditions() == null) throw new ValidationException("No conditions");
		DateTime notOnOrAfter = assertion.getConditions().getNotOnOrAfter();
		if (notOnOrAfter == null) throw new ValidationException("No NotOnOrAfter time");
		if (!notOnOrAfter.isAfterNow()) {
			throw new ValidationException("Condition NotOnOrAfter is after now: " + notOnOrAfter);
		}
	}

	/**
	 * Return the value of the /AuthnStatement@SessionIndex element in an assertion
	 * 
	 * @return The value. <code>null</code>, if the assertion does not
	 *         contain the element.
	 */
	public String getSessionIndex() {
		String retVal = null;
    	if (assertion != null && assertion.getAuthnStatements() != null) {
    		if (assertion.getAuthnStatements().size() > 0) {
    			// We only look into the first AuthnStatement
    			AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);
    			retVal = authnStatement.getSessionIndex();
    		}
    	}
    	return retVal;
	}

	/**
	 * Check whether an assertion contains an expired sessionIndex within a
	 * AuthnStatement (i.e. AuthnStatement@SessionNotOnOrAfter >= now)
	 * 
	 * @return <code>true</code>, if the assertion has expired. <code>false</code>
	 *         otherwise.
	 */
	public boolean hasSessionExpired() {
		boolean retVal = false;
    	if (assertion != null && assertion.getAuthnStatements() != null) {
			if (assertion.getAuthnStatements().size() > 0) {
				// We only look into the first AuthnStatement
				AuthnStatement authnStatement = (AuthnStatement) assertion
						.getAuthnStatements().get(0);
				if (authnStatement.getSessionNotOnOrAfter() != null) {
					retVal = authnStatement.getSessionNotOnOrAfter()
							.isBeforeNow();
				} else {
					retVal = false;
				}
			}
		}
		return retVal;
	}

	/**
	 * Return the value of the /AuthnStatement/AuthnContext/AuthnContextClassRef
	 * element in an assertion
	 * 
	 * @return The value. <code>null</code>, if the assertion does not
	 *         contain the element.
	 */
	public String getAuthnContextClassRef() {
		String retVal = null;
    	if (assertion.getAuthnStatements() != null) {
    		if (assertion.getAuthnStatements().size() > 0) {
    			// We only look into the first AuthnStatement
    			AuthnStatement authnStatement = (AuthnStatement) assertion.getAuthnStatements().get(0);
    			AuthnContext authnContext = authnStatement.getAuthnContext();
    			if (authnContext != null) {
    				AuthnContextClassRef authnContextClassRef = authnContext.getAuthnContextClassRef();
    				if (authnContextClassRef != null) {
    					retVal = authnContextClassRef.getAuthnContextClassRef();
    				}
    			}
    		}
    	}
    	return retVal;
	}

    /**
     * Validate whether a SAML assertion contains the expected elements
     * @param spEntityID The entityID of the service provider
     * @param spAssertionConsumerURL The assertion consumer URL of the service provider
     */
    public void validateAssertion(String spEntityID, String spAssertionConsumerURL) throws ValidationException {
    	try {
			assertion.validate(false);
		} catch (org.opensaml.xml.validation.ValidationException e) {
			throw new ValidationException(e);
		}
    	// There must be an ID
    	if (assertion.getID() == null) {  
    		throw new ValidationException("The assertion must contain a ID");
    	}
    	// There must be an IssueInstant
    	if (assertion.getIssueInstant() == null) {  
    		throw new ValidationException("The assertion must contain a IssueInstant");
    	}

    	// The SAML versioni must be 2.0
    	if (!SAMLVersion.VERSION_20.equals(assertion.getVersion())) {  
    		throw new ValidationException("The assertion must be version 2.0. Was " + assertion.getVersion());
    	}

    	// There must be an Issuer
    	if (assertion.getIssuer() == null ||
    		assertion.getIssuer().getValue() == null) {  
    		throw new ValidationException("The assertion must contain an Issuer");
    	}

    	// There must be a Subject/NameID
    	if (getSubjectNameIDValue() == null) {  
    		throw new ValidationException("The assertion must contain a Subject/NameID");
    	}
    	// There must be a valid recipient
    	if (!checkRecipient(spAssertionConsumerURL)) {
    		throw new ValidationException("The assertion must contain the recipient "+ spAssertionConsumerURL);
    	}
    	checkConfirmationTime();
    	checkConditionTime();

    	// There must be a valid audience
    	if (!checkAudience(spEntityID)) {
    		throw new ValidationException("The assertion must contain the service provider "+spEntityID+" within the Audience");
    	}
    	// There must be only be one AuthnStatement within the assertion
    	if (assertion.getAuthnStatements().size() != 1) {  
    		throw new ValidationException("The assertion must contain exactly one AuthnStatement. Was " + assertion.getAuthnStatements().size());
    	}
    	// AssuranceLevel and AuthnStatement/AuthnContext/AuthnContextClassRef must be consistent
    	int assuranceLevel = getAssuranceLevel();
    	String authnContextClassRefValue = null;
    	AuthnStatement authnStatement = (AuthnStatement) assertion.getAuthnStatements().get(0);
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
    	if (getSessionIndex() == null) {  
    		throw new ValidationException("The assertion must contain a AuthnStatement@SessionIndex");
    	}
    	// Session must not have expired
    	if (authnStatement.getSessionNotOnOrAfter() != null &&
    		!authnStatement.getSessionNotOnOrAfter().isAfterNow()) {  
    		throw new ValidationException("The assertion must have a AuthnStatement@SessionNotOnOrAfter and it must not have expired. SessionNotOnOrAfter: " + authnStatement.getSessionNotOnOrAfter());
    	}
    	// There must be exactly one AttributeStatement within the assertion
    	if (assertion.getAttributeStatements().size() != 1) {  
    		throw new ValidationException("The assertion must contain exactly one AttributeStatement. Contains " + assertion.getAttributeStatements().size());
    	}
    	// There must not be a AttributeStatement within the assertion
    	if (assertion.getAuthzDecisionStatements().size() != 0) {  
    		throw new ValidationException("The assertion must not contain a AuthzDecisionStatement. Contains " + assertion.getAuthzDecisionStatements().size());
    	}
    }

    public Assertion getAssertion() {
    	return assertion;
    }
    
    public int getAssuranceLevel() {
    	for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
    		for (Attribute attribute : attributeStatement.getAttributes()) {
				if (OIOSAMLConstants.ATTRIBUTE_ASSURANCE_LEVEL_NAME.equals(attribute.getName())) {
					String value = AttributeUtil.extractAttributeValueValue(attribute);
					return new AssuranceLevel(value).getValue();
				}
			}
		}
    	return 0;
    }
    
    public String getID() {
    	return assertion.getID();
    }
}
