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

import java.io.IOException;
import java.security.cert.Certificate;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.credential.Credential;

import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.service.util.SOAPClient;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.sp.util.BRSUtil;

public class OIOAttributeQuery extends OIORequest {
	private static final Logger log = Logger.getLogger(OIOAttributeQuery.class);
	
	private final AttributeQuery request;

	public OIOAttributeQuery(AttributeQuery request) {
		super(request);
		this.request = request;
	}

	public static OIOAttributeQuery newQuery(String endpointLocation, String nameId, String spEntityId) {
		
		org.opensaml.saml2.core.AttributeQuery q = BRSUtil.buildXMLObject(org.opensaml.saml2.core.AttributeQuery.class);
		q.setVersion(SAMLVersion.VERSION_20);
		
		Subject subject = BRSUtil.createSubject(nameId, endpointLocation, new DateTime().plusMinutes(5));
		q.setSubject(subject);
		
		q.setDestination(endpointLocation);
		q.setIssueInstant(new DateTime());
		q.setID(Utils.generateUUID());
		q.setIssuer(BRSUtil.createIssuer(spEntityId));
		q.setConsent("urn:oasis:names:tc:SAML:2.0:consent:current-implicit");
		
		return new OIOAttributeQuery(q);
	}
	
	public void addAttribute(String name, String format) {
		Attribute a = BRSUtil.buildXMLObject(Attribute.class);
		a.setName(name);
		a.setNameFormat(format);
		request.getAttributes().add(a);
	}

	public OIOAssertion executeQuery(SOAPClient client, Credential credential, String username, String password, boolean ignoreCertPath, Certificate idpCertificate, boolean allowUnencryptedAssertion) throws IOException {
		sign(credential);
		LogUtil lu = new LogUtil(getClass(), "", "AttributeQuery");
		XMLObject res = client.wsCall(this, lu, getDestination(), username, password, ignoreCertPath);
		if (!(res instanceof Response)) throw new IllegalStateException("Received wrong type from IdP (expected Response): " + res);
		
		OIOResponse oiores = new OIOResponse((Response) res);
		if (log.isDebugEnabled()) log.debug("Received attribute query response: " + oiores.toXML());
		
		oiores.decryptAssertion(credential, allowUnencryptedAssertion);
		oiores.validateResponse(null, idpCertificate, false);
		
		return oiores.getAssertion();
	}
	
}
