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
package dk.itst.oiosaml.sp.service.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;

import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.model.OIOSamlObject;
import dk.itst.oiosaml.sp.util.BRSUtil;

public class HttpSOAPClient implements SOAPClient {
	private static final String START_SOAP_ENVELOPE = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" + "<soapenv:Header/><soapenv:Body>";
	private static final String END_SOAP_ENVELOPE = "</soapenv:Body></soapenv:Envelope>";
	private static final Logger log = Logger.getLogger(HttpSOAPClient.class);

	public XMLObject wsCall(OIOSamlObject obj, LogUtil lu, String location, String username, String password, boolean ignoreCertPath) throws IOException {
		lu.beforeService("", location, Constants.SERVICE_ARTIFACT_RESOLVE, null);
		return wsCall(lu, location, username, password, ignoreCertPath, obj.toSoapEnvelope());
	}
	
	public XMLObject wsCall(XMLObject obj, LogUtil lu, String location, String username, String password, boolean ignoreCertPath) throws IOException {
		
		lu.beforeService("", location, Constants.SERVICE_ARTIFACT_RESOLVE, null);

		String xml = XMLHelper.nodeToString(BRSUtil.marshallObject(obj));
		xml = START_SOAP_ENVELOPE + xml.substring(xml.indexOf("?>") + 2) + END_SOAP_ENVELOPE;

		return wsCall(lu, location, username, password, ignoreCertPath, xml);
	}

	public XMLObject wsCall(LogUtil lu, String location, String username, String password, boolean ignoreCertPath, String xml) throws IOException, MalformedURLException, ProtocolException {
		URI serviceLocation;
		try {
			serviceLocation = new URI(location);
		} catch (URISyntaxException e) {
			throw new IOException("Invalid uri for artifact resolve: " + location);
		}
		if (log.isDebugEnabled()) log.debug("serviceLocation..:" + serviceLocation);
		if (log.isDebugEnabled()) log.debug("SOAP Request: " + xml);

		HttpURLConnection c = (HttpURLConnection) serviceLocation.toURL().openConnection();
		if (c instanceof HttpsURLConnection) {
			HttpsURLConnection sc = (HttpsURLConnection) c;
			if (ignoreCertPath) {
				try {
					sc.setSSLSocketFactory(new EasySSLProtocolSocketFactory());
				} catch (GeneralSecurityException e) {
					throw new RuntimeException("Unable to construct easy ssl factory", e);
				} 
			}
		}
		c.setAllowUserInteraction(false);
		c.setDoInput(true);
		c.setDoOutput(true);
		c.setFixedLengthStreamingMode(xml.getBytes().length);
		c.setRequestMethod("POST");
		c.setReadTimeout(20000);
		c.setConnectTimeout(30000);
		
		c.addRequestProperty("Content-Type", "text/xml; charset=utf-8");
		c.addRequestProperty("SOAPAction", "http://www.oasis-open.org/committees/security");
		
		if (username != null && password != null) {
			c.addRequestProperty("Authorization", "Basic " + Base64.encodeBytes((username + ":" + password).getBytes(), Base64.DONT_BREAK_LINES));
		}
		OutputStream outputStream = c.getOutputStream();
		IOUtils.write(xml, outputStream, "UTF-8");
		outputStream.flush();
		outputStream.close();
		
		if (c.getResponseCode() == 200) {
			InputStream inputStream = c.getInputStream();
			String result = IOUtils.toString(inputStream, "UTF-8");
			inputStream.close();
			
			lu.afterService(Constants.SERVICE_ARTIFACT_RESOLVE);
			
			Envelope envelope = (Envelope) BRSUtil.unmarshallElementFromString(result);
			return envelope.getBody().getUnknownXMLObjects().get(0);
		} else {
			InputStream inputStream = c.getErrorStream();
			String result = IOUtils.toString(inputStream, "UTF-8");
			inputStream.close();
			
			throw new IOException("Server returned status " + c.getResponseCode() + ", result: " + result);
		}
	}

}
