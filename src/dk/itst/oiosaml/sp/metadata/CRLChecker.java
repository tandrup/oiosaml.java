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
package dk.itst.oiosaml.sp.metadata;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.commons.configuration.Configuration;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.service.util.Constants;

public class CRLChecker {
	private static final Logger log = Logger.getLogger(CRLChecker.class);
	
	private Timer timer;

	public void checkCertificates(IdpMetadata metadata, Configuration conf) {
		for (String entityId : metadata.getEntityIDs()) {
			Metadata md = metadata.getMetadata(entityId);
			
			String url = conf.getString(Constants.PROP_CRL + entityId);
			log.debug("Checking CRL for " + entityId + " at " + url);
			if (url == null) {
				log.debug("No CRL configured for " + entityId + ". Set " + Constants.PROP_CRL + entityId + " in configuration");
				byte[] val = md.getCertificate().getExtensionValue("2.5.29.31");
				if (val != null) {
					try {
						CRLDistPoint point = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(val));
						for (DistributionPoint dp : point.getDistributionPoints()) {
							if (dp.getDistributionPoint() == null) continue;
							
							if (dp.getDistributionPoint().getName() instanceof GeneralNames) {
								GeneralNames gn = (GeneralNames) dp.getDistributionPoint().getName();
								for (GeneralName g : gn.getNames()) {
									if (g.getName() instanceof DERIA5String) {
										url =((DERIA5String)g.getName()).getString();
									}
								}
							}
						}
					} catch (IOException e) {
						throw new RuntimeException(e);
					}
				}
			}
			if (url == null) {
				log.debug("No CRL configured in oiosaml-sp.properties, and no CRL found in certificate");
				continue;
			}
			
			try {
				URL u = new URL(url);
				InputStream is = u.openStream();
				
		        CertificateFactory  cf = CertificateFactory.getInstance("X.509");
		        X509CRL crl = (X509CRL) cf.generateCRL(is);
		        is.close();
		        
		        if (log.isDebugEnabled()) log.debug("CRL for " + url + ": " + crl);

		        md.setCertificateValid(true);
		        X509CRLEntry revokedCertificate = crl.getRevokedCertificate(md.getCertificate().getSerialNumber());
		        boolean revoked = revokedCertificate != null;
		        log.debug("Certificate status for " + entityId + ": " + revoked + " - cert: " + md.getCertificate());
		        Audit.log(Operation.CRLCHECK, false, entityId, "Revoked: " + revoked);
		        
		        md.setCertificateValid(!revoked);
			} catch (MalformedURLException e) {
				log.error("Unable to parse url " + url, e);
				throw new WrappedException(Layer.BUSINESS, e);
			} catch (IOException e) {
				log.error("Unable to read CRL from " + url, e);
				throw new WrappedException(Layer.BUSINESS, e);
			} catch (GeneralSecurityException e) {
				throw new WrappedException(Layer.BUSINESS, e);
			}
		}
	}
	
	public void startChecker(long period, final IdpMetadata metadata, final Configuration conf) {
		if (timer != null) return;
		
		log.info("Starting CRL checker, running with " + period + " seconds interval. Checking " + metadata.getEntityIDs().size() + " certificates");
		timer = new Timer("CRLChecker");
		timer.schedule(new TimerTask() {
			public void run() {
				log.debug("Running CRL checker task");
				
				try {
					checkCertificates(metadata, conf);
				} catch (Exception e) {
					log.error("Unable to run CRL checker", e);
				}
			}
		}, 1000L, 1000L * period);
		
	}
	
	public void stopChecker() {
		if (timer != null) {
			log.info("Stopping CRL checker");
			timer.cancel();
			timer = null;
		}
	}
}
