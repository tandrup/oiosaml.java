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
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PolicyNode;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import org.apache.commons.configuration.Configuration;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.opensaml.xml.security.x509.X509Credential;

import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.service.util.Constants;

/**
 * Revocation of certificates are done using the follow methods.
 * 
 *   OCSP with Distribution Point from configuration.
 *   OCSP with Distribution Point from certificates.
 *   CRL with Distribution Point from configuration.
 *   CRL with Distribution Point from certificates.
 *
 * Methods are evaluated from top to bottom until a suitable method is found.
 * In case none of the methods are applicable a log entry will be generated
 * specifying the lack of CLR validation.
 * 
 */
public class CRLChecker {
	private static final Logger log = Logger.getLogger(CRLChecker.class);
	
	private Timer timer;
	
	public void checkCertificates(IdpMetadata metadata, Configuration conf) {
		for (String entityId : metadata.getEntityIDs()) {
			Metadata md = metadata.getMetadata(entityId);

			for (X509Certificate certificate : md.getAllCertificates()) {
				
				try {
					if (!doOCSPCheck(conf, entityId, md, certificate))
					{
						log.debug("No OCSP configured in oiosaml-sp.properties, and no OCSP found in certificate.");
					}
					else
					{
						continue;
					}
						
					if (!doCLRCheck(conf, entityId, md, certificate))
					{
						log.debug("No CRL configured in oiosaml-sp.properties, and no CRL found in certificate.");
						log.debug("No revokation check was done. Permenent failure.");
						
						Audit.log(Operation.CRLCHECK, false, entityId, "Revoked: YES");

						md.setCertificateValid(certificate, false);
					}
					
					Audit.log(Operation.CRLCHECK, false, entityId, "Revoked: NO");
					log.debug("Certificate status for " + entityId + ": revoked - cert: " + certificate);
					
					md.setCertificateValid(certificate, true);
				}
				catch (Exception e)
				{
					throw new WrappedException(Layer.BUSINESS, e);
				}
			}
		}
	}
	
	/**
	 * Perform revocation check using CRL.
	 * @param conf
	 * @param entityId
	 * @param md
	 * @param certificate
	 * @return true if CRL check was completed and the certificate is not revoked.
	 */
	private boolean doCLRCheck(Configuration conf, String entityId, Metadata md, X509Certificate certificate)
	{
		String url = getCRLUrl(conf, entityId, certificate);
		
		if (url == null) {
			return false;
		}

		try {
			URL u = new URL(url);
			InputStream is = u.openStream();

			CertificateFactory  cf = CertificateFactory.getInstance("X.509");
			X509CRL crl = (X509CRL) cf.generateCRL(is);
			is.close();

			if (log.isDebugEnabled()) log.debug("CRL for " + url + ": " + crl);

			if (!checkCRLSignature(crl, certificate, conf)) {
				md.setCertificateValid(certificate, false);
			} else {
				X509CRLEntry revokedCertificate = crl.getRevokedCertificate(certificate.getSerialNumber());
				return (revokedCertificate == null);
			}
		} catch (MalformedURLException e) {
			log.error("Unable to parse url " + url, e);
			throw new WrappedException(Layer.BUSINESS, e);
		} catch (IOException e) {
			log.error("Unable to read CRL from " + url, e);
			throw new WrappedException(Layer.BUSINESS, e);
		} catch (GeneralSecurityException e) {
			throw new WrappedException(Layer.BUSINESS, e);
		}
		
		return true;
	}
	
	/**
	 * Get an URL to use when downloading CRL
	 * @param conf
	 * @param entityId
	 * @param certificate
	 * @return the URL to use
	 */
	private String getCRLUrl(Configuration conf, String entityId, X509Certificate certificate) {
		String url = conf.getString(Constants.PROP_CRL + entityId);
		log.debug("Checking CRL for " + entityId + " at " + url);
		
		if (url == null) {
			log.debug("No CRL configured for " + entityId + ". Set " + Constants.PROP_CRL + entityId + " in configuration");
			byte[] val = certificate.getExtensionValue("2.5.29.31");
			
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
		return url;
	}
	
	/**
	 * Check whether a certificate revocation list (CRL) has a valid signature.
	 * @param crl
	 * @param certificate
	 * @param conf
	 * @return true if signature is valid, otherwise false.
	 */
	private boolean checkCRLSignature(X509CRL crl, X509Certificate certificate, Configuration conf) {
		if (conf.getString(Constants.PROP_CRL_TRUSTSTORE, null) == null) return true;
		
		CredentialRepository cr = new CredentialRepository();
		String location = SAMLConfiguration.getStringPrefixedWithBRSHome(conf, Constants.PROP_CRL_TRUSTSTORE);
		cr.getCertificate(location, conf.getString(Constants.PROP_CRL_TRUSTSTORE_PASSWORD), null);

		for (X509Credential cred : cr.getCredentials()) {
			try {
				crl.verify(cred.getPublicKey());
			} catch (Exception e) {
				log.debug("CRL not signed by " + cred);
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * Check the revocation status of a public key certificate using OCSP.
	 * @param  conf
	 * @param  entityId
	 * @param  md
	 * @param  certificate
	 * @return true if an OCSP check was completed, otherwise false.
	 * @throws CertificateException 
	 */
	private boolean doOCSPCheck(Configuration conf, String entityId, Metadata md, X509Certificate certificate) throws CertificateException
	{
		String ocspServer = getOCSPUrl(conf, entityId, certificate);
		
		if (ocspServer == null) {
			return false;
		}

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate ca = null;
		
		try {
			log.debug("Using CA certificate located at: " +  conf.getString(Constants.PROP_OCSP_CA));
			
			// Fetch CA certificate		
			URL u = new URL(conf.getString(Constants.PROP_OCSP_CA));
			InputStream is = u.openStream();
			ca = (X509Certificate) cf.generateCertificate(is);
			is.close();
		}
		catch (IOException e)
		{			
			throw new WrappedException(Layer.BUSINESS, e);
		}
		catch (CertificateException e)
		{
			throw new WrappedException(Layer.BUSINESS, e);
		}
		
		// Create certificate chain
        List certList = new Vector();
        certList.add(certificate);
        certList.add(ca);
		CertPath cp;
		
		cf = CertificateFactory.getInstance("X.509");
		cp = cf.generateCertPath(certList);

	    // Enable OCSP
	    Security.setProperty("ocsp.enable", "true");
		Security.setProperty("ocsp.responderURL", ocspServer);
		//Security.setProperty("ocsp.responderCertSubjectName", ocspCert.getSubjectX500Principal().getName());
	    
        try {
    		TrustAnchor anchor = new TrustAnchor(ca, null);
    		PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
	        params.setRevocationEnabled(true);
        	
	        // Validate and obtain results
        	CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
    		PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
  
            // Logging
    	    log.debug("Certificate validated");
    	    X509Certificate trustedCert = (X509Certificate) result.getTrustAnchor().getTrustedCert();
    	    
    	    if (trustedCert == null) {
    	    	log.debug("Trsuted Cert = NULL");
    	    } else {
    	    	log.debug("Trusted CA DN = " + trustedCert.getSubjectDN());
    	    }

    	    PublicKey subjectPublicKey = result.getPublicKey();
    	    log.debug("Subject Public key:\n" + subjectPublicKey);
    	    
        } catch (CertPathValidatorException cpve) {
        	log.debug("Validation failure, cert[" + cpve.getIndex() + "] :" + cpve.getMessage());
        	return false;
        } catch (NoSuchAlgorithmException e) {
        	throw new WrappedException(Layer.BUSINESS, e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new WrappedException(Layer.BUSINESS, e);
		}
        
		return true;
	}
	
	/**
	 * Gets an URL to use when performing an OCSP validation of a certificate.
	 * @param  conf
	 * @param  entityId
	 * @param  certificate
	 * @return the URL to use.
	 * @see    http://oid-info.com/get/1.3.6.1.5.5.7.48.1
	 */
	private String getOCSPUrl(Configuration conf, String entityId, X509Certificate certificate) {
		//String url = conf.getString(Constants.PROP_OCSP_RESPONDER + entityId);
		String url = conf.getString(Constants.PROP_OCSP_RESPONDER);
		log.debug("Checking OCSP for " + entityId + " at " + url);
		
		if (url == null) {
			//log.debug("No OCSP configured for " + entityId + ". Set " + Constants.PROP_OCSP_RESPONDER + entityId + " in configuration");
			log.debug("No OCSP configured for " + entityId + ". Set " + Constants.PROP_OCSP_RESPONDER + " in configuration");
			byte[] val = certificate.getExtensionValue("1.3.6.1.5.5.7.48.1");

			log.debug("Searching for certificate OCSP responder.");

			if (val != null) {
				try {
					AuthorityInformationAccess point = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(val));
					
					log.debug("AuthorityInformationAccess found: " + point);
					
					for (AccessDescription ad : point.getAccessDescriptions()) {
						if (ad.getAccessLocation() == null) continue;
						log.debug("AccessDescription found: " + ad);
						
						if (ad.getAccessLocation().getName() instanceof GeneralNames) {
							GeneralNames gn = (GeneralNames) ad.getAccessLocation().getName();
							log.debug("GeneralNames found: " + gn);
							
							for (GeneralName g : gn.getNames()) {
								log.debug("GeneralName found: " + g);
								
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
		
		return url;
	}
	
	public void startChecker(long period, final IdpMetadata metadata, final Configuration conf) {
		if (timer != null) return;
		
		String proxyHost = conf.getString(Constants.PROP_HTTP_PROXY_HOST);
		String proxyPort = conf.getString(Constants.PROP_HTTP_PROXY_PORT);
		
		if (proxyHost != null && proxyPort != null)
		{
			log.debug("Enabling use of proxy " + proxyHost + " port " + proxyPort + " when checking revocation of certificates.");
			
			System.setProperty("http.proxyHost", proxyHost);
			System.setProperty("http.proxyPort", proxyPort);
		}
		
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
