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
 *   Aage Nielsen <ani@openminds.dk>
 *   Carsten Larsen <cas@schultz.dk>
 *
 */
package dk.itst.oiosaml.sp.metadata;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.apache.commons.configuration.Configuration;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.i18n.filter.UntrustedUrlInput;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.opensaml.xml.security.x509.X509Credential;

import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
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
 * OCSP with Distribution Point from configuration. OCSP with Distribution Point
 * from certificates. CRL with Distribution Point from configuration. CRL with
 * Distribution Point from certificates.
 * 
 * Methods are evaluated from top to bottom until a suitable method is found. In
 * case none of the methods are applicable a log entry will be generated
 * specifying the lack of CLR validation.
 * 
 */
public class CRLChecker {
	private static final Logger log = LoggerFactory.getLogger(CRLChecker.class);
	private static final String AUTH_INFO_ACCESS = X509Extension.authorityInfoAccess.getId();
	private Timer timer;

	public void checkCertificates(IdpMetadata metadata, Configuration conf) {
		for (String entityId : metadata.getEntityIDs()) {
			Metadata md = metadata.getMetadata(entityId);

			for (X509Certificate certificate : md.getAllCertificates()) {

				try {
					if (doOCSPCheck(conf, entityId, md, certificate)) {
						Audit.log(Operation.OCSPCHECK, false, entityId, "Revoked: NO");
						continue;
					}

					if (doCRLCheck(conf, entityId, md, certificate)) {
						Audit.log(Operation.CRLCHECK, false, entityId, "Revoked: NO");
						continue;
					}

					md.setCertificateValid(certificate, false);

					log.debug("Revocation check failed or could not be performed. Permanent failure.");

					Audit.log(Operation.CRLCHECK, false, entityId, "Revoked: YES");

				} catch (Exception e) {
					log.error("Unexpected error while checking revokation of certificates.", e);

					Audit.log(Operation.CRLCHECK, false, entityId,
							"Unable to perform revocation check. certificate is state is set to - Revoked: YES");

					// Default to non-valid certificate.
					if (certificate != null && md != null)
						md.setCertificateValid(certificate, false);

					throw new WrappedException(Layer.BUSINESS, e);
				}
			}
		}
	}

	/**
	 * Check the revocation status of a public key certificate using OCSP.
	 * 
	 * @param conf
	 * @param entityId
	 * @param md
	 * @param certificate
	 * @return true if an OCSP check was completed, otherwise false.
	 * @throws CertificateException
	 */
	private boolean doOCSPCheck(Configuration conf, String entityId, Metadata md, X509Certificate certificate)
			throws CertificateException {
		String ocspServer = getOCSPUrl(conf, entityId, certificate);

		if (ocspServer == null) {
			log.debug("No OCSP access location could be found for " + entityId);
			return false;
		}

		log.debug("Starting OCSP validation of certificate " + certificate.getSubjectDN());

		X509Certificate ca = getCertificateCA(conf, ocspServer);
		if (ca == null) {
			return false;
		}

		// Create certificate chain
		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		certList.add(certificate);
		certList.add(ca);
		CertPath cp;

		CertificateFactory cf;
		cf = CertificateFactory.getInstance("X.509");
		cp = cf.generateCertPath(certList);

		// Enable OCSP
		Security.setProperty("ocsp.enable", "true");
		Security.setProperty("ocsp.responderURL", ocspServer);

		try {
			TrustAnchor anchor = new TrustAnchor(ca, null);
			PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
			params.setRevocationEnabled(true);

			// Validate and obtain results
			CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
			cpv.validate(cp, params);

			log.debug("Certificate successfully validated.");

		} catch (CertPathValidatorException cpve) {
			log.debug("Validation failure, cert[" + cpve.getIndex() + "] :" + cpve.getMessage());
			return false;
		} catch (NoSuchAlgorithmException e) {
			log.error("Unexpected error while validating certficate using OCSP.", e);
			return false;
		} catch (InvalidAlgorithmParameterException e) {
			log.error("Unexpected error while validating certficate using OCSP.", e);
			return false;
		}

		return true;
	}

	private X509Certificate getCertificateCA(Configuration conf, String certificateUrl) throws CertificateException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate ca = null;
		InputStream is = null;

		try {
			String caPath = conf.getString(Constants.PROP_OCSP_CA);

			if (caPath == null) {
				log.debug("CA certificate path is not configured");
				return null;
			}

			log.debug("Fetching CA certificate located at: " + caPath);

			URL u = new URL(conf.getString(Constants.PROP_OCSP_CA));
			is = u.openStream();
			ca = (X509Certificate) cf.generateCertificate(is);
			is.close();

		} catch (IOException e) {
			log.error("Unable to read CA certficate from: " + certificateUrl, e);
			return null;
		} catch (CertificateException e) {
			log.error("Unable to validate CA certficate from: " + certificateUrl, e);
			return null;
		} catch (Exception e) {
			log.error("Unexpected error while validating CA certficate from: " + certificateUrl, e);
			return null;
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
				}
			}
		}

		return ca;
	}

	/**
	 * Gets an URL to use when performing an OCSP validation of a certificate.
	 * 
	 * @param conf
	 * @param entityId
	 * @param certificate
	 * @return the URL to use.
	 * @see <a href="http://oid-info.com/get/1.3.6.1.5.5.7.48.1">http://oid-info.com/get/1.3.6.1.5.5.7.48.1</a>
	 */
	private String getOCSPUrl(Configuration conf, String entityId, X509Certificate certificate) {
		String url = conf.getString(Constants.PROP_OCSP_RESPONDER);

		if (url != null) {
			return url;
		}

		log.debug("No OCSP configured for " + entityId + " attempting to extract OCSP location from certificate "
				+ certificate.getSubjectDN());

		AuthorityInformationAccess authInfoAcc = null;
		ASN1InputStream aIn = null;

		try {
			byte[] bytes = certificate.getExtensionValue(AUTH_INFO_ACCESS);
			aIn = new ASN1InputStream(bytes);
			ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
			aIn = new ASN1InputStream(octs.getOctets());
			ASN1Primitive auth_info_acc = aIn.readObject();

			if (auth_info_acc != null) {
				authInfoAcc = AuthorityInformationAccess.getInstance(auth_info_acc);
			}
		} catch (Exception e) {
			log.debug("Cannot extract access location of OCSP responder.", e);
			return null;
		} finally {
			if (aIn != null) {
				try {
					aIn.close();
				} catch (IOException e) {
				}
			}
		}

		List<String> ocspUrls = getOCSPUrls(authInfoAcc);
		Iterator<String> urlIt = ocspUrls.iterator();

		while (urlIt.hasNext()) {
			// Just return the first URL
			Object ocspUrl = new UntrustedUrlInput(urlIt.next());
			url = ocspUrl.toString();
		}

		return url;
	}

	private List<String> getOCSPUrls(AuthorityInformationAccess authInfoAccess) {
		List<String> urls = new ArrayList<String>();

		if (authInfoAccess != null) {
			AccessDescription[] ads = authInfoAccess.getAccessDescriptions();
			for (int i = 0; i < ads.length; i++) {
				if (ads[i].getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
					GeneralName name = ads[i].getAccessLocation();
					if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
						String url = ((DERIA5String) name.getName()).getString();
						urls.add(url);
					}
				}
			}
		}

		return urls;
	}

	/**
	 * Perform revocation check using CRL.
	 * 
	 * @param conf
	 * @param entityId
	 * @param md
	 * @param certificate
	 * @return true if CRL check was completed and the certificate is not
	 *         revoked.
	 */
	private boolean doCRLCheck(Configuration conf, String entityId, Metadata md, X509Certificate certificate) {
		String url = getCRLUrl(conf, entityId, certificate);

		if (url == null) {
			log.debug("No CRL url could be found for " + entityId);
			return false;
		}

		InputStream is = null;

		try {
			URL u = new URL(url);
			is = u.openStream();

			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509CRL crl = (X509CRL) cf.generateCRL(is);

			log.debug("CRL for " + url + ": " + crl);

			if (!checkCRLSignature(crl, certificate, conf)) {
				return false;
			}

			X509CRLEntry revokedCertificate = crl.getRevokedCertificate(certificate.getSerialNumber());
			if (revokedCertificate != null) {
				log.debug("Certificate found in revocation list " + certificate.getSubjectDN());
				return false;
			}

			return true;

		} catch (MalformedURLException e) {
			log.error("Unable to parse url " + url, e);
			return false;
		} catch (IOException e) {
			log.error("Unable to read CRL from " + url, e);
			return false;
		} catch (GeneralSecurityException e) {
			log.error("Unexpected error reading CRL from " + url, e);
			return false;
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
				}
			}
		}
	}

	/**
	 * Get an URL to use when downloading CRL
	 * 
	 * @param conf
	 * @param entityId
	 * @param certificate
	 * @return the URL to use
	 */
	private String getCRLUrl(Configuration conf, String entityId, X509Certificate certificate) {
		String url = conf.getString(Constants.PROP_CRL + entityId);

		if (url != null) {
			return url;
		}

		log.debug("No CRL configured for " + entityId + " attempting to extract distribution point from certificate "
				+ certificate.getSubjectDN());

		byte[] val = certificate.getExtensionValue("2.5.29.31");

		if (val != null) {
			try {
				CRLDistPoint point = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(val));
				for (DistributionPoint dp : point.getDistributionPoints()) {
					if (dp.getDistributionPoint() == null)
						continue;

					if (dp.getDistributionPoint().getName() instanceof GeneralNames) {
						GeneralNames gn = (GeneralNames) dp.getDistributionPoint().getName();
						for (GeneralName g : gn.getNames()) {
							if (g.getName() instanceof DERIA5String) {
								url = ((DERIA5String) g.getName()).getString();
							}
						}
					}
				}
			} catch (IOException e) {
				log.debug("Cannot extract distribution point for certificate.", e);
				throw new RuntimeException(e);
			}
		}

		return url;
	}

	/**
	 * Check whether a certificate revocation list (CRL) has a valid signature.
	 * 
	 * @param crl
	 * @param certificate
	 * @param conf
	 * @return true if signature is valid, otherwise false.
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws IllegalStateException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws WrappedException
	 */
	private boolean checkCRLSignature(X509CRL crl, X509Certificate certificate, Configuration conf)
			throws WrappedException, NoSuchAlgorithmException, CertificateException, IllegalStateException,
			KeyStoreException, IOException {
		if (conf.getString(Constants.PROP_CRL_TRUSTSTORE, null) == null)
			return true;

		CredentialRepository cr = new CredentialRepository();
		cr.getCertificate(SAMLConfigurationFactory.getConfiguration().getKeystore(),
				conf.getString(Constants.PROP_CRL_TRUSTSTORE_PASSWORD), null);

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

	public void startChecker(long period, final IdpMetadata metadata, final Configuration conf) {
		if (timer != null)
			return;

		String proxyHost = conf.getString(Constants.PROP_HTTP_PROXY_HOST);
		String proxyPort = conf.getString(Constants.PROP_HTTP_PROXY_PORT);

		if (proxyHost != null && proxyPort != null) {
			log.debug("Enabling use of proxy " + proxyHost + " port " + proxyPort
					+ " when checking revocation of certificates.");

			System.setProperty("http.proxyHost", proxyHost);
			System.setProperty("http.proxyPort", proxyPort);
		}

		log.info("Starting CRL checker, running with " + period + " seconds interval. Checking "
				+ metadata.getEntityIDs().size() + " certificates");
		timer = new Timer("CRLChecker");
		timer.schedule(new TimerTask() {
			@Override
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
