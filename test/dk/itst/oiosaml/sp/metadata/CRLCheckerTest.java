package dk.itst.oiosaml.sp.metadata;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.security.credential.Credential;

import dk.itst.oiosaml.error.InvalidCertificateException;
import dk.itst.oiosaml.sp.AbstractTests;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.util.Constants;


public class CRLCheckerTest extends AbstractTests {
	
	private IdpMetadata idp;
	private CRLChecker checker;
	private Credential cred;


	@Before
	public void setUp() throws Exception {
		cred = TestHelper.getCredential();
		EntityDescriptor buildIdPMetadata = TestHelper.buildEntityDescriptor(cred);
		
		idp = new IdpMetadata(SAMLConstants.SAML20P_NS, buildIdPMetadata);
		checker = new CRLChecker();
	}
	
	@After
	public void stopTimer() {
		checker.stopChecker();
	}
	

	@Test
	public void testCheckCertificatesWithNoRevoked() throws Exception {
		checker.checkCertificates(idp, TestHelper.buildConfiguration(new HashMap<String, String>()));

		assertNotNull(idp.getFirstMetadata().getCertificate());
	}
	
	
	@Test(expected=InvalidCertificateException.class)
	public void testRevoked() throws Exception {
		X509Certificate cert = (X509Certificate) idp.getFirstMetadata().getCertificate();
		
		X509V2CRLGenerator gen = new X509V2CRLGenerator();
		gen.setThisUpdate(new Date());
		gen.setNextUpdate(new Date(System.currentTimeMillis() + 60000));
		gen.setSignatureAlgorithm("SHA1WithRSA");
		gen.setIssuerDN(new X509Principal("CN=ca"));
		gen.addCRLEntry(cert.getSerialNumber(), new Date(System.currentTimeMillis() - 1000), CRLReason.keyCompromise);
		X509CRL crl = gen.generate(cred.getPrivateKey());
		
		final File crlFile = File.createTempFile("test", "test");
		crlFile.deleteOnExit();
		FileOutputStream fos = new FileOutputStream(crlFile);
		IOUtils.write(crl.getEncoded(), fos);
		fos.close();

		Configuration conf = TestHelper.buildConfiguration(new HashMap<String, String>() {{
			put(Constants.PROP_CRL + idp.getFirstMetadata().getEntityID(), crlFile.toURI().toString());
		}});
		
		checker.checkCertificates(idp, conf);

		idp.getFirstMetadata().getCertificate();
	}

	
	@Test(expected=InvalidCertificateException.class)
	public void testTimer() throws Exception {
		X509Certificate cert = (X509Certificate) idp.getFirstMetadata().getCertificate();

		X509V2CRLGenerator gen = new X509V2CRLGenerator();
		gen.setThisUpdate(new Date());
		gen.setNextUpdate(new Date(System.currentTimeMillis() + 60000));
		gen.setSignatureAlgorithm("SHA1WithRSA");
		gen.setIssuerDN(new X509Principal("CN=ca"));
		X509CRL crl = gen.generate(TestHelper.getCredential().getPrivateKey());

		final File crlFile = File.createTempFile("test", "test");
		crlFile.deleteOnExit();
		FileOutputStream fos = new FileOutputStream(crlFile);
		IOUtils.write(crl.getEncoded(), fos);
		fos.close();

		Configuration conf = TestHelper.buildConfiguration(new HashMap<String, String>() {{
			put(Constants.PROP_CRL + idp.getFirstMetadata().getEntityID(), crlFile.toURI().toString());
		}});
		
		assertNotNull(idp.getFirstMetadata().getCertificate());
		
		checker.startChecker(1, idp, conf);
		Thread.sleep(1500);
		assertNotNull(idp.getFirstMetadata().getCertificate());
		
		gen.addCRLEntry(cert.getSerialNumber(), new Date(System.currentTimeMillis() - 1000), CRLReason.keyCompromise);
		crl = gen.generate(TestHelper.getCredential().getPrivateKey());
		
		fos = new FileOutputStream(crlFile);
		IOUtils.write(crl.getEncoded(), fos);
		fos.close();
		
		Thread.sleep(1500);
		idp.getFirstMetadata().getCertificate();
	}
}
