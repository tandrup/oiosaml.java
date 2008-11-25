package dk.itst.oiosaml.sp.service.util;

import static dk.itst.oiosaml.sp.service.TestHelper.getParameter;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Document;

import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.model.OIOAuthnRequest;
import dk.itst.oiosaml.sp.model.OIORequest;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;

public class UtilsTest extends AbstractServiceTests {
	RequestAbstractType request;
	@Before
	public void setUp() throws Exception {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		Document doc = documentBuilderFactory.newDocumentBuilder().parse(OIORequest.class.getResourceAsStream("request.xml"));
		Configuration.getBuilderFactory();
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(doc.getDocumentElement());
		request = (RequestAbstractType) unmarshaller.unmarshall(doc.getDocumentElement());
		request.getIssuer().setValue("IssuerValue");
	}

	@Test
	public void testGetCredential() throws Exception {
		Credential cred = TestHelper.getCredential();
		X509Certificate cert = TestHelper.getCertificate(cred);
		
		ByteArrayOutputStream bos = generateKeystore(cred, cert);
		
		BasicX509Credential newCredential = CredentialRepository.createCredential(new ByteArrayInputStream(bos.toByteArray()), "test");
		assertTrue(Arrays.equals(cred.getPublicKey().getEncoded(), newCredential.getPublicKey().getEncoded()));
		assertTrue(Arrays.equals(cred.getPrivateKey().getEncoded(), newCredential.getPrivateKey().getEncoded()));
		
		KeyStore store = KeyStore.getInstance("JKS");
		store.load(null, null);
		store.setKeyEntry("saml", cred.getPrivateKey(), "test".toCharArray(), new Certificate[] { cert });

		bos = new ByteArrayOutputStream();
		store.store(bos, "test".toCharArray());
		bos.close();

		newCredential = CredentialRepository.createCredential(new ByteArrayInputStream(bos.toByteArray()), "test");
		assertTrue(Arrays.equals(cred.getPublicKey().getEncoded(), newCredential.getPublicKey().getEncoded()));
		assertTrue(Arrays.equals(cred.getPrivateKey().getEncoded(), newCredential.getPrivateKey().getEncoded()));
	}

	private ByteArrayOutputStream generateKeystore(Credential cred, X509Certificate cert) throws KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException {
		Security.addProvider(new BouncyCastleProvider());
		KeyStore store = KeyStore.getInstance("JKS");
		store.load(null, null);
		store.setKeyEntry("saml", cred.getPrivateKey(), "test".toCharArray(), new Certificate[] { cert });
		store.setCertificateEntry("samltest", cert);

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		store.store(bos, "test".toCharArray());
		bos.close();
		return bos;
	}
	
	@Test
	public void testGetCertificate() throws Exception {
		Credential cred = TestHelper.getCredential();
		X509Certificate cert = TestHelper.getCertificate(cred);
		
		ByteArrayOutputStream bos = generateKeystore(cred, cert);
		
		File file = File.createTempFile("test", ".keystore");
		file.deleteOnExit();
		IOUtils.write(bos.toByteArray(), new FileOutputStream(file));
		
		assertNotNull(new CredentialRepository().getCertificate(file.getAbsolutePath(), "test", null));
	}

	@Test
	public void testMakeXML() {
		String xml = "<test></test>";
		assertEquals("&lt;test&gt;<br />&lt;/test&gt;", Utils.makeXML(xml));
		
		assertEquals("test", Utils.makeXML("test"));
	}

	@Test
	public void testBeautifyXML() {
		String xml = "<test><more></more></test>";
		assertEquals("<test>\n  <more>\n  </more>\n</test>", Utils.beautifyXML(xml, "  ").trim());
	}

	@Test
	public void testGenerateUUID() {
		assertTrue(Utils.generateUUID().startsWith("_"));
	}

	@Test
	public void testVerifySignature() throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
		OIOAuthnRequest request = OIOAuthnRequest.buildAuthnRequest("http://ssoServiceLocation", "spEntityId", SAMLConstants.SAML2_ARTIFACT_BINDING_URI, session, logUtil);
		String url = request.getRedirectURL(credential, logUtil);
		credential.getPublicKey().getEncoded();
		String signature = getParameter("Signature", url);
		
       byte[] data = url.substring(url. indexOf(Constants.SAML_SAMLREQUEST), url.lastIndexOf("&")).getBytes();

       final PublicKey key = credential.getPublicKey();
       byte[] sig = Base64.decode(URLDecoder.decode(signature, "UTF-8"));
		assertTrue(Utils.verifySignature(data, key, sig));
		
		assertFalse(Utils.verifySignature(new byte[] {}, key, sig));
		assertFalse(Utils.verifySignature(data, key, new byte[] {}));
	}
	
	@Test
	public void testGetSoapVersion() throws Exception {
		String xml = "<?xml version=\"1.0\"?><soap11:Envelope xmlns:test=\"test\" xmlns:soap11=\"http://schemas.xmlsoap.org/soap/envelope/\"></soap11:Envelope>";
		
		assertEquals("http://schemas.xmlsoap.org/soap/envelope/", Utils.getSoapVersion(xml));
		
		xml = "<?xml version=\"1.0\"?><Envelope xmlns:test=\"test\" xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\"></Envelope>";
		assertEquals("http://schemas.xmlsoap.org/soap/envelope/", Utils.getSoapVersion(xml));

		xml = "<?xml version=\"1.0\"?><Envelope xmlns:test=\"test\" xmlns:soap11=\"http://www.w3.org/2003/05/soap-envelope\" xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\"></Envelope>";
		assertEquals("http://schemas.xmlsoap.org/soap/envelope/", Utils.getSoapVersion(xml));
		
		xml = "<?xml version=\"1.0\"?><soap12:Envelope xmlns:test=\"test\" xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\" xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\"></soap12:Envelope>";
		assertEquals("http://www.w3.org/2003/05/soap-envelope", Utils.getSoapVersion(xml));
		
	}
}
