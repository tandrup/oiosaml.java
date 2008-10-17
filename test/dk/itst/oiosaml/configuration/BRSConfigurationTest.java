package dk.itst.oiosaml.configuration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.MapConfiguration;
import org.junit.Test;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.service.TestHelper;

public class BRSConfigurationTest {

	@Test(expected=IllegalStateException.class)
	public void failOnMissingSystemProperty() {
		SAMLConfiguration.setSystemConfiguration(null);
		SAMLConfiguration.getSystemConfiguration();
	}
	
	@Test
	public void testGetStringPrefixedWithBRSHome() {
		Map<String, String> props = new HashMap<String, String>() {{
			put(SAMLUtil.OIOSAML_HOME, "home");
			put("key", "value");
		}};
		
		
		Configuration conf = new MapConfiguration(props);
		assertEquals("home/value", SAMLConfiguration.getStringPrefixedWithBRSHome(conf, "key"));
		
	}
	
	@Test
	public void testIsConfigured() throws Exception{
		assertFalse(SAMLConfiguration.isConfigured());
		
		SAMLConfiguration.setHomeProperty(System.getProperty("java.io.tmpdir") + "/void");
		assertFalse(SAMLConfiguration.isConfigured());
		final File dir = new File(File.createTempFile("test", "test").getAbsolutePath() + ".home");
		dir.mkdir();
		SAMLConfiguration.setHomeProperty(dir.getAbsolutePath());
		assertFalse(SAMLConfiguration.isConfigured());
		
		File content = new File(dir, "oiosaml-sp.properties");
		FileOutputStream fos = new FileOutputStream(content);
		fos.write("testing".getBytes());
		fos.close();
		
		SAMLConfiguration.setHomeProperty(dir.getAbsolutePath());
		assertTrue(SAMLConfiguration.isConfigured());
		
		content.delete();
		dir.delete();
	}

	@Test
	public void setSystemConfiguration() {
		Configuration conf = TestHelper.buildConfiguration(new HashMap<String, String>());
		SAMLConfiguration.setSystemConfiguration(conf);
		assertSame(conf, SAMLConfiguration.getSystemConfiguration());
	}

}
