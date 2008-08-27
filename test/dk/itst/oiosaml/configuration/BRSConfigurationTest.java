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
		BRSConfiguration.setSystemConfiguration(null);
		BRSConfiguration.getSystemConfiguration();
	}
	
	@Test
	public void testGetStringPrefixedWithBRSHome() {
		Map<String, String> props = new HashMap<String, String>() {{
			put(SAMLUtil.OIOSAML_HOME, "home");
			put("key", "value");
		}};
		
		
		Configuration conf = new MapConfiguration(props);
		assertEquals("home/value", BRSConfiguration.getStringPrefixedWithBRSHome(conf, "key"));
		
	}
	
	@Test
	public void testIsConfigured() throws Exception{
		assertFalse(BRSConfiguration.isConfigured(null));
		assertFalse(BRSConfiguration.isConfigured("/void"));
		final File dir = new File(File.createTempFile("test", "test").getAbsolutePath() + ".home");
		dir.mkdir();
		assertFalse(BRSConfiguration.isConfigured(dir.getAbsolutePath()));
		
		File content = new File(dir, "content");
		FileOutputStream fos = new FileOutputStream(content);
		fos.write("testing".getBytes());
		fos.close();
		
		assertTrue(BRSConfiguration.isConfigured((dir.getAbsolutePath())));
		
		content.delete();
		dir.delete();
	}

	@Test
	public void setSystemConfiguration() {
		Configuration conf = TestHelper.buildConfiguration(new HashMap<String, String>());
		BRSConfiguration.setSystemConfiguration(conf);
		assertSame(conf, BRSConfiguration.getSystemConfiguration());
	}

}
