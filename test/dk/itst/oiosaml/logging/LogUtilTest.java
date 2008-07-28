package dk.itst.oiosaml.logging;

import static org.junit.Assert.*;

import java.util.HashMap;

import org.apache.log4j.Logger;
import org.apache.log4j.Priority;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import dk.itst.oiosaml.logging.LogUtil;

public class LogUtilTest {

	private final class CountLogger extends Logger {
		int invokeCount = 0;

		private CountLogger(String name) {
			super(name);
		}

		public int getInvokeCount() {
			return invokeCount;
		}

		public void resetInvokeCount() {
			invokeCount = 0;
		}

		public void debug(Object message) {
			invokeCount++;
		}

		public void debug(Object message, Throwable t) {
			invokeCount++;
		}

		public void info(Object message) {
			invokeCount++;
		}

		public void info(Object message, Throwable t) {
			invokeCount++;
		}

		public void error(Object message) {
			invokeCount++;
		}

		public void error(Object message, Throwable t) {
			invokeCount++;
		}

		public void fatal(Object message) {
			invokeCount++;
		}

		public void fatal(Object message, Throwable t) {
			invokeCount++;
		}

		public void log(Priority priority, Object message) {
			invokeCount++;
		}

		public void log(Priority priority, Object message, Throwable t) {
			invokeCount++;
		}

		public void log(String callerFQCN, Priority level, Object message,
				Throwable t) {
			invokeCount++;
		}

		public void trace(Object message) {
			invokeCount++;
		}

		public void trace(Object message, Throwable t) {
			invokeCount++;
		}

		public void warn(Object message) {
			invokeCount++;
		}

		public void warn(Object message, Throwable t) {
			invokeCount++;
		}
	}

	CountLogger logger = new CountLogger("testLogger");
	
	LogUtil lu;
	
	HashMap<String, String> map = new HashMap<String, String>();
	
	@Before
	public void setUp() throws Exception {
		LogUtil.setLogger(logger);
		logger.resetInvokeCount();
		lu = new LogUtil(this.getClass(), "$Id");
		map.put("Key", "Value");
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testAuditMap() {
		lu.audit(map);
		assertTrue(logger.getInvokeCount() > 0);
	}

	@Test
	public void testAuditObjectArray() {
		lu.audit(new String[] {"Test"});
	}

	@Test
	public void testAuditString() {
		lu.audit("Test");
		assertTrue(logger.getInvokeCount() > 0);		
	}

	@Test
	public void testAuditStringString() {
		lu.audit("key", "value");
		assertTrue(logger.getInvokeCount() > 0);
	}

	@Test
	public void testSystemString() {
		lu.system("test");
		assertTrue(logger.getInvokeCount() > 0);		
	}

	@Test
	public void testSystemStringString() {
		lu.system("key", "value");
		assertTrue(logger.getInvokeCount() > 0);		
	}

	@Test
	public void testSystemMap() {
		lu.system(map);
		assertTrue(logger.getInvokeCount() > 0);				
	}

	@Test
	public void testErrorThrowableString() {
		lu.error(new Exception(), "test");
		assertTrue(logger.getInvokeCount() > 0);				
	}

	@Test
	public void testErrorThrowable() {
		lu.error(new Exception());
		assertTrue(logger.getInvokeCount() > 0);				
	}

	@Test
	public void testErrorString() {
		lu.error("String");
		assertTrue(logger.getInvokeCount() > 0);				
	}

	@Test
	public void testWarnThrowableString() {
		lu.warn(new Exception(), "hulahop");
		assertTrue(logger.getInvokeCount() > 0);				
	}

	@Test
	public void testWarnThrowable() {
		lu.warn(new Exception());
		assertTrue(logger.getInvokeCount() > 0);				
	}

	@Test
	public void testWarnString() {
		lu.warn("test");		
		assertTrue(logger.getInvokeCount() > 0);				
	}

}
