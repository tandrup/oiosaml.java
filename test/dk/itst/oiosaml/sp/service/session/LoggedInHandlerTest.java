package dk.itst.oiosaml.sp.service.session;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.jmock.Expectations;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.util.Constants;

public class LoggedInHandlerTest extends AbstractServiceTests{
	
	
	@Before @After
	public void stopCleanup() {
		handler.stopCleanup();
	}
	
	
	@Test
	public void testSetAssertion() {
		handler.setAssertion(session, new OIOAssertion(assertion));
		
		OIOAssertion assertion = handler.getAssertion(session.getId());
		assertEquals(this.assertion, assertion.getAssertion());
		
		String idx = new OIOAssertion(this.assertion).getSessionIndex();
		assertEquals(idx, handler.getSessionIndexFromAssertion(session.getId()));
		
		assertEquals(session.getId(), handler.getRelatedSessionId(idx));
		
	}

	@Test(expected=IllegalArgumentException.class)
	public void failOnReplayAssertionId() {
		context.checking(new Expectations() {{
			allowing(session).setAttribute(with(equal(Constants.SESSION_USER_ASSERTION)), with(any(UserAssertion.class)));
		}});
		handler.setAssertion(session, new OIOAssertion(assertion));
		
		// this is replay - should throw IllegalArgumentException
		handler.setAssertion(session, new OIOAssertion(assertion));
		
	}
	
	@Test
	public void testIsLoggedIn() {
		assertFalse(handler.isLoggedIn(session));
		setHandler();
		assertTrue(handler.isLoggedIn(session));
	}

	@Test
	public void testLogOut() {
		// session does not exist, no errors
		context.checking(new Expectations() {{ 
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		handler.logOut(session);
		context.assertIsSatisfied();
		
		setHandler();
		assertNotNull(handler.getAssertion(session.getId()));
		context.checking(new Expectations() {{ 
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		handler.logOut(session);
		assertNull(handler.getAssertion(session.getId()));
	}

	@Test
	public void testGetIDHttpSession() {
		String id = handler.getID(session, new LogUtil(getClass(), "1.0"));
		assertNotNull(id);
		assertEquals(1, ids.size());
		
		LogUtil lu = handler.removeID(session, id);
		assertNotNull(lu);
		assertEquals(0, ids.size());
		context.assertIsSatisfied();
		
		assertNull(handler.removeID(session, id));
	}

	@Test
	public void testGetSessionIndexFromAssertion() {
		assertNull(handler.getSessionIndexFromAssertion("testing"));
		assertNull(handler.getSessionIndexFromAssertion(null));
	}

	@Test
	public void testGetNameIdFromAssertion() {
		setHandler();
		assertNull(handler.getNameIdFromAssertion("testing"));
		assertNull(handler.getNameIdFromAssertion(null));
		assertEquals("joetest", handler.getNameIdFromAssertion(session.getId()));

	}
	
	@Test 
	public void cleanUpIsScheduled() throws Exception {
		handler.scheduleCleanupTasks(1);
		setHandler();
		assertTrue(handler.isLoggedIn(session));
		assertNotNull(handler.getSessionIndexFromAssertion(session.getId()));
		Thread.sleep(2100);
		assertFalse(handler.isLoggedIn(session));
		assertNull(handler.getSessionIndexFromAssertion(session.getId()));
	}
	
	@Test
	public void testStopSchedule() throws Exception {
		handler.scheduleCleanupTasks(1);
		handler.stopCleanup();
		setHandler();
		assertTrue(handler.isLoggedIn(session));
		assertNotNull(handler.getSessionIndexFromAssertion(session.getId()));
		Thread.sleep(2100);
		assertTrue(handler.isLoggedIn(session));
		assertNotNull(handler.getSessionIndexFromAssertion(session.getId()));
	}

	@Test(expected=IllegalArgumentException.class)
	public void cleanupRequestIds() throws Exception {
		handler.registerRequest("1", "id");
		handler.setRequestIdsCleanupDelay(1);
		handler.scheduleCleanupTasks(1);
		
		Thread.sleep(2000);
		handler.removeEntityIdForRequest("1");
	}
	

}
