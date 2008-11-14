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
package dk.itst.oiosaml.sp.service.session;

import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpSession;

import org.apache.commons.collections.map.LRUMap;
import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.SessionIndex;

import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.LogId;
import dk.itst.oiosaml.sp.service.util.Utils;

/**
 * NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB<br />
 * This class dosn't run in a cluster setup.<br />
 * NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB NB
 * 
 * 
 */
@SuppressWarnings("unchecked")
public class LoggedInHandler {

	public static final String VERSION = "$Id: LoggedInHandler.java 2896 2008-05-20 09:49:22Z jre $";
	
	private static final Logger log = Logger.getLogger(LoggedInHandler.class);

	private static LoggedInHandler instance = new LoggedInHandler();

	private final Map<String, TimeOutWrapper<OIOAssertion>> sessionMap = new ConcurrentHashMap<String, TimeOutWrapper<OIOAssertion>>();
	private final Map<String, TimeOutWrapper<String>> sessionIndexMap = new ConcurrentHashMap<String, TimeOutWrapper<String>>();
	private final Map<String, TimeOutWrapper<String>> requestIds = new ConcurrentHashMap<String, TimeOutWrapper<String>>();
	private Map<String, OIOAssertion> usedAssertionIds = new LRUMap(10000);
	
	private long requestIdsCleanupDelay = ((long)1000*60*5); //5 minutes.

	private Timer cleanupTimer = null;

	private CleanupTimerTask<String, String> requestIdsCleanupTimerTask;
	private CleanupTimerTask<String, String> sessionIndexMapCleanupTask;
	private CleanupTimerTask<String, OIOAssertion> sessionMapCleanupTask;

	
	private LoggedInHandler() {
	}

	/**
	 * @return A handle to the singleton {@link LoggedInHandler}
	 */
	public static synchronized LoggedInHandler getInstance() {
		return instance;
	}

	/**
	 * Associate an {@link Assertion} with a given session
	 * 
	 * @param session
	 *            Reference to the session
	 * @param assertion
	 *            The associated {@link Assertion}
	 */
	public synchronized void setAssertion(HttpSession session, OIOAssertion assertion) throws IllegalArgumentException{
		Issuer issuer = assertion.getAssertion().getIssuer();
		String key = (issuer != null ? issuer.getValue() : "unknown") + ":" + assertion.getAssertion().getID();
		if(usedAssertionIds.containsKey(key)) {
			throw new IllegalArgumentException("Assertion ID begin replayed: " + key);
		}
		usedAssertionIds.put(key, assertion);
		setAssertion(session.getId(), assertion);
	}

	/**
	 * Associate an {@link Assertion} with a given session
	 * 
	 * @param session
	 *            Reference to the session
	 * @param assertion
	 *            The associated {@link Assertion}
	 */
	private synchronized void setAssertion(String sessionId, OIOAssertion assertion) {
		if (null == assertion)
			return;

		sessionMap.put(sessionId, new TimeOutWrapper<OIOAssertion>(assertion));

		String sessionIndex = assertion.getSessionIndex();
		if (sessionIndex != null) {
			// Remove the old sessionIndex
			sessionIndexMap.remove(sessionIndex);

			// Store the new sessionIndex
			sessionIndexMap.put(sessionIndex, new TimeOutWrapper<String>(sessionId));
		}
	}

	/**
	 * @return true if the session is logged in and has a non expired assertion,
	 *         false otherwise. If the user is logged in the GUID of the user is
	 *         set on the session attribute SESSION_USER_GUID. Otherwise it is
	 *         removed.
	 */
	public boolean isLoggedIn(HttpSession session) {
		OIOAssertion ass = getAssertion(session.getId());
		return ass != null && !ass.hasSessionExpired();
	}

	/**
	 * Mark a given session as it has been logged out by removing it the
	 * assertion
	 * 
	 * @param session
	 */
	public void logOut(HttpSession session) {
		// We cannot remove the SESSION_ID_LIST since we use it in LogoutHttpResponseServlet
		// session.removeAttribute(Constants.SESSION_ID_LIST);
		removeAssertion(session.getId());
		session.removeAttribute(Constants.SESSION_USER_ASSERTION);
	}

	private void removeAssertion(String sessionId) {
		TimeOutWrapper<OIOAssertion> tow = sessionMap.remove(sessionId);
		if(tow != null) {
			OIOAssertion ass = tow.getObject();

			if(ass != null) {
				String sessionIndex = ass.getSessionIndex();
				if(sessionIndex != null) {
					sessionIndexMap.remove(sessionIndex);
				}
			}
		}
	}

	/**
	 * Mark a given session as it has been logged out by removing it the
	 * assertion
	 * 
	 * @param sessionId
	 */
	public void logOut(String sessionId) {
		removeAssertion(sessionId);
	}

	/**
	 * Generate a new id for a SAML request and add it to the SESSION_ID_LIST on
	 * the current session
	 * 
	 * @param session
	 *            Reference to the session
	 * @return The generated id
	 */
	public String getID(HttpSession session) {
		return getID(session, null);
	}

	/**
	 * Generate a new id for a SAML request and add it to the SESSION_ID_LIST on
	 * the current session with an associated timer object ({@link LogUtil})
	 * 
	 * @param session
	 *            Reference to the session
	 * @param lu
	 *            The associated timer object
	 * @return The generated id
	 */
	public String getID(HttpSession session, LogUtil lu) {
		Map<String, LogId> idList = getIdMap(session);

		String id =  Utils.generateUUID();
		LogId logId = new LogId(id, lu);
		idList.put(id, logId);
		
		return id;
	}
	
	
	private Map<String, LogId> getIdMap(HttpSession session) {
		Map idList = (Map) session.getAttribute(Constants.SESSION_ID_LIST);
		if (idList == null) {
			idList = new HashMap();
			session.setAttribute(Constants.SESSION_ID_LIST, idList);
		}
		return idList;
	}

	/**
	 * Remove an existing id from a SAML request from the SESSION_ID_LIST on the
	 * current session
	 * 
	 * @param session
	 *            Reference to the session
	 * @param id
	 *            The id
	 * @return The associated timer object in case it exist, otherwise null
	 */
	public LogUtil removeID(HttpSession session, String id) {
		Map<String, LogId> idList = getIdMap(session);

		if (idList == null || !idList.containsKey(id))
			return null;

		LogId logId = idList.remove(id);
		return logId.getLu();
	}

	/**
	 * @return The {@link Assertion} associated with the session
	 */
	public synchronized OIOAssertion getAssertion(String sessionId) {
		if(sessionId == null) {
			return null;
		}
		if (!sessionMap.containsKey(sessionId))
			return null;

		TimeOutWrapper<OIOAssertion> tow = sessionMap.get(sessionId);
		tow.setAccesstime();
		return tow.getObject();
	}

	/**
	 * @return The {@link SessionIndex} as a string from the assertion
	 *         associated with the session
	 */
	public synchronized String getSessionIndexFromAssertion(String sessionId) {
		OIOAssertion ass = getAssertion(sessionId);

		if (null == ass)
			return null;
		else
			return ass.getSessionIndex();
	}

	/**
	 * @param sessionIndex
	 *            The sessionIndex from the assertion
	 * @return The sessionId associated with the sessionIndex in case there is
	 *         one, otherwise null
	 */
	public String getRelatedSessionId(String sessionIndex) {
		return sessionIndexMap.get(sessionIndex).getObject();
	}

	/**
	 * @param sessionID
	 *            Reference to the session
	 * @return The {@link NameID} as a string from the assertion associated with
	 *         the session
	 */
	public synchronized String getNameIdFromAssertion(String sessionID) {
		OIOAssertion ass = getAssertion(sessionID);
		if (null == ass)
			return null;
		else
			return ass.getSubjectNameIDValue();
	}

	public synchronized int getAssuranceLevel(String sessionId) {
		OIOAssertion ass = getAssertion(sessionId);

		if (null == ass)
			return 0;
		else
			return ass.getAssuranceLevel();
	}

	/**
	 * Clone is not supported!
	 */
	public Object clone() throws CloneNotSupportedException {
		throw new CloneNotSupportedException();
	}

	/**
	 * Get the entity ID for the IdP which issued the current assertion.
	 * @param sessionId
	 * @return The entity ID or <code>null</code> if there is no current assertion.
	 */
	public String getAuthenticatingEntityID(String sessionId) {
		OIOAssertion ass = getAssertion(sessionId);
		if (ass != null) {
			return ass.getAssertion().getIssuer().getValue();
		} else {
			return null;
		}
	}
	
	public void registerRequest(String id, String receiverEntityID) {
		if (log.isDebugEnabled()) log.debug("Registered id " + id + " for " + receiverEntityID + "(size: " + requestIds.size() + ")");

		
		requestIds.put(id, new TimeOutWrapper<String>(receiverEntityID));
	}
	
	/**
	 * Remove a request id from the list of registered request ids and return the registered IdP entity id.
	 * @param id
	 * @throws IllegalArgumentException If the request id is unknown.
	 */
	public String removeEntityIdForRequest(String id) {
		if (log.isDebugEnabled()) log.debug("Removing id " + id);
		 
		TimeOutWrapper<String> tow = requestIds.remove(id);
		if(tow == null) {
			throw new IllegalArgumentException("Request id " + id + " is unknown");
		}
		if (log.isDebugEnabled()) log.debug("Entity for request " + id + ": " + tow.getObject());
		return tow.getObject();
	}

	public synchronized void scheduleCleanupTasks(int maxInactiveIntervalSeconds) {

		long sessionCleanupDelay = (long)maxInactiveIntervalSeconds * 1000;

		cleanupTimer = new Timer();
		if(requestIdsCleanupTimerTask == null) {
			requestIdsCleanupTimerTask = new CleanupTimerTask<String, String>(requestIds, requestIdsCleanupDelay);
			cleanupTimer.scheduleAtFixedRate(requestIdsCleanupTimerTask, requestIdsCleanupDelay, requestIdsCleanupDelay);
		}
		if(sessionIndexMapCleanupTask == null) {
			sessionIndexMapCleanupTask = new CleanupTimerTask<String, String>(sessionIndexMap, sessionCleanupDelay);
			cleanupTimer.scheduleAtFixedRate(sessionIndexMapCleanupTask, sessionCleanupDelay, sessionCleanupDelay);
		}
		if(sessionMapCleanupTask == null) {
			sessionMapCleanupTask = new CleanupTimerTask<String, OIOAssertion>(sessionMap, sessionCleanupDelay);
			cleanupTimer.scheduleAtFixedRate(sessionMapCleanupTask, sessionCleanupDelay, sessionCleanupDelay);
		}
	}
	
	public synchronized void stopCleanup() {
		if (cleanupTimer != null) {
			cleanupTimer.cancel();
			requestIdsCleanupTimerTask = null;
			sessionIndexMapCleanupTask = null;
			sessionMapCleanupTask = null;
			cleanupTimer = null;
		}
	}

	/**
	 * Set the delay for the request ids map.
	 * If the task is already running, it will not be restarted.
	 */
	public void setRequestIdsCleanupDelay(long delay) {
		requestIdsCleanupDelay = delay * 1000L;
	}

	public void resetReplayProtection(int maxNum) {
		usedAssertionIds = new LRUMap(maxNum);
	}
}

