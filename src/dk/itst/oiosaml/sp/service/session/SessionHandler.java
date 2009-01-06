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
 * created by Trifork A/S are Copyright (C) 2009 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.sp.service.session;

import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.Assertion;

import dk.itst.oiosaml.sp.model.OIOAssertion;

public interface SessionHandler {

	/**
	 * Associate an assertion with a given session
	 */
	public void setAssertion(String sessionId, OIOAssertion assertion) throws IllegalArgumentException;

	
	/**
	 * @return true if the session is logged in and has a non expired assertion,
	 *         false otherwise. 
	 */
	public boolean isLoggedIn(String sessionId);
	
	/**
	 * Mark a given session as it has been logged out by removing it the
	 * assertion
	 */
	public void logOut(HttpSession session);
	
	/**
	 * Mark a given session as it has been logged out by removing it the associated
	 * assertion
	 * 
	 * @param sessionId
	 */
	public void logOut(String sessionId);
	
	/**
	 * Generate a new id for a SAML request and add it to the SESSION_ID_LIST on
	 * the current session
	 * 
	 * @param session
	 *            Reference to the session
	 * @return The generated id
	 */
	public String getID(HttpSession session);
	
	
	/**
	 * Remove an existing id from a SAML request from the SESSION_ID_LIST on the
	 * current session
	 * 
	 * @param session
	 *            Reference to the session
	 * @param id
	 *            The id
	 */
	public void removeID(HttpSession session, String id);
	
	/**
	 * @return The {@link Assertion} associated with the session
	 */
	public OIOAssertion getAssertion(String sessionId);
	
	/**
	 * @param sessionIndex
	 *            The sessionIndex from the assertion
	 * @return The sessionId associated with the sessionIndex in case there is
	 *         one, otherwise null
	 */
	public String getRelatedSessionId(String sessionIndex);
	
	public void registerRequest(String id, String receiverEntityID);
	
	
	/**
	 * Remove a request id from the list of registered request ids and return the registered IdP entity id.
	 * @param id
	 * @throws IllegalArgumentException If the request id is unknown.
	 */
	public String removeEntityIdForRequest(String id);

	/**
	 * Clean stored ids and sessions.
	 * 
	 * @param requestIdsCleanupDelay Milliseconds to store assertion ids for replay prevention.
	 * @param sessionCleanupDelay Milliseconds to store session data before purging (in case logout has not been called).
	 */
	public void cleanup(long requestIdsCleanupDelay, long sessionCleanupDelay);
	
	/**
	 * Set the max number of assertion ids to track for replay protection, and reset the cache.
	 * @param maxNum
	 */
	public void resetReplayProtection(int maxNum);

}
