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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpSession;

import org.apache.commons.collections.map.LRUMap;
import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Issuer;

import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;

/**
 * Singleton implementation of a SessionHandler. Do not use this in a clustered environment, as it depends on static maps flor state sharing.
 * 
 * @author Joakim Recht
 *
 */
public class SingleVMSessionHandler implements SessionHandler {
	private static final Logger log = Logger.getLogger(SingleVMSessionHandler.class);
	
	private static final SingletonHandler instance = new SingletonHandler();
	
	public OIOAssertion getAssertion(String sessionId) {
		return instance.getAssertion(sessionId);
	}

	public String getRelatedSessionId(String sessionIndex) {
		return instance.getRelatedSessionId(sessionIndex);
	}

	public boolean isLoggedIn(String sessionId) {
		return instance.isLoggedIn(sessionId);
	}

	public void logOut(HttpSession session) {
		instance.logOut(session);
	}

	public void logOut(String sessionId) {
		instance.logOut(sessionId);
	}

	public void registerRequest(String id, String receiverEntityID) {
		instance.registerRequest(id, receiverEntityID);
	}

	public String removeEntityIdForRequest(String id) {
		return instance.removeEntityIdForRequest(id);
	}

	public void setAssertion(String sessionId, OIOAssertion assertion)
			throws IllegalArgumentException {
		instance.setAssertion(sessionId, assertion);
	}

	public void cleanup(long requestIdsCleanupDelay, long sessionCleanupDelay) {
		instance.cleanup(requestIdsCleanupDelay, sessionCleanupDelay);
	}
	
	public void resetReplayProtection(int maxNum) {
		instance.resetReplayProtection(maxNum);
	}

	public String saveRequest(Request request) {
		return instance.saveRequest(request);
	}
	
	public Request getRequest(String state) throws IllegalArgumentException {
		return instance.getRequest(state);
	}

	@SuppressWarnings("unchecked")
	private static class SingletonHandler {
		private final Map<String, TimeOutWrapper<OIOAssertion>> sessionMap = new ConcurrentHashMap<String, TimeOutWrapper<OIOAssertion>>();
		private final Map<String, TimeOutWrapper<String>> sessionIndexMap = new ConcurrentHashMap<String, TimeOutWrapper<String>>();
		private final Map<String, TimeOutWrapper<String>> requestIds = new ConcurrentHashMap<String, TimeOutWrapper<String>>();
		private final Map<String, TimeOutWrapper<Request>> requests = new ConcurrentHashMap<String, TimeOutWrapper<Request>>();
		private Map<String, OIOAssertion> usedAssertionIds = new LRUMap(10000);
	
		public synchronized void setAssertion(String sessionId, OIOAssertion assertion) throws IllegalArgumentException{
			Issuer issuer = assertion.getAssertion().getIssuer();
			String key = (issuer != null ? issuer.getValue() : "unknown") + ":" + assertion.getAssertion().getID();
			if(usedAssertionIds.containsKey(key)) {
				throw new IllegalArgumentException("Assertion ID begin replayed: " + key);
			}
			usedAssertionIds.put(key, assertion);
			sessionMap.put(sessionId, new TimeOutWrapper<OIOAssertion>(assertion));

			String sessionIndex = assertion.getSessionIndex();
			if (sessionIndex != null) {
				// Remove the old sessionIndex
				sessionIndexMap.remove(sessionIndex);

				// Store the new sessionIndex
				sessionIndexMap.put(sessionIndex, new TimeOutWrapper<String>(sessionId));
			}
		}

		public boolean isLoggedIn(String sessionId) {
			OIOAssertion ass = getAssertion(sessionId);
			return ass != null && !ass.hasSessionExpired();
		}
		
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

		public void logOut(String sessionId) {
			removeAssertion(sessionId);
		}
		
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

		public String getRelatedSessionId(String sessionIndex) {
			return sessionIndexMap.get(sessionIndex).getObject();
		}

		public Object clone() throws CloneNotSupportedException {
			throw new CloneNotSupportedException();
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
		
		
		public void cleanup(long requestIdsCleanupDelay, long sessionCleanupDelay) {
			cleanup(sessionMap, sessionCleanupDelay);
			cleanup(requestIds, requestIdsCleanupDelay);
			cleanup(sessionIndexMap, sessionCleanupDelay);
			cleanup(requests, sessionCleanupDelay);
		}

		private <E, T> void cleanup(Map<E, TimeOutWrapper<T>> map, long cleanupDelay) {
			if (log.isDebugEnabled()) log.debug(hashCode() +  " Running cleanup timer on " + map);
			for (E key : map.keySet()) {
				TimeOutWrapper<T> tow = map.get(key);
				if (tow.isExpired(cleanupDelay)) {
					log.debug("Expiring " + tow);
					map.remove(key);
				}
			}
		}

		public void resetReplayProtection(int maxNum) {
			usedAssertionIds = new LRUMap(maxNum);
		}
		
		public String saveRequest(Request request) {
			String state = Utils.generateUUID();
			requests.put(state, new TimeOutWrapper<Request>(request));
			return state;
		}
		
		public Request getRequest(String state) throws IllegalArgumentException {
			TimeOutWrapper<Request> request = requests.remove(state);
			if (request == null) {
				throw new IllegalArgumentException("No request for state " + state);
			}
			return request.getObject();
		}

	}

}
