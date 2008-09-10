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
package dk.itst.oiosaml.logging;

import java.io.PrintWriter;
import java.io.Serializable;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;

import dk.itst.oiosaml.error.WrappedException;

/**
 * Utility class to facilitate a common log format throughout the projects. The
 * class does not do any logging it self, but provides a number of methods which
 * return strings having the correct logging format A typical example of the
 * usage in a service would be <code>
 *   public void myService(...) {
 *    	LogUtil lu = new LogUtil("MyClass.class",VERSION,"MyService", "user123");
 *      try {
 *	      ...
 *        lu.audit("Some extra info"); // Do audit logging
 *        ...
 *      } catch (Exception e) {
 *        lu.error(e);				   // Log error message
 *      } finally {
 *        lu.endService(); // Log the execution time of the service
 *      }
 *   }
 * </code>
 * 
 * Below are shown examples of the log format strings produced by the utility
 * methods {@link #audit(String)}: [Z9203006] [MyService]
 * [dk.eogs.brs.server.service.MyClass:22] [] [AUDIT] [MyService] [User]
 * [testAudit] [NORMAL] [] [] [arg1=[val1] arg2=[val2]]
 * 
 * {@link #beforeService(String, String, String, String)}:
 * {@link #afterService(String)}: [Z9203006] [MyService]
 * [dk.eogs.brs.server.service.MyClass:$Id: LogUtil.java 4226 2007-11-27
 * 17:19:22Z pagerbak $] [] [EXECTIME] [CONSUMER] [] [] [myService] [47]
 * [debugInfo]
 * 
 * {@link #endService()}: [Z9203006] [MyService]
 * [dk.eogs.brs.server.service.MyClass:$Id: LogUtil.java 4226 2007-11-27
 * 17:19:22Z pagerbak $] [] [EXECTIME] [PROVIDER] [Z9203006]
 * [dk.eogs.brs.server.service.MyClass:$Id: LogUtil.java 4226 2007-11-27
 * 17:19:22Z pagerbak $] [testExecTime] [47] []
 * 
 * {@link #system(String)}: [Z9203006] [MyService]
 * [dk.eogs.brs.server.service.MyClass:$Id: LogUtil.java 4226 2007-11-27
 * 17:19:22Z pagerbak $] [] [SYSTEM] [Just some info]
 * 
 * {@link #error(Throwable)}: [Z9203006] [MyService]
 * [dk.eogs.brs.server.service.MyClass:$Id: LogUtil.java 4226 2007-11-27
 * 17:19:22Z pagerbak $] [] [ERROR] [java.lang.Exception] [Something went wrong]
 * [java.lang.Exception: Something went wrong \nat
 * dk.eogs.brs.server.service.MyClass.testError(LogUtilTest.java:53) ...] [extra
 * errorInfo]
 * 
 * @author Louis Steinthal, Capgemini
 * 
 */
public class LogUtil implements Serializable {

	public static final String VERSION = "$Id: LogUtil.java 2950 2008-05-28 08:22:34Z jre $";
	private static final long serialVersionUID = -2872902727388216668L;
	private static Logger log = Logger.getLogger("AUDIT_LOGGER");
	private static final String HEADER = "[";
	private static final String DELIMITER = "] [";
	private static final String LOGINFO = "info";
	private static final String SECURITY_LEVEL_NORMAL = "NORMAL";
	public static final String CATEGORY_SYSTEM = "SYSTEM";
	public static final String CATEGORY_AUDIT = "AUDIT";
	public static final String CATEGORY_EXECTIME = "EXECTIME";
	public static final String CATEGORY_FATAL = "FATAL";
	public static final String CATEGORY_ERROR = "ERROR";
	public static final String CATEGORY_WARNING = "WARNING";
	public static final String EXECTIME_PROVIDER = "PROVIDER";
	public static final String EXECTIME_CONSUMER = "CONSUMER";
	public static final String EXECTIME_CUSTOM = "CUSTOM";
	private static final String UNKNOWN = "UNKNOWN";
	private static String hostName;
	private String version = null;
	private String serviceName = "";
	private String className;
	private String userName = "";
	private String requestId = "";
	private String service;
	private String header;

	private Map<String, TimeUtil> execMap = new HashMap<String, TimeUtil>();


	static {
		// Look up the host name of the server once!
		try {
			hostName = InetAddress.getLocalHost().getHostName();
		} catch (UnknownHostException e) {
			hostName = UNKNOWN;
		}
	}

	/**
	 * Initialize log4j with the specified configuration file.
	 * 
	 * @param xmlFilename
	 *            The log4j configuration file. It must be in xml format, since
	 *            the DomConfigurator is used unconditionally. An absolute path is expected.
	 */
	public static void configureLog4j(String xmlFilename) {
		try {
			DOMConfigurator.configure(xmlFilename);
			log.info("Configuring logging from " + xmlFilename);
		} catch (Exception e) {
			log.error("Unable to configure logging from " + xmlFilename, e);
		}
	}

	public static void setLogger(Logger arg) {
		log = arg;
	}
	
	/**
	 * @see #LogUtil(Class, String, String, String)
	 */
	public LogUtil(Class<?> clazz, String version) {
		this(clazz, version, null, null);
	}

	/**
	 * @see #LogUtil(Class, String, String, String)
	 */
	public LogUtil(Class<?> clazz, String version, String serviceName) {
		this(clazz, version, serviceName, null);
	}

	/**
	 * Constructor giving a handle to the utility methods which enables services
	 * in to use a common log format.
	 * 
	 * @param clazz
	 *            The class which instantiated the
	 *            {@link #LogUtil(Class, String, String, String)}
	 * @param version
	 *            The version of the class
	 * @param serviceName
	 *            The name of the current service
	 * @param userName
	 *            The name/id of the current user
	 */
	public LogUtil(Class<?> clazz, String version, String serviceName, String userName) {
		setClassName(clazz.getName());
		setServiceName(serviceName);
		setUserName(userName);
		this.version = version;
		startService();
	}

	/**
	 * Produces an output string of the form: [hostName] [serviceName]
	 * [className:version] [empty requestId]
	 * 
	 * @return The output string
	 */
	private String getHeader() {
		if (header == null) {
			StringBuffer str = new StringBuffer(HEADER);
			str.append(hostName).append(DELIMITER);
			str.append(serviceName).append(DELIMITER);
			str.append(className).append(":").append(version).append(DELIMITER);
			str.append(requestId).append(DELIMITER);
			header = str.toString();
		}
		return header;
	}

	/**
	 * Produces an output string in the format: key1=[val1] key2=[val2] ...
	 * keyn=[valn]
	 * 
	 * @param m
	 *            Map of (key, value)-pairs
	 * @return The output string
	 */
	private StringBuffer format(Map<?, ?> m) {
		StringBuffer str = new StringBuffer("");
		boolean first = true;
		for (Map.Entry<?, ?> e : m.entrySet()) {
			if (!first) {
				str.append(" ");
			}
			str.append(e.getKey()).append("=").append("[");
			str.append(e.getValue()).append("]");
			first = false;
			
		}
		return str;
	}

	/**
	 * Produces an output string in the format: elem1=[elem2] elem3=[elem4] ...
	 * elem(2n-1)=[elem2n]
	 * 
	 * @param o
	 *            An array of elements
	 * @return The output string
	 */
	private StringBuffer format(Object[] o) {
		StringBuffer str = new StringBuffer("");
		boolean first = true;
		for (int i = 0; i + 1 < o.length; i = i + 2) {
			if (!first) {
				str.append(" ");
			}
			str.append(o[i]).append("=").append("[");
			str.append(o[i + 1]).append("]");
			first = false;

		}
		return str;
	}

	/**
	 * Produces an output string of the form: &lt;LOGHEADER&gt; [EXECTIME]
	 * [serviceProviderHost] [serviceProvider] [service] [exec time in millisec]
	 * [debug info]
	 * 
	 * @param execTimeType
	 *            Provider or Consumer
	 * @param service
	 *            The name of the service
	 * @param debugInfo
	 *            Some debug info to be included in the log line
	 * @return The output string
	 */
	private String getExecTimeString(String execTimeType, String service, String debugInfo) {
		Object o = execMap.remove(service);
		TimeUtil timeUtil;
		if (o != null) {
			timeUtil = (TimeUtil) o;
		} else {
			timeUtil = new TimeUtil("", "", "");
		}
		StringBuffer str = new StringBuffer(getHeader()).append(CATEGORY_EXECTIME).append(DELIMITER).append(
				execTimeType).append(DELIMITER);
		str.append(timeUtil.getServiceProviderHost()).append(DELIMITER); // ServiceProviderHost
		str.append(timeUtil.getServiceProvider()).append(DELIMITER); // ServiceProvider
		str.append(service).append(DELIMITER);
		str.append(timeUtil.getExecTime()).append(DELIMITER);
		str.append(debugInfo != null ? debugInfo : timeUtil.getDebugInfo()).append("]");
		return str.toString();
	}

	/**
	 * Starts timer so the duration of a given service can be measured from a
	 * consumer's point of view. When the service has terminated, call the
	 * method {@link #afterService(String)} to stop the timer
	 * {@link #afterService(String)} Apart from the parameter
	 * <code>service</code>, the parameters are used only producing output in
	 * {@link #afterService(String)}
	 * 
	 * @param serviceProviderHost
	 *            The host which exposes the service
	 * @param serviceProvider
	 *            The name of the service provider
	 * @param service
	 *            The name of the service, which is invoked
	 * @param debugInfo
	 *            Adequate debug info which should be included in the log
	 *            message produced by {@link #afterService(String)}
	 */
	public void beforeService(String serviceProviderHost, String serviceProvider, String service, String debugInfo) {
		// Put the current time in the local map
		if ((serviceProviderHost == null || "".equals(serviceProviderHost)) && serviceProvider != null
				&& serviceProvider.toUpperCase().startsWith("HTTP")) {
			int endIndex = serviceProvider.indexOf('/', 8); // after https://
			if (endIndex > 0) {
				serviceProviderHost = serviceProvider.substring(0, endIndex);
			}
		}
		execMap.put(service, new TimeUtil(serviceProviderHost, serviceProvider, debugInfo));
	}

	/**
	 * @see #beforeService(String, String, String, String)
	 */
	public void beforeService(String service, String debugInfo) {
		// Put the current time in the local map
		beforeService("", "", service, debugInfo);
	}

	/**
	 * @see #beforeService(String, String, String, String)
	 */
	public void beforeService(String service) {
		// Put the current time in the local map
		beforeService("", "", service, "");
	}

	/**
	 * Stops the timer related to the parameter service and returns an output
	 * string in the right format to be used for the execution time log. It is
	 * assumed, that {@link #beforeService(String, String, String, String)} has
	 * been called before invoking this method
	 * 
	 * @param service
	 *            The service which just has terminated
	 * @return Output string in the right format including the time in
	 *         milliseconds for the duration of the service
	 */
	public String afterService(String service) {
		String str = getExecTimeString(EXECTIME_CONSUMER, service, null);
		log.info(str);
		return str;
	}

	/**
	 * Starts timer so the duration of a given service can be measured from a
	 * provider's point of view. Just before the service terminates, call the
	 * method {@link #endService()} to stop the timer. The method is implicitly
	 * called by the constructor of the <code>LogUtil</code>-class, so
	 * usually there is no need for an explicit call to this method.
	 * 
	 * @param debugInfo
	 *            A relevant string to be included in the log message when
	 *            {@link #endService()} is called
	 */
	public void startService(String debugInfo) {
		// Put the current time in the local map
		execMap.put(service, new TimeUtil(hostName, className, debugInfo));
	}

	/**
	 * @see #startService(String)
	 */
	public void startService() {
		startService("");
	}

	/**
	 * Stops the timer related to the parameter service and returns an output
	 * string in the right format to be used for the execution time log. It is
	 * assumed, that {@link #startService(String)} has been called before
	 * invoking this method, which is implicitly done in the constructor of the
	 * <code>LogUtil</code>-class.
	 * 
	 * @param debugInfo
	 *            A relevant string to be included in the log message.
	 * @return Output string in the right format including the time in
	 *         milliseconds for the duration of the service
	 */
	public String endService(String debugInfo) {
		String str = getExecTimeString(EXECTIME_PROVIDER, service, debugInfo);
		log.info(str);
		return str;
	}

	/**
	 * @see #endService(String)
	 */
	public String endService() {
		String str = getExecTimeString(EXECTIME_PROVIDER, service, null);
		log.info(str);
		return str;
	}

	/**
	 * Produces an output string of the form: &lt;LOGHEADER&gt; [AUDIT] [userName]
	 * [service] [NORMAL] [] []
	 * 
	 * @return The output string
	 */
	private StringBuffer getAuditHeader() {
		StringBuffer str = new StringBuffer(getHeader()).append(CATEGORY_AUDIT).append(DELIMITER).append(
				getServiceName()).append(DELIMITER);
		str.append(getUserName()).append(DELIMITER);
		str.append(service).append(DELIMITER);
		str.append(SECURITY_LEVEL_NORMAL).append(DELIMITER); // Security
		// Level
		str.append("").append(DELIMITER); // OrgUnit
		str.append("").append(DELIMITER); // Patient
		return str;
	}

	/**
	 * Produces an output string of the form: &lt;AUDITHEADER&gt; [&lt;format of
	 * properties -&gt;]
	 * 
	 * @see java.util.Map
	 * 
	 * @param map
	 *            The properties which should be shown in the audit log
	 * @return The output string
	 */
	public String audit(Map<?, ?> map) {
		StringBuffer str = getAuditHeader();
		str.append(format(map));
		str.append("]");
		String s = str.toString();
		log.info(s);
		return s;
	}

	/**
	 * Produces an output string of the form: &lt;AUDITHEADER&gt; [&lt;format of objects -&gt;]
	 * 
	 * @see java.lang.Object
	 * 
	 * @param objects
	 *            The objects which should be shown in the audit log
	 * @return The output string
	 */
	public String audit(Object[] objects) {
		StringBuffer str = getAuditHeader();
		str.append(format(objects));
		str.append("]");
		String s = str.toString();
		log.info(s);
		return s;
	}

	/**
	 * Produces an output string of the form: &lt;AUDITHEADER&gt; [info=[loginfo]]
	 * 
	 * @param logInfo
	 *            The loginfo which should be shown in the audit log
	 * @return The output string
	 */
	public String audit(String logInfo) {
		return audit(getSimpleProperty(logInfo));
	}

	/**
	 * Produces an output string of the form: &lt;AUDITHEADER&gt; [key=[value]]
	 * 
	 * @param key
	 *            The key which should be shown in the audit log
	 * @param value
	 *            The value which should be shown in the audit log
	 * @return The output string
	 */
	public String audit(String key, String value) {
		return audit(getSimpleProperty(key, value));
	}

	/**
	 * Produces an output string of the form: &lt;LOGHEADER&gt; [SYSTEM]
	 * 
	 * @return The output string
	 */
	private StringBuffer getSystemHeader() {
		StringBuffer str = new StringBuffer(getHeader()).append(CATEGORY_SYSTEM).append(DELIMITER);
		return str;
	}

	/**
	 * Produces an output string of the form: &lt;SYSTEMHEADER&gt; [logInfo]
	 * 
	 * @param logInfo
	 *            The loginfo which should be shown in the log message
	 * @return The output string
	 */
	public String system(String logInfo) {
		StringBuffer str = getSystemHeader();
		str.append(logInfo);
		str.append("]");
		log.info(str);
		return str.toString();
	}

	/**
	 * Produces an output string of the form: &lt;SYSTEMHEADER&gt; [key=[value]]
	 * 
	 * @param key
	 *            The key which should be shown in the log message
	 * @param value
	 *            The value which should be shown in the log message
	 * @return The output string
	 */
	public String system(String key, String value) {
		StringBuffer str = getSystemHeader();
		str.append(format(getSimpleProperty(key, value)));
		str.append("]");
		log.info(str);
		return str.toString();
	}

	/**
	 * Produces an output string of the form: &lt;SYSTEMHEADER&gt; [&lt;format of
	 * objects -&gt;]
	 * 
	 * @see java.util.Map
	 * 
	 * @param map
	 *            The map which should be shown in the log message
	 * @return The output string
	 */
	public String system(Map<?, ?> map) {
		StringBuffer str = getSystemHeader();
		str.append(format(map));
		str.append("]");
		log.info(str);
		return str.toString();
	}

	/**
	 * Produces an output string of the form: &lt;LOGHEADER&gt; [category]
	 * 
	 * @return The output string
	 */
	private StringBuffer getSimpleHeader(String category) {
		StringBuffer str = new StringBuffer(getHeader()).append(category)
				.append(DELIMITER);
		return str;
	}

	/**
	 * Produces an output string of the form: &lt;ERRORHEADER&gt; [class with error]
	 * [message] [stackTrace] [logInfo]
	 * 
	 * @param t
	 * 			  The throwable
	 * @param logInfo
	 *            The loginfo which should be shown in the log message
	 * @return The output string
	 */
	private String errorOrWarning(Throwable t, String logInfo, String category) {
		if (t instanceof WrappedException) {
			t = ((WrappedException) t).getCause();
		}
		StringBuffer str = getSimpleHeader(category);
		if (t != null) {
			str.append(t.getClass().getName());
		}
		str.append(DELIMITER);
		if (t != null) {
			str.append(t.getMessage());
		} else {
			str.append(logInfo);
		}
		str.append(DELIMITER);
		if (t != null) {
			StringWriter sw = new StringWriter();
			t.printStackTrace(new PrintWriter(sw));
			str.append(sw);
		}
		str.append(DELIMITER);
		if (t != null) {
			str.append(logInfo);
		}
		str.append("]");
		String s = str.toString();
		if (CATEGORY_ERROR.equals(category)) {
			log.error(s);
		} else if (CATEGORY_WARNING.equals(category)) {
			log.warn(s);
		} else if (CATEGORY_FATAL.equals(category)) {
			log.fatal(s);
		}
		return s;
	}

	/**
	 * Produces an output string of the form: &lt;ERRORHEADER&gt; [class with error]
	 * [message] [stackTrace] [logInfo]
	 * 
	 * @param t
	 * 			  The throwable
	 * @param logInfo
	 *            The loginfo which should be shown in the log message
	 * @return The output string
	 */
	public String error(Throwable t, String logInfo) {
		return errorOrWarning(t, logInfo, CATEGORY_ERROR);
	}

	/**
	 * @see #error(Throwable, String)
	 */
	public String error(Throwable t) {
		return error(t, "");
	}

	/**
	 * @see #error(Throwable, String)
	 */
	public String error(String message) {
		return error(null, message);
	}

	/**
	 * Produces an output string of the form: &lt;FATALHEADER&gt; [class with fatal error]
	 * [message] [stackTrace] [logInfo]
	 * 
	 * @param t
	 * 			  The throwable
	 * @param logInfo
	 *            The loginfo which should be shown in the log message
	 * @return The output string
	 */
	public String fatal(Throwable t, String logInfo) {
		return errorOrWarning(t, logInfo, CATEGORY_FATAL);
	}

	/**
	 * @see #fatal(Throwable, String)
	 */
	public String fatal(Throwable t) {
		return fatal(t, "");
	}

	/**
	 * @see #fatal(Throwable, String)
	 */
	public String fatal(String message) {
		return fatal(null, message);
	}

	/**
	 * Produces an output string of the form: &lt;WARNINGHEADER&gt; [class with
	 * warning] [message] [stackTrace] [logInfo]
	 * 
	 * @param t
	 * 			  The throwable
	 * @param logInfo
	 *            The loginfo which should be shown in the log message
	 * @return The output string
	 */
	public String warn(Throwable t, String logInfo) {
		return errorOrWarning(t, logInfo, CATEGORY_WARNING);
	}

	/**
	 * @see #warn(Throwable, String)
	 */
	public String warn(Throwable t) {
		return warn(t, "");
	}

	/**
	 * @see #warn(Throwable, String)
	 */
	public String warn(String message) {
		return warn(null, message);
	}

	/**
	 * Convert a string in to a property (info,str)
	 * 
	 * @param str
	 *            The string to be included in the property
	 * @return The Properties
	 */
	private Properties getSimpleProperty(String str) {
		Properties p = new Properties();
		p.put(LOGINFO, str == null ? "null" : str);
		return p;
	}

	/**
	 * Convert (key, value) in to a property (key, value)
	 * 
	 * @param key
	 *            The key to be included in the property
	 * @param value
	 *            The value to be included in the property
	 * @return The Properties
	 */
	public Properties getSimpleProperty(String key, String value) {
		Properties p = new Properties();
		p.put(key, value == null ? "null" : value);
		return p;
	}

	public String getClassName() {
		return className;
	}

	public void setClassName(String className) {
		this.className = className;
		header = null;
	}

	public String getServiceName() {
		return serviceName;
	}

	public void setServiceName(String serviceName) {
		this.serviceName = serviceName;
		header = null;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getRequestId() {
		return requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	/**
	 * Helper class to deal with more than one concurrent time measurement
	 */
	private class TimeUtil {

		private String serviceProviderHost;

		private String serviceProvider;

		private String debugInfo;

		private long startTime;

		public TimeUtil(String serviceProviderHost, String serviceProvider, String debugInfo) {
			this.serviceProviderHost = serviceProviderHost;
			this.serviceProvider = serviceProvider;
			this.debugInfo = debugInfo;
			startTime = System.currentTimeMillis();
		}

		public String getDebugInfo() {
			return debugInfo;
		}

		public long getExecTime() {
			return System.currentTimeMillis() - startTime;
		}

		public String getServiceProvider() {
			return serviceProvider;
		}

		public String getServiceProviderHost() {
			return serviceProviderHost;
		}
	}

}
