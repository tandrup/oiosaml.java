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
 * Contributor(s):
 * Aage Nielsen - <ani@openminds.dk>
 *
 */
package dk.itst.oiosaml.configuration.jdbc;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.SQLException;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;

/**
 * @author dk7n83
 *
 */
public class JdbcConfiguration {
	public static final String TAG_NAME = "jndi-name";
	public static final String OIOSAML_DATASOURCE = "META-INF/services/oiosaml-ds.xml";
	private static final Logger log = Logger.getLogger(JdbcConfiguration.class);
	private DataSource dataSource;

	/**
	 * 
	 * @param fileName - when null is passed - the oiosaml-ds.xml is used
	 */
	
	
	/**
	 * This class gets a connection to the database - based on a datasource file.
	 *  
	 * @param autoSetup - true if META-INF/services/oiosaml-ds.xml is being used
	 */
	public JdbcConfiguration(boolean autoSetup) {
		if (autoSetup) {
			try {
				InputStream resourceAsStream = this.getClass().getClassLoader().getResourceAsStream(OIOSAML_DATASOURCE);
				DocumentBuilder dom = DocumentBuilderFactory.newInstance().newDocumentBuilder();
				Document dsDom = dom.parse(resourceAsStream);
				log.info("Parsing for " + TAG_NAME + " in  ");
				log.info(getStringFromDoc(dsDom));
				String jndiName = "java:" + dsDom.getElementsByTagName(TAG_NAME).item(0).getTextContent();
				InitialContext ctx = new InitialContext();
				log.info("Looking up JNDI: " + jndiName);
				dataSource = (DataSource) ctx.lookup(jndiName);
			} catch (NamingException e) {
				log.error("Unable to lookup [" + TAG_NAME + "] from " + OIOSAML_DATASOURCE + " [" + e.getMessage() + "]");
				throw new RuntimeException(e);
			} catch (ParserConfigurationException e) {
				log.error("XML parse configuration error when trying " + OIOSAML_DATASOURCE + " [" + e.getMessage() + "]");
				throw new RuntimeException(e);
			} catch (SAXException e) {
				log.error("The xml appears to be incorrect. Looking for content in " + TAG_NAME + " [" + e.getMessage() + "]");
				throw new RuntimeException(e);
			} catch (IOException e) {
				log.error("Unable to find or read from file " + OIOSAML_DATASOURCE + " [" + e.getMessage() + "]");
				throw new RuntimeException(e);
			}
		}
	}

	public void setupDataSourceByFile(String fileName) {
	}

	private String getStringFromDoc(org.w3c.dom.Document doc) {
		DOMImplementationLS domImplementation = (DOMImplementationLS) doc.getImplementation();
		LSSerializer lsSerializer = domImplementation.createLSSerializer();
		return lsSerializer.writeToString(doc);
	}

	/**
	 * Get the connection to the database
	 * 
	 * @return a connection to a database
	 */
	public Connection getConnection() {
		try {
			Connection c = dataSource.getConnection();
			c.setAutoCommit(true);
			return c;
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
	}

	public void closeConnection(Connection connection) {
		if (connection == null)
			return;
		try {
			connection.close();
		} catch (SQLException e) {
			log.error("Unable to close connection", e);
		}
	}

	public DataSource getDataSource() {
		return dataSource;
	}

	public void setDataSource(DataSource dataSource) {
		this.dataSource = dataSource;
	}
}
