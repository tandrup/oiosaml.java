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

import java.sql.Connection;
import java.sql.SQLException;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.apache.log4j.Logger;

/**
 * @author dk7n83
 *
 */
public class JdbcConfiguration {
	private static final Logger log = Logger.getLogger(JdbcConfiguration.class);
	private DataSource dataSource;

	/**
	 * 
	 * @param fileName - when null is passed - the oiosaml-ds.xml is used
	 */
	
	
	public JdbcConfiguration(String jndiName) {
		try {
			InitialContext ctx = new InitialContext();
			log.info("Looking up JNDI: " + jndiName);
			dataSource = (DataSource) ctx.lookup(jndiName);
		} catch (NamingException e) {
			log.error("Unable to lookup " + jndiName, e);
			throw new RuntimeException(e);
		}
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
