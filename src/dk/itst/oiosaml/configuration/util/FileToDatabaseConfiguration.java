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
package dk.itst.oiosaml.configuration.util;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Iterator;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;

public class FileToDatabaseConfiguration {
	static String NL = "\n";

	public static void main(String[] args) {
		if (args.length < 2) {
			System.out.println("File configuration to database configuration needs 4 parameters:");
			System.out.println("1) Filename");
			System.out.println("2) Database url");
			System.out.println("3) Database user");
			System.out.println("4) Database password");
			System.out.println("5) Reverse - save to file (Optional)" + NL);
			System.out.println("Remember to add sqldriver to classpath. The table 'properties' has to be created - see ddl." + NL);
			System.out.println("Exam: ");
			System.out.println("FileToDabaseConfiguration myconf.properties jdbc:oracle:thin:@dev.openminds.dk:1615:OIOSAML oiouser oiopwd");
			return;
		}
		String fileName = args[0];
		String databaseUrl = args[1];
		String databaseUser = args[2];
		String databasePwd = args[3];
		String doDbToFile =null;
		if (args.length==5)
			doDbToFile= args[4];
		
		System.out.println("Reading from configurationfile: " + fileName);
		System.out.println("Reading from database url: " + databaseUrl);
		Connection con = null;
		try {
			con = DriverManager.getConnection(databaseUrl, databaseUser, databasePwd);
			if (isTableOk(con)) {
				if (doDbToFile != null) {
					saveToFile(fileName, con);
				} else {
					saveToDb(fileName, con);
				}
			}
		} catch (ConfigurationException e) {
			System.err.println("Unable to read or write configurationsfile! Error: " + e.getMessage());
		} catch (SQLException e) {
			System.err.println("Unable to select or insert from database! Error: " + e.getMessage());
		} finally {
			try {
				con.close();
			} catch (SQLException e) {
				System.err.println("Unable to close database");
			}
		}
	}

	private static boolean isTableOk(Connection con) throws SQLException {
		Statement countStatement = con.createStatement();
		ResultSet countQuery = countStatement.executeQuery("select count(*) from properties");
		int no = -1;
		while (countQuery.next()) {
			no=countQuery.getInt("count(*)");
			System.out.println("Found " + no + " propteries in database");
		}
		return (no > -1);
	}

	private static void saveToFile(String fileName, Connection con) throws SQLException, ConfigurationException {
		Statement selectStatement = con.createStatement();
		PropertiesConfiguration propertiesConfiguration = new PropertiesConfiguration(new File(fileName));
		String sql = "select conf_key, conf_value from properties";
		ResultSet props = selectStatement.executeQuery(sql);
		while (props.next()) {
			String key = props.getString("conf_key");
			String value = props.getString("conf_value");
			propertiesConfiguration.addProperty(key, value);
		}
		propertiesConfiguration.save();
	}

	private static void saveToDb(String fileName, Connection con) throws SQLException, ConfigurationException {
		Statement insertStatement = con.createStatement();
		PropertiesConfiguration propertiesConfiguration = new PropertiesConfiguration(new File(fileName));
		for (@SuppressWarnings("unchecked")	Iterator<String> iterator = propertiesConfiguration.getKeys(); iterator.hasNext();) {
			String key = iterator.next();
			String value = propertiesConfiguration.getString(key);
			String ins = "insert into properties  (conf_key, conf_value) VALUES ('" + key + "','" + value + "')";
			insertStatement.executeUpdate(ins);
		}
	}
}
