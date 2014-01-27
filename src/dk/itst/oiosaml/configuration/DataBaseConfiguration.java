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
 *  2012 Danish National IT and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Aage Nielsen <ani@openminds.dk>
 * 
 */
package dk.itst.oiosaml.configuration;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.DatabaseConfiguration;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.log4j.Logger;
import org.opensaml.xml.XMLObject;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.jdbc.JdbcConfiguration;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.sp.service.util.Constants;

public class DataBaseConfiguration implements SAMLConfiguration {
	private static final Logger log = Logger.getLogger(DatabaseConfiguration.class);
	private JdbcConfiguration jdbcConfiguration = new JdbcConfiguration(true);
	private Configuration systemConfiguration;

	public boolean isConfigured() {
		return (systemConfiguration != null);
	}

	public void setInitConfiguration(Map<String, String> params) {
		
	}

	public Configuration getCommonConfiguration() throws IOException {
		CompositeConfiguration conf = new CompositeConfiguration();
		Enumeration<URL> resources = FileConfiguration.class.getClassLoader().getResources("oiosaml-common.properties");
		while (resources.hasMoreElements()) {
			URL u = resources.nextElement();
			log.debug("Loading common config from " + u);
			try {
				conf.addConfiguration(new PropertiesConfiguration(u));
			} catch (ConfigurationException e) {
				log.error("Cannot load the configuration file", e);
				throw new WrappedException(Layer.DATAACCESS, e);
			}
		}
		return conf;
	}

	public Configuration getSystemConfiguration() throws IllegalStateException {
		if (systemConfiguration != null)
			return systemConfiguration;
		CompositeConfiguration conf = new CompositeConfiguration();
		try {
			org.apache.commons.configuration.DatabaseConfiguration dbConfiguration = new org.apache.commons.configuration.DatabaseConfiguration(jdbcConfiguration.getDataSource(), "properties", "conf_key", "conf_value");
			log.debug("Loading custom config from " + jdbcConfiguration.getDataSource().getConnection().getMetaData().getURL());
			conf.addConfiguration(dbConfiguration);
			conf.addConfiguration(getCommonConfiguration());
			systemConfiguration = conf;
		} catch (IOException e) {
			log.error("Unable to load oiosaml-common.propeties from classpath", e);
			throw new WrappedException(Layer.DATAACCESS, e);
		} catch (SQLException e) {
			log.error("Unable to load properties from database", e);
			throw new WrappedException(Layer.DATAACCESS, e);
		}
		return systemConfiguration;
	}

	public KeyStore getKeystore() throws WrappedException, NoSuchAlgorithmException, CertificateException, IllegalStateException, IOException, KeyStoreException {
		KeyStore keystore = KeyStore.getInstance("JKS");
		Connection con = jdbcConfiguration.getConnection();
		try {
			PreparedStatement ps = con.prepareStatement("SELECT keystore FROM java_keystore");
			ResultSet rs = ps.executeQuery();
			rs.next();
			Clob clob = rs.getClob(1);
			keystore.load(clob.getAsciiStream(),getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_PASSWORD).toCharArray());
		} catch (SQLException e) {
			throw new RuntimeException(e);
		} finally {
			jdbcConfiguration.closeConnection(con);
		}
		return keystore;
	}

	public InputStream getLoggerConfiguration() throws WrappedException {
		
		Connection con = jdbcConfiguration.getConnection();
		InputStream is=null;
		try {
			PreparedStatement ps = con.prepareStatement("SELECT log4j FROM logger");
			ResultSet rs = ps.executeQuery();
			rs.next();
			Clob clob = rs.getClob(1);
			is=clob.getAsciiStream();
		} catch (SQLException e) {
			throw new RuntimeException(e);
		} finally {
			jdbcConfiguration.closeConnection(con);
		}
		return is;
	}

	public XMLObject getSPMetaData() throws WrappedException {
		XMLObject spMetadata = null;
		Connection con = jdbcConfiguration.getConnection();
		try {
			PreparedStatement ps = con.prepareStatement("SELECT metadata FROM serviceprovider");
			ResultSet rs = ps.executeQuery();
			rs.next();
			spMetadata = SAMLUtil.unmarshallElementFromString(rs.getString("metadata"));
		} catch (SQLException e) {
			throw new RuntimeException(e);
		} finally {
			jdbcConfiguration.closeConnection(con);
		}
		return spMetadata;
	}

	public List<XMLObject> getListOfIdpMetadata() throws WrappedException {
		List<XMLObject> idps = new ArrayList<XMLObject>();
		Connection con = jdbcConfiguration.getConnection();
		try {
			PreparedStatement ps = con.prepareStatement("SELECT metadata FROM identityproviders");
			ResultSet rs = ps.executeQuery();
			while (rs.next()) {
				idps.add(SAMLUtil.unmarshallElementFromString(rs.getString("metadata")));
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		} finally {
			jdbcConfiguration.closeConnection(con);
		}
		return idps;
	}

	public void setConfiguration(Configuration configuration) {
		systemConfiguration = configuration;
	}
}
