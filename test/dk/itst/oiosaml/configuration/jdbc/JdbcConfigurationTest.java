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
 * created by Trifork A/S are Copyright (C) 2012 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.configuration.jdbc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.io.InputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

public class JdbcConfigurationTest {

	
	@Before
	public void setUp() throws Exception {
	
	}

	@After
	public void tearDown() throws Exception {
	
	}

	@Test
	public void testReadJndiName() {
		try {
			InputStream resourceAsStream = this.getClass().getClassLoader().getResourceAsStream(JdbcConfiguration.OIOSAML_DATASOURCE);
			DocumentBuilder dom=DocumentBuilderFactory.newInstance().newDocumentBuilder();
			Document dsDom = dom.parse(resourceAsStream);
			System.out.println(getStringFromDoc(dsDom));
			String jndiName = dsDom.getElementsByTagName(JdbcConfiguration.TAG_NAME).item(0).getTextContent();
			assertEquals("jdbc/oiosaml.ds", jndiName);
			assertFalse("jdbc/wrong.ds".equalsIgnoreCase(jndiName));

		} catch (Exception e) {
			fail("Unable to lookup "+JdbcConfiguration.TAG_NAME+" from "+JdbcConfiguration.OIOSAML_DATASOURCE+ " ["+e.getMessage()+"]");
		} 
	}
	
	public String getStringFromDoc(org.w3c.dom.Document doc)    {
	    DOMImplementationLS domImplementation = (DOMImplementationLS) doc.getImplementation();
	    LSSerializer lsSerializer = domImplementation.createLSSerializer();
	    return lsSerializer.writeToString(doc);   
	}

}
