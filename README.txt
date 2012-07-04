See docs/index.html for full documentation, including installation
instructions.


Quick start:
 - Unzip oiosaml.java-sp-demo-*.war and edit WEB-INF/web.xml
 - Set oiosaml-j.home to point to an empty directory
 - Zip the files back into a war file
 - Deploy the war to a servlet container like Apache Tomcat
 - Open a browser and access the deployed application
 - Click on the Configure link to configure the system
 

 OIOSAML.java is distributed under the Mozilla Public License 1.1, 
 and is based on OpenSAML 2.0, which is released under the 
 Apache License 2.0.



Building the project:
 - Download and install Gant (http://gant.codehaus.org)
 - Run gant build_everything  (note that you will need gant 1.9.5 or earlier, later versions have issues)
 
When importing the project into Eclipse, remember to run gant build_everything
to download the necessary jar files.
  

Maven
=====
maven build is deprecated - use gant
