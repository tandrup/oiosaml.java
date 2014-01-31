DROP TABLE IF EXISTS oiosaml_assertions; 
CREATE TABLE oiosaml_assertions
(
  id character varying(255) NOT NULL,
  assertion text NOT NULL,
  assertionid character varying(255) NOT NULL,
  sessionindex character varying(255) NOT NULL,
  "timestamp" timestamp without time zone NOT NULL,
  CONSTRAINT oiosaml_assertions_pkey PRIMARY KEY (id),
  CONSTRAINT oiosaml_assertions_assertionid_key UNIQUE (assertionid),
  CONSTRAINT oiosaml_assertions_sessionindex_key UNIQUE (sessionindex)
);

DROP TABLE IF EXISTS oiosaml_identityproviders;
CREATE TABLE oiosaml_identityproviders
(
  id character varying(255) NOT NULL,
  certificateurl character varying(255),
  entityid character varying(255),
  loginurl character varying(255),
  logouturl character varying(255),
  metadata text,
  metadataurl character varying(255),
  validfrom date,
  validto date,
  version integer,
  CONSTRAINT identityproviders_pkey PRIMARY KEY (id)
);

DROP TABLE IF EXISTS oiosaml_java_keystore;
CREATE TABLE oiosaml_java_keystore
(
  id character varying(255) NOT NULL,
  keystore bytea,
  ks_type character varying(255),
  CONSTRAINT java_keystore_pkey PRIMARY KEY (id)
);

DROP TABLE IF EXISTS oiosaml_logger;
CREATE TABLE oiosaml_logger
(
  id character varying(255) NOT NULL,
  log4j text,
  CONSTRAINT logger_pkey PRIMARY KEY (id)
);

DROP TABLE IF EXISTS oiosaml_properties;
CREATE TABLE oiosaml_properties
(
  conf_key character varying(255) NOT NULL,
  conf_value character varying(255),
  CONSTRAINT properties_pkey PRIMARY KEY (conf_key)
);

DROP TABLE IF EXISTS oiosaml_requestdata;
CREATE TABLE oiosaml_requestdata
(
  id character varying(255) NOT NULL,
  data text NOT NULL,
  "timestamp" timestamp without time zone NOT NULL,
  CONSTRAINT oiosaml_requestdata_pkey PRIMARY KEY (id)
);

DROP TABLE IF EXISTS oiosaml_requests;
CREATE TABLE oiosaml_requests
(
  id character varying(255) NOT NULL,
  receiver text NOT NULL,
  "timestamp" timestamp without time zone NOT NULL,
  CONSTRAINT oiosaml_requests_pkey PRIMARY KEY (id)
);

DROP TABLE IF EXISTS oiosaml_serviceprovider;
CREATE TABLE oiosaml_serviceprovider
(
  id character varying(255) NOT NULL,
  entityid character varying(255),
  loginurl character varying(255),
  logouturl character varying(255),
  metadata text,
  validfrom date,
  validto date,
  version integer,
  CONSTRAINT serviceprovider_pkey PRIMARY KEY (id)
);
