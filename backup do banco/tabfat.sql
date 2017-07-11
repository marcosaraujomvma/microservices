-- Table: faturas

-- DROP TABLE faturas;

CREATE TABLE faturas
(
  id serial NOT NULL,
  id_medidor character varying(4000),
  fatura character varying(30),
  signature text,
  "timestamp" timestamp without time zone DEFAULT now(),
  conferencia character varying(10),
  CONSTRAINT faturas_pkey PRIMARY KEY (id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE faturas
  OWNER TO postgres;

