-- Table: logmedidores

-- DROP TABLE logmedidores;

CREATE TABLE logmedidores
(
  id serial NOT NULL,
  id_medidor text,
  leitura text,
  ts_medidor text,
  assinatura text,
  ts_server timestamp without time zone DEFAULT now(),
  CONSTRAINT logmedidores_pkey PRIMARY KEY (id)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE logmedidores
  OWNER TO postgres;

