-- Dummy Subnet API for doing fake transactions. 
-- Only support one token type.

CREATE TABLE accounts (
  id integer PRIMARY KEY,
  address text NOT NULL,
  balance integer NOT NULL
) STRICT;

CREATE UNIQUE INDEX accounts_address ON accounts(address);

CREATE TABLE txs (
  id text PRIMARY KEY,
	height integer NOT NULL,
  payer text NOT NULL,
  payee text NOT NULL,
  amount integer NOT NULL,
  FOREIGN KEY(type_id) REFERENCES types(id)
) STRICT;

CREATE UNIQUE INDEX txs_height ON txs(height);

