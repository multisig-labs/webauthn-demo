package db

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

func OpenDB(dbFileName string) (*sql.DB, *Queries) {
	dbFile, err := sql.Open("sqlite", dbFileName)
	if err != nil {
		panic(err)
	}
	_, err = dbFile.Exec("PRAGMA optimize;PRAGMA foreign_keys=ON;PRAGMA journal_mode=WAL;")
	if err != nil {
		panic(err)
	}

	// Create tables
	schema := `
CREATE TABLE accounts (
  id integer PRIMARY KEY,
  address text NOT NULL,
  balance integer NOT NULL
);
CREATE UNIQUE INDEX accounts_address ON accounts(address);
CREATE TABLE txs (
  id text PRIMARY KEY,
  payer text NOT NULL,
  payee text NOT NULL,
  amount integer NOT NULL,
  tx_hash text NOT NULL,
  sig text NOT NULL
);
`
	_, err = dbFile.Exec(schema)
	if err != nil {
		panic(err)
	}

	_, err = dbFile.Exec(`INSERT INTO accounts (address, balance) VALUES ('dummyAddr1', 1000), ('dummyAddr2', 500)`)
	if err != nil {
		panic(err)
	}
	return dbFile, New(dbFile)
}
