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
	return dbFile, New(dbFile)
}
