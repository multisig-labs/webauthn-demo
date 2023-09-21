package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "embed"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

func OpenDB(dbFileName string) (*sql.DB, *Queries) {
	var dbFile *sql.DB
	var err error

	if _, err = os.Stat(dbFileName); err == nil {
		dbFile, err = sql.Open("sqlite", dbFileName)
		if err != nil {
			panic(err)
		}
	} else {
		// Create the DB
		if err := os.MkdirAll(filepath.Dir(dbFileName), 0755); err != nil {
			panic(err)
		}

		dbFile, err = sql.Open("sqlite", dbFileName)
		if err != nil {
			panic(err)
		}
		if _, err = dbFile.Exec(schema); err != nil {
			panic(err)
		}
		fmt.Println("Database created successfully.")
	}

	_, err = dbFile.Exec("PRAGMA optimize;PRAGMA foreign_keys=ON;PRAGMA journal_mode=WAL;")
	if err != nil {
		panic(err)
	}

	return dbFile, New(dbFile)
}
