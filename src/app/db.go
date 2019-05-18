package app

import (
	"database/sql"
	"log"
)

var db *sql.DB

func InitDB(dbFile string) {
	var err error
	db, err = sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Fatalf("ERROR_DATABASE_INIT | %v", err)
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS users (" +
		"id INTEGER PRIMARY KEY, " +
		"username TEXT NOT NULL UNIQUE, " +
		"email TEXT NOT NULL UNIQUE, " +
		"password TEXT NOT NULL, " +
		"passwordsalt TEXT NOT NULL, " +
		"otpsecret TEXT NOT NULL, " +
		"lockexpire DATETIME NOT NULL" +
		")")
	if err != nil {
		log.Fatalf("ERROR_DATABASE_INIT | %v", err)
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS sessions (" +
		"sessionKey VARCHAR(32) PRIMARY KEY, " +
		"sessionData TEXT NOT NULL, " +
		"expires DATETIME NOT NULL, " +
		"valid INTEGER NOT NULL, " +
		"userid INTEGER NOT NULL, " +
		"useragent TEXT NOT NULL, " +
		"ipaddress TEXT NOT NULL" +
		")")
	if err != nil {
		log.Fatalf("ERROR_DATABASE_INIT | %v", err)
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS auth_tokens (" +
		"selector VARCHAR(12) PRIMARY KEY, " +
		"hashedvalidator VARCHAR(64) NOT NULL, " +
		"userid INTEGER NOT NULL, " +
		"expires DATETIME NOT NULL, " +
		"valid INTEGER NOT NULL, " +
		"useragent TEXT NOT NULL, " +
		"ipaddress TEXT NOT NULL" +
		")")
	if err != nil {
		log.Fatalf("ERROR_DATABASE_INIT | %v", err)
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS reset_tokens (" +
		"id INTEGER PRIMARY KEY, " +
		"userid INTEGER NOT NULL, " +
		"token VARCHAR(32) NOT NULL, " +
		"expire DATETIME NOT NULL, " +
		"valid INTEGER NOT NULL" +
		")")
	if err != nil {
		log.Fatalf("ERROR_DATABASE_INIT | %v", err)
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS login_attempts (" +
		"id INTEGER PRIMARY KEY, " +
		"username TEXT NOT NULL, " +
		"time DATETIME NOT NULL, " +
		"useragent TEXT NOT NULL, " +
		"ipaddr TEXT NOT NULL, " +
		"success INTEGER" +
		")")
	if err != nil {
		log.Fatalf("ERROR_DATABASE_INIT | %v", err)
	}
}
