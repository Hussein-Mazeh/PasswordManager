package main

import (
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

func main() {
	dir := flag.String("dir", "", "vault directory containing vault.db")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --dir")
		os.Exit(1)
	}

	dbPath := filepath.Join(*dir, "vault.db")
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT id, website, username, type, salt, encrypted_pass FROM passwords ORDER BY id`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "query passwords: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	var found bool
	for rows.Next() {
		found = true
		var (
			id      int64
			website string
			user    string
			typ     string
			salt    []byte
			blob    []byte
		)

		if err := rows.Scan(&id, &website, &user, &typ, &salt, &blob); err != nil {
			fmt.Fprintf(os.Stderr, "scan row: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("ID %d | %s/%s (%s)\n", id, website, user, typ)
		fmt.Printf("  salt (base64): %s\n", base64.StdEncoding.EncodeToString(salt))
		fmt.Printf("  encrypted_pass (base64, %d bytes): %s\n", len(blob), base64.StdEncoding.EncodeToString(blob))
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "iterate rows: %v\n", err)
		os.Exit(1)
	}

	if !found {
		fmt.Println("no credentials stored")
	}
}
