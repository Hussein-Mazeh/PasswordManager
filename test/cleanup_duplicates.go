package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	_ "modernc.org/sqlite"
)

func main() {
	dir := flag.String("dir", "", "vault directory containing vault.db")
	dryRun := flag.Bool("dry-run", false, "print duplicates without deleting")
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

	rows, err := db.Query(`SELECT id, website, username FROM passwords ORDER BY website, username, id`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "query passwords: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	type record struct {
		id      int64
		website string
		user    string
	}

	duplicates := make(map[string][]record)

	for rows.Next() {
		var r record
		if err := rows.Scan(&r.id, &r.website, &r.user); err != nil {
			fmt.Fprintf(os.Stderr, "scan row: %v\n", err)
			os.Exit(1)
		}
		key := r.website + "\u0000" + r.user
		duplicates[key] = append(duplicates[key], r)
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "iterate rows: %v\n", err)
		os.Exit(1)
	}

	var removal []record
	for _, records := range duplicates {
		if len(records) <= 1 {
			continue
		}
		// keep the earliest id (records already ordered by id), remove the rest
		removal = append(removal, records[1:]...)
	}

	if len(removal) == 0 {
		fmt.Println("no duplicate website/username pairs found")
		return
	}

	sort.Slice(removal, func(i, j int) bool { return removal[i].id < removal[j].id })

	fmt.Printf("found %d duplicate rows to delete:\n", len(removal))
	for _, r := range removal {
		fmt.Printf("  id=%d website=%s user=%s\n", r.id, r.website, r.user)
	}

	if *dryRun {
		fmt.Println("dry run requested; no rows deleted")
		return
	}

	tx, err := db.Begin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "begin transaction: %v\n", err)
		os.Exit(1)
	}

	for _, r := range removal {
		if _, err := tx.Exec(`DELETE FROM passwords WHERE id = ?`, r.id); err != nil {
			tx.Rollback()
			fmt.Fprintf(os.Stderr, "delete id %d: %v\n", r.id, err)
			os.Exit(1)
		}
	}

	if err := tx.Commit(); err != nil {
		fmt.Fprintf(os.Stderr, "commit transaction: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("deleted %d duplicate rows\n", len(removal))
}
