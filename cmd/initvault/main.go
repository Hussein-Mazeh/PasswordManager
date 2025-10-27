package main

import (
	"log"

	"github.com/Hussein-Mazeh/PasswordManager/internal/vault"
)

func main() {
	db, err := vault.Open(vault.Config{})
	if err != nil {
		log.Fatalf("open vault database: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec("VACUUM"); err != nil {
		log.Fatalf("initialize vault database: %v", err)
	}
}
