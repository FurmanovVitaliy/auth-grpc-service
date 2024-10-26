package main

import (
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres" // PgSQL driver
	_ "github.com/golang-migrate/migrate/v4/source/file"       // file source driver
)

func main() {
	var migrationsPath, migrationsTable, dbHost, dbPort, dbUser, dbPassword, dbName string

	flag.StringVar(&migrationsTable, "migrations-table", "migrations", "name of the migrations table")
	flag.StringVar(&dbHost, "db-host", "localhost", "database host")
	flag.StringVar(&dbPort, "db-port", "5436", "database port")
	flag.StringVar(&dbUser, "db-user", "postgres", "database user")
	flag.StringVar(&dbPassword, "db-password", "qwerty", "database password")
	flag.StringVar(&dbName, "db-name", "sso", "database name")
	flag.StringVar(&migrationsPath, "migrations-path", "./migrations", "path to migrations")

	flag.Parse()

	if migrationsPath == "" {
		log.Fatal("migrations path is required")
	}

	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", dbUser, dbPassword, dbHost, dbPort, dbName)

	m, err := migrate.New(
		"file://"+migrationsPath,
		dbURL,
	)
	if err != nil {
		log.Fatalf("failed to create migrator: %v", err)
	}

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			log.Println("no migrations to apply")
			return
		}
		log.Fatalf("failed to apply migrations: %v", err)
	}

	log.Println("migrations applied successfully")
}
