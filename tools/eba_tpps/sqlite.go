package main

import (
	"context"
	"database/sql"

	"github.com/botsman/tppVerifier/app/models"
	_ "github.com/mattn/go-sqlite3"
)

type SqliteDb struct {
	DB *sql.DB
}

func setupSqliteDb(path string) (*SqliteDb, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	// Optionally, ping to check connection
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &SqliteDb{DB: db}, nil
}

func (db *SqliteDb) Disconnect(ctx context.Context) error {
	return db.DB.Close()
}

func (db *SqliteDb) SaveTPPs(ctx context.Context, _ string, tpps []models.TPP) error {
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	tppStmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO tpps (id, ob_id, name_latin, name_native, authority, country, type, registry, authorized_at, withdrawn_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer tppStmt.Close()

	serviceStmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO tpp_services (tpp_ob_id, country, service) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer serviceStmt.Close()

	for _, tpp := range tpps {
		_, err = tppStmt.ExecContext(ctx, tpp.Id, tpp.OBID, tpp.NameLatin, tpp.NameNative, tpp.Authority, tpp.Country, tpp.Type, tpp.Registry, tpp.AuthorizedAt, tpp.WithdrawnAt, tpp.CreatedAt, tpp.UpdatedAt)
		if err != nil {
			return err
		}
		for country, services := range tpp.Services {
			for _, service := range services {
				_, err = serviceStmt.ExecContext(ctx, tpp.OBID, country, string(service))
				if err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit()
}
