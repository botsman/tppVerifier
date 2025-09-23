package certdb

import (
	"context"
	"database/sql"
	"github.com/botsman/tppVerifier/app/cert"
	_ "github.com/mattn/go-sqlite3"
	"time"
)

type SqliteCertDb struct {
	DB *sql.DB
}

func setupSqliteCertDb(path string) (*SqliteCertDb, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &SqliteCertDb{DB: db}, nil
}

func (db *SqliteCertDb) Disconnect(ctx context.Context) error {
	return db.DB.Close()
}

func (db *SqliteCertDb) SaveCert(ctx context.Context, crt *cert.ParsedCert) error {
	stmt, err := db.DB.PrepareContext(ctx, `INSERT OR REPLACE INTO certs (sha256, pem, serial_number, not_before, not_after, updated_at, created_at, is_active, position) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	stmt, err = db.DB.PrepareContext(ctx, `
		INSERT INTO certs (sha256, pem, serial_number, not_before, not_after, updated_at, created_at, is_active, position)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(sha256) DO UPDATE SET
			pem=excluded.pem,
			serial_number=excluded.serial_number,
			not_before=excluded.not_before,
			not_after=excluded.not_after,
			updated_at=excluded.updated_at,
			is_active=excluded.is_active,
			position=excluded.position,
			created_at=certs.created_at
	`)
	if err != nil {
		return err
	}
	_, err = stmt.ExecContext(ctx,
		crt.Sha256(),
		crt.Pem(),
		crt.Cert.SerialNumber.String(),
		crt.Cert.NotBefore,
		crt.Cert.NotAfter,
		crt.UpdatedAt,
		crt.CreatedAt,
		crt.IsActive,
		crt.Position,
	)
	return err
}

func (db *SqliteCertDb) CleanupInactive(ctx context.Context, now time.Time) (int64, error) {
	res, err := db.DB.ExecContext(ctx, `UPDATE certs SET is_active = 0 WHERE is_active = 1 AND position = 'Root' AND updated_at != ?`, now)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return n, err
}
