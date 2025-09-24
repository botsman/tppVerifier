package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/botsman/tppVerifier/app/cert"
	"github.com/botsman/tppVerifier/app/db"
	"github.com/botsman/tppVerifier/app/models"
	_ "github.com/mattn/go-sqlite3"
)

// NewSQLiteRepo creates a TppRepository backed by SQLite, using the given database file path.
func NewSQLiteRepo(_ context.Context, path string) (db.TppRepository, error) {
	dbConn, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	if err := dbConn.Ping(); err != nil {
		return nil, err
	}
	return &TppSqliteRepository{db: dbConn}, nil
}

type TppSqliteRepository struct {
	db *sql.DB
}

func NewTppSqliteRepository(db *sql.DB) *TppSqliteRepository {
	return &TppSqliteRepository{db: db}
}

func (r *TppSqliteRepository) GetTpp(ctx context.Context, id string) (*models.TPP, error) {
	row := r.db.QueryRowContext(ctx, `SELECT name_latin, name_native, id, ob_id, authority, country, type, registry, authorized_at, withdrawn_at, created_at, updated_at FROM tpps WHERE ob_id = ?`, id)
	tpp := &models.TPP{}
	var authorizedAt, withdrawnAt, createdAt, updatedAt sql.NullTime
	err := row.Scan(&tpp.NameLatin, &tpp.NameNative, &tpp.Id, &tpp.OBID, &tpp.Authority, &tpp.Country, &tpp.Type, &tpp.Registry, &authorizedAt, &withdrawnAt, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	if authorizedAt.Valid {
		tpp.AuthorizedAt = &authorizedAt.Time
	}
	if withdrawnAt.Valid {
		tpp.WithdrawnAt = &withdrawnAt.Time
	}
	tpp.CreatedAt = createdAt.Time
	tpp.UpdatedAt = updatedAt.Time

	services := make(map[string][]models.Service)
	rows, err := r.db.QueryContext(ctx, `SELECT country, service FROM tpp_services WHERE tpp_ob_id = ?`, tpp.OBID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var country, service string
		if err := rows.Scan(&country, &service); err != nil {
			return nil, err
		}
		services[country] = append(services[country], models.Service(service))
	}
	tpp.Services = services

	return tpp, nil
}

func (r *TppSqliteRepository) GetRootCertificates(ctx context.Context) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT pem FROM certs WHERE is_active = 1 AND position = ?`, models.PositionRoot)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roots []string
	for rows.Next() {
		var certRaw []byte
		if err := rows.Scan(&certRaw); err != nil {
			return nil, err
		}
		roots = append(roots, string(certRaw))
	}
	return roots, nil
}

func (r *TppSqliteRepository) AddCertificate(ctx context.Context, c *cert.ParsedCert) error {
	if c == nil {
		return errors.New("certificate cannot be nil")
	}
	certBson, err := c.ToBson()
	if err != nil {
		return err
	}
	// Map certBson to SQL fields as needed
	_, err = r.db.ExecContext(ctx, `INSERT INTO certs (cert_raw, is_active, position) VALUES (?, ?, ?)`, c.Cert.Raw, certBson["is_active"], certBson["position"])
	return err
}
