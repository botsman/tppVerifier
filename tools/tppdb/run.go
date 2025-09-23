package tppdb

import (
	"context"

	"github.com/botsman/tppVerifier/app/models"
)

type db interface {
	SaveTPPs(ctx context.Context, collection string, tpp []models.TPP) error
	Disconnect(ctx context.Context) error
}

func Run() error {
	// Download and parse the registry
	// populate DB
	// 1. Download metadata at https://euclid.eba.europa.eu/register/api/filemetadata?t=1737374419184
	// 2. Download the zip file at `golden_copy_path_context` + `latest_version_relative_zip_path`
	// 3. Unzip the file
	// 4. Parse the file
	// 5. Save the parsed data to the DB

	getRegistry()
	defer deleteRegistry()

	tppChan, err := parseRegistry()
	if err != nil {
		return err
	}
	client, err := setupMongoDb()
	// client, err := setupSqliteDb("data/sqlite.db")
	if err != nil {
		return err
	}
	defer client.Disconnect(context.TODO())
	return saveTPPs(client, tppChan)
}
