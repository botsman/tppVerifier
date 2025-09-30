package tppdb

import (
	"context"
	"log"

	"github.com/botsman/tppVerifier/app/models"
)

type db interface {
	SaveTPPs(ctx context.Context, collection string, tpp []models.TPP) error
	Disconnect(ctx context.Context) error
}

func Run(ctx context.Context, connStr string) error {
	// Download and parse the registry
	// populate DB
	// 1. Download metadata at https://euclid.eba.europa.eu/register/api/filemetadata?t=1737374419184
	// 2. Download the zip file at `golden_copy_path_context` + `latest_version_relative_zip_path`
	// 3. Unzip the file
	// 4. Parse the file
	// 5. Save the parsed data to the DB
	client, err := setupMongoDb(ctx, connStr)
	// client, err := setupSqliteDb(ctx, connStr)
	if err != nil {
		return err
	}

	err = getRegistry()
	if err != nil {
		log.Printf("Error getting registry: %s\n", err)
		return err
	}
	defer deleteRegistry()

	tppChan, err := parseRegistry()
	if err != nil {
		return err
	}
	defer client.Disconnect(ctx)
	return saveTPPs(client, tppChan)
}
