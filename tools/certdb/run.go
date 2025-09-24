package certdb

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func Run(ctx context.Context, connStr string) error {
	// Choose DB implementation here (Mongo or SQLite)
	db, err := setupMongoCertDb(ctx, connStr)
	// db, err := setupSqliteCertDb(ctx, connStr)
	if err != nil {
		return fmt.Errorf("DB setup failed: %w", err)
	}
	defer db.Disconnect(ctx)

	now := time.Now()
	nowStr := now.Format(time.RFC3339)
	fmt.Println(nowStr)
	httpClient := &http.Client{}

	xmlChan := loadXMLs(httpClient)
	certsChan := parseXMLs(xmlChan)
	parsedCertsChan := parseCerts(certsChan, now)

	for crt := range parsedCertsChan {
		err := db.SaveCert(ctx, crt)
		if err != nil {
			fmt.Println("Error saving cert:", err)
		}
	}

	modified, err := db.CleanupInactive(ctx, now)
	if err != nil {
		return fmt.Errorf("error updating inactive certificates: %w", err)
	}
	fmt.Println("Finished processing certificates at", nowStr)
	fmt.Printf("Updated %d certificates to inactive\n", modified)
	return nil
}
