package certsdb

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	ctx := context.Background()
	// Choose DB implementation here (Mongo or SQLite)
	db, err := setupMongoCertDb()
	// db, err := setupSqliteCertDb("data/sqlite.db")
	if err != nil {
		log.Fatalf("DB setup failed: %v", err)
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
		fmt.Println("Error updating inactive certificates:", err)
	}
	fmt.Println("Finished processing certificates at", nowStr)
	fmt.Printf("Updated %d certificates to inactive\n", modified)
}
