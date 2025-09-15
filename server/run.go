package main

import (
	"context"
	"log"
	"net/http"

	"github.com/botsman/tppVerifier/app"
	"github.com/botsman/tppVerifier/app/cert"
	"github.com/botsman/tppVerifier/app/verify"

	// "github.com/botsman/tppVerifier/server/mongo"
	"github.com/botsman/tppVerifier/server/sqlite"
)

func main() {
	ctx := context.Background()

	// Uncomment the backend you want to use:
	// repo, err := mongo.NewMongoRepo(ctx, "mongodb://localhost:27017", "tppVerifier")
	repo, err := sqlite.NewSQLiteRepo("../data/sqlite.db")
	if err != nil {
		log.Fatalf("Failed to initialize repository: %v", err)
	}

	httpClient := &http.Client{}
	vs := verify.NewVerifySvc(repo, httpClient)
	roots, err := repo.GetRootCertificates(ctx)
	if err != nil {
		log.Fatalf("Failed to get root certificates: %v", err)
	}
	for _, root := range roots {
		if root == "" {
			log.Println("Skipping empty root certificate")
			continue
		}
		rootCerts, err := cert.ParseCerts([]byte(root))
		if err != nil {
			log.Printf("Error parsing root certificate: %s", err)
			continue
		}
		for _, rootCert := range rootCerts {
			if rootCert.Cert == nil {
				log.Println("Skipping nil root certificate")
				continue
			}
			vs.AddRoot(rootCert)
		}
	}
	r := app.SetupRouter(vs)
	r.Run()
}
