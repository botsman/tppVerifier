package main

import (
	"context"
	"log"
	"net/http"

	"github.com/botsman/tppVerifier/app"
	"github.com/botsman/tppVerifier/app/verify"
	"github.com/botsman/tppVerifier/app/cert"
	"github.com/botsman/tppVerifier/server/db"
)

func main() {
	ctx := context.Background()
	client, err := db.GetMongoDb(ctx)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := client.Disconnect(context.TODO()); err != nil {
			log.Fatal(err)
		}
	}()

	httpClient := &http.Client{}
	tppRepo := db.NewTppMongoRepository(client.Database)
	vs := verify.NewVerifySvc(tppRepo, httpClient)
	roots, err := tppRepo.GetRootCertificates(ctx)
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
			vs.AddRoot(rootCert.Cert)
		}
	}
	r := app.SetupRouter(vs)
	r.Run()
}
