package main

import (
	"context"
	"crypto/x509"
	"log"
	"net/http"

	"github.com/botsman/tppVerifier/app"
	"github.com/botsman/tppVerifier/app/verify"
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

	httpClient := &http.Client{} // Assuming you want to use a default HTTP client
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
		rootCert, err := verify.RawCertToPEM([]byte(root))
		if err != nil {
			log.Printf("Error converting root certificate to PEM format: %s", err)
			continue
		}
		cert, err := x509.ParseCertificate(rootCert)
		if err != nil {
			log.Printf("Error parsing root certificate: %s", err)
			continue
		}
		vs.AddRoot(cert)
	}
	r := app.SetupRouter(vs)
	r.Run()
}
