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
	rootPool := x509.NewCertPool()
	for _, root := range roots {
		// TODO: check if roots are formatted correctly
		if !rootPool.AppendCertsFromPEM([]byte(root)) {
			log.Printf("Failed to append root certificate")
		}
	}
	vs.SetRoots(rootPool)
	r := app.SetupRouter(vs)
	r.Run()
}
