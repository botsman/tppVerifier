package main

import (
	"context"
	"log"
	"net/http"

	"github.com/botsman/tppVerifier/app"
	"github.com/botsman/tppVerifier/app/verify"
	"github.com/botsman/tppVerifier/server/db"
)

func main() {
	client, err := db.GetMongoDb()
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
	r := app.SetupRouter(vs)
	r.Run()
}
