package main

import (
	"context"
	"log"

	"github.com/botsman/tppVerifier/app"
	"github.com/botsman/tppVerifier/app/db"
	"github.com/botsman/tppVerifier/app/dbRepository"
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

	tppRepo := dbRepository.NewTppMongoRepository(client.Database)
	r := app.SetupRouter(tppRepo)
	app.SetupTppVerifyRoutes(r)
	r.Run()
}
