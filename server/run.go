package main

import (
	"context"
	"log"

	"github.com/botsman/tppVerifier/app"
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

	tppRepo := db.NewTppMongoRepository(client.Database)
	r := app.SetupRouter(tppRepo)
	app.SetupTppVerifyRoutes(r)
	r.Run()
}
