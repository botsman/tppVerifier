package main

import (
	"log"

	"github.com/gin-gonic/gin"

	"github.com/botsman/tppVerifier/app/db"
	"github.com/botsman/tppVerifier/app/dbRepository"
	"github.com/botsman/tppVerifier/app/verify"
)

func setupRouter() *gin.Engine {
	r := gin.Default()
	return r
}

func setupTppVerifyRoutes(r *gin.Engine) {
	tppRoute := r.Group("/tpp")
	tppRoute.POST("/verify", verify.Verify)
}

func main() {
	client, err := db.GetMongoDb()
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := client.Disconnect(nil); err != nil {
			log.Fatal(err)
		}
	}()

	tppRepo := dbRepository.NewTppMongoRepository(client.Database)
	r := setupRouter()
	setupTppVerifyRoutes(r)
	r.Use(dbRepository.DbMiddleware(tppRepo))
	r.Run()
}
