package main

import (
	"log"

	"github.com/gin-gonic/gin"

	"github.com/botsman/tppVerifier/app/db"
	"github.com/botsman/tppVerifier/app/verify"
)

func DbMiddleware(client db.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("db", client)
		c.Next()
	}
}

func main() {
	db, err := db.GetMongoDb()
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := db.Disconnect(nil); err != nil {
			log.Fatal(err)
		}
	}()
	r := gin.Default()
	r.Use(DbMiddleware(db))

	tppRoute := r.Group("/tpp")
	tppRoute.POST("/verify", verify.Verify)
	r.Run()
}
