package app

import (

	"github.com/gin-gonic/gin"

	"github.com/botsman/tppVerifier/app/dbRepository"
	"github.com/botsman/tppVerifier/app/verify"
)


func SetupRouter(db dbRepository.TppRepository) *gin.Engine {
	r := gin.Default()
	r.Use(dbRepository.DbMiddleware(db))
	return r
}

func SetupTppVerifyRoutes(r *gin.Engine) {
	tppRoute := r.Group("/tpp")
	tppRoute.POST("/verify", verify.Verify)
}
