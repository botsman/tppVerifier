package app

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/botsman/tppVerifier/app/verify"
)


type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}


func SetupRouter(vs *verify.VerifySvc) *gin.Engine {
	r := gin.Default()
	r.POST("/tpp/verify", vs.Verify)
	return r
}
