package app

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/botsman/tppVerifier/app/verify"
)

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func SetupRouter(vs *verify.VerifySvc) *gin.Engine {
	r := gin.Default()
	headerName := os.Getenv("AUTH_HEADER_NAME")
	headerValue := os.Getenv("AUTH_HEADER_VALUE")
	if headerName == "" || headerValue == "" {
		panic("AUTH_HEADER_NAME and AUTH_HEADER_VALUE must be set")
	}

	r.Use(func(c *gin.Context) {
		if c.GetHeader(headerName) != headerValue {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid or missing header"})
			return
		}
		c.Next()
	})

	r.POST("/tpp/verify", vs.Verify)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	return r
}
