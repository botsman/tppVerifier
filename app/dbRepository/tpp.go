package dbRepository

import (
	"context"

	"github.com/botsman/tppVerifier/app/models"
	"github.com/gin-gonic/gin"
)


type TppRepository interface {
	GetTpp(ctx context.Context, id string) (*models.TPP, error)
}

func DbMiddleware(repo TppRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("tppRepository", repo)
		c.Next()
	}
}
