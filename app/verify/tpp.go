package verify

import (
	"errors"

	"github.com/botsman/tppVerifier/app/dbrepository"
	"github.com/botsman/tppVerifier/app/models"
	"github.com/gin-gonic/gin"
)

func getTpp(c *gin.Context, id string) (*models.TPP, error) {
	repo, ok := c.MustGet("tppRepository").(dbrepository.TppRepository)
	if !ok {
		return nil, errors.New("Couldn't get db client")
	}
	tpp, err := repo.GetTpp(c, id)
	if err != nil {
		return nil, err
	}
	return tpp, nil
}
