package db

import (
	"context"

	"github.com/botsman/tppVerifier/app/models"
)


type TppRepository interface {
	GetTpp(ctx context.Context, id string) (*models.TPP, error)
}
