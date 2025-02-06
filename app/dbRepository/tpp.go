package dbrepository

import (
	"context"

	"github.com/botsman/tppVerifier/app/models"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)


type TppRepository interface {
	GetTpp(ctx context.Context, id string) (*models.TPP, error)
}

type TppMongoRepository struct {
	db *mongo.Database
}

func (r *TppMongoRepository) GetTpp(ctx context.Context, id string) (*models.TPP, error) {
	tpp := &models.TPP{}
	err := r.db.Collection("tpp").FindOne(ctx, bson.M{"id": id}).Decode(&tpp)
	if err != nil {
		return nil, err
	}
	return tpp, nil
}

func NewTppMongoRepository(db *mongo.Database) *TppMongoRepository {
	return &TppMongoRepository{db: db}
}

func DbMiddleware(repo TppRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("tppRepository", repo)
		c.Next()
	}
}
