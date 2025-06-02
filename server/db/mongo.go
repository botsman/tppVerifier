package db

import (
	"context"
	"errors"
	"log"
	"os"

	"github.com/botsman/tppVerifier/app/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoClient struct {
	Client   *mongo.Client
	Database *mongo.Database
}

func GetMongoDb() (*MongoClient, error) {
	mongoURI := os.Getenv("MONGO_URL")
	if mongoURI == "" {
		return nil, errors.New("MONGO_URL is not set")
	}
	clientOptions := options.Client().ApplyURI(mongoURI)

	mongoClient, err := mongo.Connect(nil, clientOptions)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	err = mongoClient.Ping(nil, nil)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	dbName := os.Getenv("MONGO_DB")
	if dbName == "" {
		log.Fatal("MONGO_DB is not set")
		panic("MONGO_DB is not set")
	}
	db := mongoClient.Database(dbName)
	return &MongoClient{Client: mongoClient, Database: db}, nil
}

func (db *MongoClient) Disconnect(ctx context.Context) error {
	return db.Disconnect(ctx)
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
