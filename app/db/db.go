package db

import (
	"context"
	"errors"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Client interface {
	Disconnect(ctx context.Context) error
	// GetOne(ctx context.Context, collectionName string, filter interface{}) (interface{}, error)
}

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
