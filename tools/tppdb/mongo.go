package tppdb

import (
	"context"
	"log"
	"os"

	"github.com/botsman/tppVerifier/app/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDb struct {
	Client   *mongo.Client
	Database *mongo.Database
}

func setupMongoDb() (*MongoDb, error) {
	mongoURI := os.Getenv("MONGO_URL")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	clientOptions := options.Client().ApplyURI(mongoURI)

	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return &MongoDb{
		Client:   client,
		Database: client.Database("tppVerifier"),
	}, nil
}

func (db *MongoDb) Disconnect(ctx context.Context) error {
	return db.Client.Disconnect(ctx)
}

func (db *MongoDb) SaveTPPs(ctx context.Context, collectionName string, tpps []models.TPP) error {
	collection := db.Database.Collection(collectionName)
	opts := options.Update().SetUpsert(true)
	for _, tpp := range tpps {
		filter := bson.M{"id": tpp.Id}
		update := bson.M{"$set": tpp}
		_, err := collection.UpdateOne(ctx, filter, update, opts)
		if err != nil {
			return err
		}
	}
	return nil
}
