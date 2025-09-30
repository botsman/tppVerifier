package tppdb

import (
	"context"
	"errors"
	"strings"

	"github.com/botsman/tppVerifier/app/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDb struct {
	Client   *mongo.Client
	Database *mongo.Database
}

func setupMongoDb(ctx context.Context, connStr string) (*MongoDb, error) {
	opts := options.Client().ApplyURI(connStr)
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return nil, err
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, err
	}
	dbName, err := extractDatabaseName(connStr)
	if err != nil {
		return nil, err
	}
	db := client.Database(dbName)
	return &MongoDb{
		Client:   client,
		Database: db,
	}, nil
}

func extractDatabaseName(connStr string) (string, error) {
	opts := options.Client().ApplyURI(connStr)
	if opts.Auth != nil && opts.Auth.AuthSource != "" {
		return opts.Auth.AuthSource, nil
	}
	connStrParts := strings.Split(connStr, "/")
	if len(connStrParts) < 2 {
		return "", errors.New("database name not found in connection string")
	}
	return connStrParts[len(connStrParts)-1], nil
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
