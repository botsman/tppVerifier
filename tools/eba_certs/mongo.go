package main

import (
	"context"
	"log"
	"os"
	"time"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"github.com/botsman/tppVerifier/app/cert"
)

type MongoCertDb struct {
	Client   *mongo.Client
	Database *mongo.Database
}

func setupMongoCertDb() (*MongoCertDb, error) {
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
	return &MongoCertDb{
		Client:   client,
		Database: client.Database("tppVerifier"),
	}, nil
}

func (db *MongoCertDb) Disconnect(ctx context.Context) error {
	return db.Client.Disconnect(ctx)
}

func (db *MongoCertDb) SaveCert(ctx context.Context, crt *cert.ParsedCert) error {
	certsCollection := db.Database.Collection("certs")
	filter := map[string]any{ "sha256": crt.Sha256() }
	certSet, err := crt.ToBson()
	if err != nil {
		return err
	}
	update := map[string]any{
		"$set": certSet,
		"$setOnInsert": map[string]any{
			"created_at": crt.CreatedAt,
		},
	}
	opts := options.Update().SetUpsert(true)
	_, err = certsCollection.UpdateOne(ctx, filter, update, opts)
	return err
}


func (db *MongoCertDb) CleanupInactive(ctx context.Context, now time.Time) (int64, error) {
	certsCollection := db.Database.Collection("certs")
	res, err := certsCollection.UpdateMany(ctx,
		map[string]any{
			"is_active":  true,
			"position":   "Root",
			"updated_at": map[string]any{"$ne": now},
		},
		map[string]any{
			"$set": map[string]any{"is_active": false},
		},
	)
	if err != nil {
		return 0, err
	}
	return res.ModifiedCount, nil
}
