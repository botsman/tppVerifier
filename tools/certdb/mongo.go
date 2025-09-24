package certdb

import (
	"context"
	"github.com/botsman/tppVerifier/app/cert"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type MongoCertDb struct {
	Client   *mongo.Client
	Database *mongo.Database
}

func setupMongoCertDb(ctx context.Context, connStr string) (*MongoCertDb, error) {
	opts := options.Client().ApplyURI(connStr)
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return nil, err
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, err
	}
	db := client.Database(opts.Auth.AuthSource)
	if db == nil {
		db = client.Database("tppVerifier")
	}
	return &MongoCertDb{
		Client:   client,
		Database: db,
	}, nil
}

func (db *MongoCertDb) Disconnect(ctx context.Context) error {
	return db.Client.Disconnect(ctx)
}

func (db *MongoCertDb) SaveCert(ctx context.Context, crt *cert.ParsedCert) error {
	certsCollection := db.Database.Collection("certs")
	filter := map[string]any{"sha256": crt.Sha256()}
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
