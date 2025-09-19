package mongo

import (
	"context"
	"errors"

	"github.com/botsman/tppVerifier/app/cert"
	"github.com/botsman/tppVerifier/app/db"
	"github.com/botsman/tppVerifier/app/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func NewMongoRepo(ctx context.Context, connStr string) (db.TppRepository, error) {
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
	return &TppMongoRepository{db: db}, nil
}

type TppMongoRepository struct {
	db *mongo.Database
}

func (r *TppMongoRepository) GetTpp(ctx context.Context, id string) (*models.TPP, error) {
	tpp := &models.TPP{}
	err := r.db.Collection("tpps").FindOne(ctx, bson.M{"ob_id": id}).Decode(&tpp)
	if err != nil {
		return nil, err
	}
	return tpp, nil
}

func (r *TppMongoRepository) GetRootCertificates(ctx context.Context) ([]string, error) {
	filter := bson.M{
		"is_active": true,
		"position":  models.PositionRoot,
	}
	cursor, err := r.db.Collection("certs").Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roots []string
	for cursor.Next(ctx) {
		var crt cert.ParsedCert
		if err := cursor.Decode(&crt); err != nil {
			return nil, err
		}
		roots = append(roots, string(crt.Cert.Raw))
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return roots, nil
}

func (r *TppMongoRepository) AddCertificate(ctx context.Context, cert *cert.ParsedCert) error {
	if cert == nil {
		return errors.New("certificate cannot be nil")
	}
	certBson, err := cert.ToBson()
	if err != nil {
		return err
	}
	_, err = r.db.Collection("certs").InsertOne(ctx, certBson)
	if err != nil {
		return err
	}
	return nil
}

func NewTppMongoRepository(db *mongo.Database) *TppMongoRepository {
	return &TppMongoRepository{db: db}
}
