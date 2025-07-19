package db

import (
	"context"
	"errors"
	"log"
	"os"
	"time"

	"github.com/botsman/tppVerifier/app/models"
	"github.com/botsman/tppVerifier/app/cert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoClient struct {
	Client   *mongo.Client
	Database *mongo.Database
}

func GetMongoDb(ctx context.Context) (*MongoClient, error) {
	mongoURI := os.Getenv("MONGO_URL")
	if mongoURI == "" {
		return nil, errors.New("MONGO_URL is not set")
	}
	clientOptions := options.Client().ApplyURI(mongoURI)

	mongoClient, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	err = mongoClient.Ping(ctx, nil)
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
	return db.Database.Client().Disconnect(ctx)
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

func (r *TppMongoRepository) GetRootCertificates(ctx context.Context) ([]string, error) {
	// Get all certificates from the "certs" collection for now
	cursor, err := r.db.Collection("certs").Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roots []string
	for cursor.Next(ctx) {
		var tpp models.ParsedCert
		if err := cursor.Decode(&tpp); err != nil {
			return nil, err
		}
		roots = append(roots, tpp.Pem)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return roots, nil
}

func (r *TppMongoRepository) AddIntermediateCertificate(ctx context.Context, cert *cert.ParsedCert) error {
	if cert == nil {
		return errors.New("certificate cannot be nil")
	}
	certBson, err := cert.ToBson(time.Now())
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
