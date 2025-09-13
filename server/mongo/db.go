package mongo

import (
	"context"
	"errors"
	"log"
	"os"

	"github.com/botsman/tppVerifier/app/cert"
	"github.com/botsman/tppVerifier/app/models"
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
	err := r.db.Collection("tpps").FindOne(ctx, bson.M{"ob_id": id}).Decode(&tpp)
	if err != nil {
		return nil, err
	}
	return tpp, nil
}

func (r *TppMongoRepository) GetRootCertificates(ctx context.Context) ([]string, error) {
	filter := bson.M{
		"is_active": true,
		"position":  models.Root,
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
