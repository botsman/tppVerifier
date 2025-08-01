package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/botsman/tppVerifier/app/models"
)

type Service string

const (
	AIS Service = "AISP"
	PIS Service = "PISP"
	// CBPII Service = "CBPII"
)

const RegisterJsonName = "eba_register.json"

var now = time.Now()

// func serviceFromString(str string) (Service, error) {
// 	switch str {
// 	case "PS_080":
// 		return AIS, nil
// 	case "PS_070":
// 		return PIS, nil
// 	}
// 	return "", fmt.Errorf("unknown service: %s", str)
// }

func getRegistry() error {
	reader, err := downloadRegistry()
	if err != nil {
		return err
	}
	err = unzip(reader)
	if err != nil {
		return err
	}
	return nil
}

func downloadRegistry() (io.ReadCloser, error) {
	metadataUrl := fmt.Sprintf("https://euclid.eba.europa.eu/register/api/filemetadata?t=%d", time.Now().Unix())
	metadataResponse, err := http.Get(metadataUrl)
	if err != nil {
		log.Printf("Error getting metadata: %s\n", err)
		return nil, err
	}
	metadataBody, err := io.ReadAll(metadataResponse.Body)
	if err != nil {
		return nil, err
	}
	metadata := map[string]string{}
	err = json.Unmarshal(metadataBody, &metadata)
	if err != nil {
		log.Fatalln("Error unmarshalling metadata", err)
		return nil, err
	}
	registerUrl := metadata["golden_copy_path_context"] + metadata["latest_version_relative_zip_path"]
	registerReq, err := http.Get(registerUrl)
	if err != nil {
		return nil, err
	}
	return registerReq.Body, nil
}

func unzip(arch io.ReadCloser) error {
	buff := bytes.NewBuffer([]byte{})
	size, err := io.Copy(buff, arch)
	if err != nil {
		return err
	}

	reader := bytes.NewReader(buff.Bytes())
	zipReader, err := zip.NewReader(reader, size)
	if err != nil {
		return err
	}
	for _, f := range zipReader.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		err := unzipFile(f)
		if err != nil {
			return err
		}
	}
	return nil
}

func unzipFile(f *zip.File) error {
	fileReader, err := f.Open()
	if err != nil {
		return err
	}
	dst, err := os.Create(RegisterJsonName)
	if err != nil {
		return err
	}
	defer func(dst *os.File) {
		err := dst.Close()
		if err != nil {
			panic(err)
		}
	}(dst)
	_, err = io.Copy(dst, fileReader)
	if err != nil {
		return err
	}
	return nil
}

func parseRegistry() (<-chan models.TPP, error) {
	file, err := os.ReadFile(RegisterJsonName)
	if err != nil {
		return nil, err
	}

	res := make(chan models.TPP)
	go func() {
		var registry [][]models.TPP
		err = json.Unmarshal(file, &registry)
		if err != nil {
			log.Fatal(err)
		}
		for _, tpps := range registry {
			for _, tpp := range tpps {
				if tpp.Id == "" {
					continue
				}
				if tpp.Type == "" {
					continue
				}
				if tpp.NameLatin == "" {
					continue
				}
				if len(tpp.Services) == 0 {
					continue
				}
				tpp.CreatedAt = now
				tpp.UpdatedAt = now
				res <- tpp
			}
		}
		close(res)
	}()
	return res, nil
}

func setupDb() (*mongo.Client, error) {
	// mongoURI := os.Getenv("MONGO_URL")
	mongoURI := "mongodb://localhost:27017"
	if mongoURI == "" {
		return nil, errors.New("MONGO_URL is not set")
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
	return client, nil
}

func saveTPPs(out <-chan models.TPP) error {
	client, err := setupDb()
	if err != nil {
		return err
	}
	defer client.Disconnect(context.TODO())
	// TODO: use a bulk insert
	collection := client.Database("tppVerifier").Collection("tpps")
	batchSize := 1000
	batch := make([]interface{}, 0, batchSize)
	idx := 0
	for tpp := range out {
		idx += 1
		batch = append(batch, tpp)
		if idx == batchSize {
			_, err := collection.InsertMany(context.TODO(), batch)
			if err != nil {
				return err
			}
			batch = make([]interface{}, 0, batchSize)
			idx = 0
		}
	}
	if len(batch) > 0 {
		_, err := collection.InsertMany(context.TODO(), batch)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	// Download and parse the registry
	// populate DB
	// 1. Download metadata at https://euclid.eba.europa.eu/register/api/filemetadata?t=1737374419184
	// 2. Download the zip file at `golden_copy_path_context` + `latest_version_relative_zip_path`
	// 3. Unzip the file
	// 4. Parse the file
	// 5. Save the parsed data to the DB

	getRegistry()
	tppChan, err := parseRegistry()
	if err != nil {
		log.Fatal(err)
	}
	err = saveTPPs(tppChan)
	if err != nil {
		log.Fatal(err)
	}
}
