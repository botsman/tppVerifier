package ebacerts

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Load XML files from EBA
// Parse them
// Insert results into the database

type CertType string

const (
	QWAC   CertType = "QWAC"
	QSealC CertType = "QSealC"
)

type Scope string

const (
	AIS Scope = "AIS"
	PIS Scope = "PIS"
)

type Register string

const (
	EBA Register = "EBA"
)

type RawCert struct {
	Pem  string
	Type CertType
}

func getEEACountries() []string {
	return []string{
		"AT",
		"BE",
		"BG",
		"HR",
		"CY",
		"CZ",
		"DK",
		"EE",
		"FI",
		"FR",
		"DE",
		"GR",
		"HU",
		"IS",
		"IE",
		"IT",
		"LV",
		"LI",
		"LT",
		"LU",
		"MT",
		"NL",
		"NO",
		"PL",
		"PT",
		"RO",
		"SK",
		"SI",
		"ES",
		"SE",
	}
}

func loadXMLs(client *http.Client) <-chan []byte {
	xmlChan := make(chan []byte)
	var wg sync.WaitGroup
	for _, country := range getEEACountries() {
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			res, err := client.Get(fmt.Sprintf("https://eidas.ec.europa.eu/efda/tl-browser/api/v1/browser/download/%s", c))
			if err != nil {
				fmt.Println(err)
				return
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if err != nil {
				fmt.Println(err)
				return
			}
			xmlChan <- body

		}(country)
	}

	go func() {
		wg.Wait()
		close(xmlChan)
	}()
	return xmlChan
}

func parseXML(xmlData []byte) <-chan RawCert {
	certChan := make(chan RawCert)

	go func() {
		defer close(certChan)
		xmlFile := TrustServiceStatusList{}
		err := xml.Unmarshal(xmlData, &xmlFile)
		if err != nil && err != io.EOF {
			fmt.Println(err)
			return
		}
		for _, tsp := range xmlFile.TrustServiceProviders {
			for _, tspService := range tsp.TSPServices {
				if !tspService.ServiceInformation.isValidStatus() {
					continue
				}
				serviceType := tspService.ServiceInformation.getType()
				if serviceType != QSealC {
					continue
				}
				cert := tspService.ServiceInformation.getPemCert()
				if cert == "" {
					continue
				}
				certChan <- RawCert{
					Pem:  cert,
					Type: serviceType,
				}
			}
		}
	}()

	return certChan
}

func parseXMLs(xmlChan <-chan []byte) <-chan RawCert {
	certsChan := make(chan RawCert)
	var wg sync.WaitGroup
	for xml := range xmlChan {
		wg.Add(1)
		go func(x []byte) {
			defer wg.Done()
			for cert := range parseXML(x) {
				certsChan <- cert
			}
		}(xml)
	}

	go func() {
		wg.Wait()
		close(certsChan)
	}()
	return certsChan
}

func parseCerts(certChan <-chan RawCert) <-chan ParsedCert {
	parsedCertChan := make(chan ParsedCert)
	go func() {
		defer close(parsedCertChan)
		for cert := range certChan {
			parsedCert, err := parseCert(cert)
			if err != nil {
				fmt.Println(err)
				continue
			}
			parsedCertChan <- parsedCert
		}
	}()
	return parsedCertChan
}

func setupDb() (*mongo.Client, error) {
	// mongoURI := os.Getenv("MONGO_URL")
	mongoURI := "mongodb://localhost:27017"
	if mongoURI == "" {
		return nil, errors.New("MONGO_URL is not set")
	}
	clientOptions := options.Client().ApplyURI(mongoURI)

	client, err := mongo.Connect(nil, clientOptions)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	err = client.Ping(nil, nil)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return client, nil
}

func main() {
	db, err := setupDb()
	if err != nil {
		panic(err)
	}
	now := time.Now()
	nowStr := now.Format(time.RFC3339)
	fmt.Println(nowStr)
	httpClient := &http.Client{}
	xmlChan := loadXMLs(httpClient)
	certsChan := parseXMLs(xmlChan)
	parsedCertsChan := parseCerts(certsChan)
	for cert := range parsedCertsChan {
		// write to db
		db.Database("tpp-verifier").Collection("certs").InsertOne(nil, cert)
	}
}
