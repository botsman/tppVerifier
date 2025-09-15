package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/botsman/tppVerifier/app/cert"
	"github.com/botsman/tppVerifier/app/models"
)

type RawCert struct {
	Pem  string
	Type models.CertUsage
}

func getEEACountries() []string {
	return []string{
		"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IS", "IE", "IT", "LV", "LI", "LT", "LU", "MT", "NL", "NO", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
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
				if serviceType == "" {
					continue
				}
				crt := tspService.ServiceInformation.getPemCert()
				if crt == "" {
					continue
				}
				certChan <- RawCert{
					Pem:  crt,
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
			for crt := range parseXML(x) {
				certsChan <- crt
			}
		}(xml)
	}
	go func() {
		wg.Wait()
		close(certsChan)
	}()
	return certsChan
}

func parseCerts(certChan <-chan RawCert, now time.Time) <-chan *cert.ParsedCert {
	parsedCertChan := make(chan *cert.ParsedCert)
	go func() {
		defer close(parsedCertChan)
		for crt := range certChan {
			parsedCerts, err := cert.ParseCerts([]byte(crt.Pem))
			if err != nil {
				fmt.Println(err)
				continue
			}
			for _, parsedCert := range parsedCerts {
				parsedCert.UpdatedAt = now
				parsedCert.IsActive = true
				parsedCert.Position = models.PositionRoot
				parsedCert.Registers = []models.Register{models.EBA}
				parsedCertChan <- parsedCert
			}
		}
	}()
	return parsedCertChan
}
