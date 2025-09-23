package tppdb

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
	"slices"
	"strings"
	"time"

	"github.com/botsman/tppVerifier/app/models"
)

type RawTPP struct {
	CA_OwnerID            string
	Code                  string
	Type                  string
	AuthorizedAt          *time.Time
	WithdrawnAt           *time.Time
	NationalReferenceCode string
	Names                 []string
	Country               string
	Services              map[string][]models.Service
}

func (r *RawTPP) GetLatinName() string {
	if len(r.Names) == 1 {
		return r.Names[0]
	}
	if len(r.Names) > 1 {
		// We should check that it contains only Latin characters
		// But keep it simple for now
		return r.Names[1]
	}
	return ""
}

func (r *RawTPP) GetNativeName() string {
	if len(r.Names) == 1 {
		return r.Names[0]
	}
	if len(r.Names) > 1 {
		return r.Names[0]
	}
	return ""
}

func (r *RawTPP) toTPP() models.TPP {
	authority := parseAuthority(r.CA_OwnerID, r.Country)
	if authority == "" {
		// log.Printf("Invalid authority for CA_OwnerID %s and Country %s, skipping TPP\n", r.CA_OwnerID, r.Country)
		return models.TPP{}
	}
	obID, err := parseOBID(r.NationalReferenceCode, r.Country, authority)
	if err != nil {
		// log.Printf("Error parsing OBID for NationalReferenceCode %s, Country %s, Authority %s: %v, skipping TPP\n", r.NationalReferenceCode, r.Country, authority, err)
		return models.TPP{}
	}
	tpp := models.TPP{
		NameLatin:    r.GetLatinName(),
		NameNative:   r.GetNativeName(),
		Id:           r.Code,
		OBID:         obID,
		Authority:    authority,
		Country:      r.Country,
		Services:     r.Services,
		AuthorizedAt: r.AuthorizedAt,
		WithdrawnAt:  r.WithdrawnAt,
		Type:         r.Type,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Registry:     "EBA",
	}

	if len(r.Names) > 1 {
		tpp.NameNative = r.Names[1]
	}

	return tpp
}

func (r *RawTPP) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	CA_OwnerID, ok := raw["CA_OwnerID"].(string)
	if !ok {
		// log.Println("CA_OwnerID is required, skipping this TPP")
		return nil
	}
	r.CA_OwnerID = CA_OwnerID
	code, ok := raw["EntityCode"].(string)
	if !ok {
		return errors.New("EntityCode is required")
	}
	r.Code = code

	entType, ok := raw["EntityType"].(string)
	if !ok {
		// log.Println("Type is required, skipping this TPP")
		return nil
	}
	r.Type = entType
	authorizedAtVal, err := r.findProperty(raw["Properties"], "ENT_AUT")
	if err != nil {
		// log.Println("AuthorizedAt is required, skipping this TPP")
		return nil
	}
	if len(authorizedAtVal) > 0 {
		authorizedAt, withdrawnAt, err := parseAuthorizedAt(authorizedAtVal)
		if err != nil {
			// log.Printf("Error parsing authorized date: %v, skipping this TPP\n", err)
			return nil
		}
		r.AuthorizedAt = authorizedAt
		r.WithdrawnAt = withdrawnAt
	}
	nationalReferenceCode, err := r.findProperty(raw["Properties"], "ENT_NAT_REF_COD")
	if err != nil {
		return err
	}
	r.NationalReferenceCode = nationalReferenceCode[0]
	names, err := r.findProperty(raw["Properties"], "ENT_NAM")
	if err != nil {
		return err
	}
	r.Names = names
	country, err := r.findProperty(raw["Properties"], "ENT_COU_RES")
	if err != nil {
		return err
	}
	r.Country = country[0]
	services, err := r.parseServices(raw["Services"])
	if err != nil {
		return err
	}
	r.Services = services
	return nil
}

func parseAuthorizedAt(vals []string) (*time.Time, *time.Time, error) {
	switch len(vals) {
	case 0:
		return nil, nil, errors.New("no authorized date found")
	case 1:
		authorizedAt, err := time.Parse(time.DateOnly, vals[0])
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing authorized date: %w", err)
		}
		return &authorizedAt, nil, nil
	default:
		// Even is authorizedAt, odd is withdrawnAt
		// Pick the last one as it is the latest date
		isEven := len(vals)%2 == 0
		var authorizedAtIdx int
		var withdrawnAtIdx int
		if isEven {
			authorizedAtIdx = len(vals) - 2
			withdrawnAtIdx = len(vals) - 1
		} else {
			authorizedAtIdx = len(vals) - 1
			withdrawnAtIdx = len(vals) - 2
		}
		var err error
		authorizedAt, err := time.Parse(time.DateOnly, vals[authorizedAtIdx])
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing authorized date: %w", err)
		}
		withdrawnAt, err := time.Parse(time.DateOnly, vals[withdrawnAtIdx])
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing revoked date: %w", err)
		}
		return &authorizedAt, &withdrawnAt, nil
	}
}

func serviceFromString(str string) (models.Service, error) {
	switch str {
	case "PS_080":
		return models.AISP, nil
	case "PS_070":
		return models.PISP, nil
	}
	return "", fmt.Errorf("unknown service: %s", str)
}

func parseOBID(entityNatRefCode string, country string, authority string) (string, error) {
	// TPP Open banking ID is expected to be in the format: PSD{country}-{authority}-{id}
	// Eg. PSDFI-FINFSA-0111027-9
	// Id may or may not contain a dash at the end. For simplicity it will be removed
	natRefCode := strings.ReplaceAll(entityNatRefCode, "-", "")
	natRefCode = strings.ReplaceAll(natRefCode, " ", "")
	return fmt.Sprintf("PSD%s-%s-%s", country, authority, natRefCode), nil
}

func parseAuthority(authority string, country string) string {
	// authority is expected to be in the format: {country}-{authority}
	// Eg. "FI_FIN-FSA"
	// The dash is removed if it exists
	parts := strings.Split(authority, "_")
	if len(parts) != 2 {
		return ""
	}
	if parts[0] != country {
		return ""
	}
	res := parts[1]
	res = strings.ReplaceAll(res, "-", "")
	return res
}

func parseCountry(properties []interface{}) string {
	for _, prop := range properties {
		if propMap, ok := prop.(map[string]interface{}); ok {
			if country, ok := propMap["ENT_COU_RES"].(string); ok {
				return country
			}
		}
	}
	return ""
}

func (r *RawTPP) parseServices(servicesData any) (map[string][]models.Service, error) {
	// Services are represented aither as []map[string]string or as []map[string][]string
	// depending if the country has multiple services or not
	res := make(map[string][]models.Service)
	if servicesData == nil {
		return res, nil
	}
	for _, countryServices := range servicesData.([]any) {
		for country, services := range countryServices.(map[string]interface{}) {
			// service may be either a string or an array of strings
			switch service := services.(type) {
			case string:
				s, err := serviceFromString(service)
				if err != nil {
					continue
				}
				res[country] = append(res[country], s)
			case []interface{}:
				for _, service := range service {
					s, err := serviceFromString(service.(string))
					if err != nil {
						continue
					}
					res[country] = append(res[country], s)
				}
			}
		}
	}
	return res, nil
}

func (r *RawTPP) findProperty(properties any, key string) ([]string, error) {
	if props, ok := properties.([]any); ok {
		for _, prop := range props {
			if propMap, ok := prop.(map[string]any); ok {
				if value, ok := propMap[key].(string); ok {
					return []string{value}, nil
				} else if values, ok := propMap[key].([]any); ok {
					strValues := make([]string, len(values))
					for i, v := range values {
						if str, ok := v.(string); ok {
							strValues[i] = str
						} else {
							return nil, fmt.Errorf("expected string value for %s", key)
						}
					}
					return strValues, nil
				}
			}
		}
		return nil, fmt.Errorf("property %s not found", key)
	}
	return nil, fmt.Errorf("properties is not a valid format")
}

const RegisterJsonName = "eba_register.json"

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

func deleteRegistry() error {
	err := os.Remove(RegisterJsonName)
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
		var registry [][]RawTPP
		err = json.Unmarshal(file, &registry)
		if err != nil {
			log.Fatal(err)
		}
		for _, tpps := range registry {
			for _, rawTpp := range tpps {
				if rawTpp.CA_OwnerID == "" || rawTpp.Code == "" {
					// log.Printf("Skipping TPP with missing CA_OwnerID or Code: %+v\n", rawTpp)
					continue
				}
				if rawTpp.Type == "" {
					// log.Printf("Skipping TPP with missing Type: %+v\n", rawTpp)
					continue
				}
				if rawTpp.AuthorizedAt == nil || rawTpp.AuthorizedAt.IsZero() {
					// log.Printf("Skipping TPP with missing AuthorizedAt: %+v\n", rawTpp)
					continue
				}
				if !slices.Contains([]string{"PSD_AISP", "PSD_PI", "PSD_EMI"}, rawTpp.Type) {
					continue
				}
				res <- rawTpp.toTPP()
			}
		}
		close(res)
	}()
	return res, nil
}

func saveTPPs(dbImpl db, out <-chan models.TPP) error {
	batchSize := 1000
	batch := make([]models.TPP, 0, batchSize)
	idx := 0
	for tpp := range out {
		idx += 1
		batch = append(batch, tpp)
		if idx == batchSize {
			err := dbImpl.SaveTPPs(context.TODO(), "tpps", batch)
			if err != nil {
				return err
			}
			batch = make([]models.TPP, 0, batchSize)
			idx = 0
		}
	}
	if len(batch) > 0 {
		err := dbImpl.SaveTPPs(context.TODO(), "tpps", batch)
		if err != nil {
			return err
		}
	}
	return nil
}
