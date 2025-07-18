package models

import (
	"encoding/json"
	"fmt"
	"time"
	"unicode"

	"go.mongodb.org/mongo-driver/bson"
)

type Service string

const (
	AISP Service = "AISP"
	PISP Service = "PISP"
	// CBPII Service = "CBPII"
)

func serviceFromString(str string) (Service, error) {
	switch str {
	case "PS_080":
		return AISP, nil
	case "PS_070":
		return PISP, nil
	}
	return "", fmt.Errorf("unknown service: %s", str)
}

type TPP struct {
	NameLatin    string               `bson:"name_latin"`
	NameNative   string               `bson:"name_native"`
	Id           string               `bson:"id"`
	Authority    string               `bson:"authority"`
	Services     map[string][]Service `bson:"services"`
	AuthorizedAt time.Time            `bson:"authorized_at"`
	WithdrawnAt  time.Time            `bson:"withdrawn_at"`
	Type         string               `bson:"type"`
	CreatedAt    time.Time            `bson:"created_at"`
	UpdatedAt    time.Time            `bson:"updated_at"`
	Registry     string               `bson:"registry"`
}

func (t *TPP) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	id, ok := raw["EntityCode"].(string)
	if !ok {
		return nil
	}
	t.Id = id
	t.Authority = raw["CA_OwnerID"].(string) // TODO: remove country prefix
	entityType, ok := raw["EntityType"].(string)
	if !ok {
		return nil
	}
	t.Type = entityType
	properties, ok := raw["Properties"].([]interface{})
	if !ok {
		return nil
	}
	for _, prop := range properties {
		for k, v := range prop.(map[string]interface{}) {
			switch k {
			// "ENT_NAM" may be either a string or an array of strings
			case "ENT_NAM":
				switch v := v.(type) {
				case string:
					t.NameNative = v
					t.NameLatin = v
				case []interface{}:
					for _, v := range v {
						name := v.(string)
						// assume that checking only the first character is enough
						if unicode.Is(unicode.Latin, rune(name[0])) {
							t.NameLatin = name
						} else {
							t.NameNative = name
						}
					}

				}
			case "ENT_AUT":
				entAut, ok := v.([]interface{})
				if !ok {
					return nil
				}

				parseDate := func(value interface{}) (time.Time, bool) {
					str, ok := value.(string)
					if !ok {
						return time.Time{}, false
					}

					formats := []string{
						time.RFC3339,
						"2006-01-02",
						"2006-01-02T15:04:05",
						"2006-01-02 15:04:05",
					}

					for _, format := range formats {
						if parsedTime, err := time.Parse(format, str); err == nil {
							return parsedTime, true
						}
					}

					return time.Time{}, false
				}

				switch len(entAut) {
				case 1:
					if parsedTime, ok := parseDate(entAut[0]); ok {
						t.AuthorizedAt = parsedTime
					}
				case 2:
					if parsedTime, ok := parseDate(entAut[0]); ok {
						t.AuthorizedAt = parsedTime
					}
					if parsedTime, ok := parseDate(entAut[1]); ok {
						t.WithdrawnAt = parsedTime
					}
				}
			}
		}

	}
	t.Services = make(map[string][]Service)
	services, ok := raw["Services"].([]interface{})
	if !ok {
		return nil
	}
	for _, countryServices := range services {
		for country, services := range countryServices.(map[string]interface{}) {
			// service may be either a string or an array of strings
			switch service := services.(type) {
			case string:
				s, err := serviceFromString(service)
				if err != nil {
					continue
				}
				t.Services[country] = append(t.Services[country], s)
			case []interface{}:
				for _, service := range service {
					s, err := serviceFromString(service.(string))
					if err != nil {
						continue
					}
					t.Services[country] = append(t.Services[country], s)
				}
			}
		}
	}
	t.Registry = "EBA"
	return nil
}

type Register string

const (
	EBA Register = "EBA"
)

type CertType string

const (
	QWAC   CertType = "QWAC"
	QSealC CertType = "QSealC"
)

type Position string

const (
	Root         Position = "Root"
	Intermediate Position = "Intermediate"
	Leaf         Position = "Leaf"
)

type Scope string

const (
	AIS Scope = "AIS"
	PIS Scope = "PIS"
)

type ParsedCert struct {
	Pem          string
	SerialNumber string
	Sha256       string
	Links        []string
	Registers    []Register
	NotBefore    time.Time
	NotAfter     time.Time
	Type         CertType // types?
	Position     Position
	Scopes       []Scope
	RootSha256   *string `bson:"root_sha256,omitempty"` // sha256 of the root certificate, if this is an intermediate or leaf certificate
	// CRLs		 []string ??
	CreatedAt time.Time `bson:"created_at"`
	UpdatedAt time.Time `bson:"updated_at"`
	IsActive  bool      `bson:"is_active"`
}

func (c ParsedCert) ToBson(now time.Time) (bson.M, error) {
	res := bson.M{
		"pem":           c.Pem,
		"serial_number": c.SerialNumber,
		"sha256":        c.Sha256,
		"registers":     c.Registers,
		"not_before":    c.NotBefore,
		"not_after":     c.NotAfter,
		"type":          c.Type,
		"position":      c.Position,
		"updated_at":    now,
		"is_active":     true,
	}
	if c.Links != nil {
		res["links"] = c.Links
	}
	if c.RootSha256 != nil {
		res["root_sha256"] = *c.RootSha256
	}
	if c.Scopes != nil {
		res["scopes"] = c.Scopes
	}
	return res, nil
}
