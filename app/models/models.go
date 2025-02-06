package models

import (
	"encoding/json"
	"fmt"
	"time"
	"unicode"
)


type Service string

const (
	AIS Service = "AISP"
	PIS Service = "PISP"
	// CBPII Service = "CBPII"
)

func serviceFromString(str string) (Service, error) {
	switch str {
	case "PS_080":
		return AIS, nil
	case "PS_070":
		return PIS, nil
	}
	return "", fmt.Errorf("unknown service: %s", str)
}


type TPP struct {
	NameLatin    string               `bson:"name_latin"`
	NameNative   string               `bson:"name_native"`
	Id           string               `bson:"id"`
	Authority    string               `bson:"authority"`
	Services     map[string][]Service `bson:"services"`
	AuthorizedAt string               `bson:"authorized_at"`
	WithdrawnAt  string               `bson:"withdrawn_at"`
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
				switch len(entAut) {
				case 1:
					t.AuthorizedAt = entAut[0].(string)
				case 2:
					t.AuthorizedAt = entAut[0].(string)
					t.WithdrawnAt = entAut[1].(string)
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
