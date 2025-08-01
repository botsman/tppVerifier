package models

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
)

type CertUsage string

const (
	QWAC    CertUsage = "QWAC"
	QSEAL   CertUsage = "QSEAL"
	UNKNOWN CertUsage = "UNKNOWN"
)

type Service string

const (
	AISP Service = "AIS"
	PISP Service = "PIS"
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
	OBID         string               `bson:"ob_id"`
	Authority    string               `bson:"authority"`
	Country      string               `bson:"country"`
	Services     map[string][]Service `bson:"services"`
	AuthorizedAt time.Time            `bson:"authorized_at"`
	WithdrawnAt  *time.Time           `bson:"withdrawn_at"`
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
	entityType, ok := raw["EntityType"].(string)
	if !ok {
		return nil
	}
	t.Type = entityType
	if !slices.Contains([]string{"PSD_AISP", "PSD_PI", "PSD_EMI"}, t.Type) {
		return nil
	}
	countries, err := findProperty(raw["Properties"], "ENT_COU_RES")
	if err != nil {
		return err
	}
	if len(countries) != 1 {
		return fmt.Errorf("country not found in TPP data")
	}
	t.Country = countries[0]
	authority := parseAuthority(raw["CA_OwnerID"].(string), t.Country)
	if authority == "" {
		return fmt.Errorf("authority not found in TPP data for country %s", t.Country)
	}
	t.Authority = authority
	entityNatRefCodes, err := findProperty(raw["Properties"], "ENT_NAT_REF_COD")
	if err != nil {
		return fmt.Errorf("error finding ENT_NAT_REF_COD: %s\n", err)
	}
	if len(entityNatRefCodes) != 1 {
		return fmt.Errorf("entity national reference code not found in TPP data for country %s", t.Country)
	}
	OBID, err := parseOBID(entityNatRefCodes[0], t.Country, authority)
	if err != nil {
		return err
	}
	t.OBID = OBID
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
						t.WithdrawnAt = &parsedTime
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

func findProperty(properties interface{}, key string) ([]string, error) {
	if props, ok := properties.([]interface{}); ok {
		for _, prop := range props {
			if propMap, ok := prop.(map[string]interface{}); ok {
				if value, ok := propMap[key].(string); ok {
					return []string{value}, nil
				} else if values, ok := propMap[key].([]interface{}); ok {
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

func parseOBID(entityNatRefCode string, country string, authority string) (string, error) {
	// TPP Open banking ID is expected to be in the format: PSD{country}-{authority}-{id}
	// Eg. PSDFI-FINFSA-0111027-9
	// Id may or may not contain a dash at the end. For simplicity it will be removed
	natRefCode := strings.ReplaceAll(entityNatRefCode, "-", "")
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

type Register string

const (
	EBA Register = "EBA"
)

type Position string

const (
	Root         Position = "Root"
	Intermediate Position = "Intermediate"
	Leaf         Position = "Leaf"
)

type ObRole string

const (
	PSP_PI ObRole = "PSP_PI"
	PSP_AI ObRole = "PSP_AI"
)

type Scope string

const (
	ScopeAIS     Scope = "AIS"
	ScopePIS     Scope = "PIS"
	ScopeUnknown Scope = "UNKNOWN"
)
