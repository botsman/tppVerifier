package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson"
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

type TPP struct {
	NameLatin    string               `bson:"name_latin"`
	NameNative   string               `bson:"name_native"`
	Id           string               `bson:"id"`
	OBID         string               `bson:"ob_id"`
	Authority    string               `bson:"authority"`
	Country      string               `bson:"country"`
	Services     map[string][]Service `bson:"services"`
	AuthorizedAt *time.Time           `bson:"authorized_at"`
	WithdrawnAt  *time.Time           `bson:"withdrawn_at"`
	Type         string               `bson:"type"`
	CreatedAt    time.Time            `bson:"created_at"`
	UpdatedAt    time.Time            `bson:"updated_at"`
	Registry     string               `bson:"registry"`
	IsActive     bool                 `bson:"is_active"`
}

func (t *TPP) ToBSON() (bson.M, error) {
	tppBson := bson.M{
		"name_latin":    t.NameLatin,
		"name_native":   t.NameNative,
		"id":            t.Id,
		"ob_id":         t.OBID,
		"authority":     t.Authority,
		"country":       t.Country,
		"services":      t.Services,
		"authorized_at": t.AuthorizedAt,
		"withdrawn_at":  t.WithdrawnAt,
		"type":          t.Type,
		"updated_at":    t.UpdatedAt,
		"registry":      t.Registry,
	}
	return tppBson, nil
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
