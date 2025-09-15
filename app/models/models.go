package models

import (
	"time"
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
}

type Register string

const (
	EBA Register = "EBA"
)

type Position string

const (
	PositionRoot         Position = "Root"
	PositionIntermediate Position = "Intermediate"
	PositionLeaf         Position = "Leaf"
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

type CertificateResponse struct {
	Expired      bool           `json:"expired"`
	Scopes       []Scope        `json:"scopes"`
	SerialNumber string         `json:"serial_number"`
	Issuer       map[string]any `json:"issuer"`
	Subject      map[string]any `json:"subject"`
	NotBefore    string         `json:"not_before"`
	NotAfter     string         `json:"not_after"`
	Usage        CertUsage      `json:"usage"`
}

type TppResponse struct {
	Id         string               `json:"id"`
	NameLatin  string               `json:"name_latin"`
	NameNative string               `json:"name_native"`
	Authority  string               `json:"authority"`
	Services   map[string][]Service `json:"services"`
	Country    string               `json:"country,omitempty"`
}
