package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/botsman/tppVerifier/app/models"
)

type PSD2QcType struct {
	RolesOfPSP []Role
	NCAName    string
	NCAId      string
}

type Role struct {
	OID   asn1.ObjectIdentifier
	Value models.ObRole
}

type QCStatement struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"optional"`
}

type NCA struct {
	Country string
	Name    string
	Id      string
}

type ParsedCert struct {
	Cert      *x509.Certificate `json:"-"`
	Registers []models.Register
	CreatedAt time.Time
	UpdatedAt time.Time
	IsActive  bool
	Position  models.Position
}

func (c *ParsedCert) ToBson() (bson.M, error) {
	if c.Cert == nil {
		return nil, errors.New("certificate is nil")
	}
	rawCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
	if rawCertPem == nil {
		return nil, errors.New("error encoding certificate to PEM format")
	}
	res := bson.M{
		"pem":           rawCertPem,
		"serial_number": c.Cert.SerialNumber.String(),
		"sha256":        c.Sha256(),
		"registers":     c.Registers,
		"not_before":    c.Cert.NotBefore,
		"not_after":     c.Cert.NotAfter,
		"updated_at":    c.UpdatedAt,
		"position":      c.Position,
	}
	nca, err := c.NCA()
	if err != nil {
		return nil, err
	}
	if nca != nil {
		res["nca"] = bson.M{
			"country": nca.Country,
			"name":    nca.Name,
			"id":      nca.Id,
		}
	}
	scopes, err := c.OBScopes()
	if err != nil {
		return nil, err
	}
	if scopes != nil {
		res["scopes"] = scopes
	}
	if c.Position == models.Leaf {
		res["usage"] = c.Usage()
	}
	return res, nil
}

func (c *ParsedCert) UnmarshalBSON(data []byte) error {
	var raw bson.M
	if err := bson.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.Registers = raw["registers"].([]models.Register)
	c.CreatedAt = raw["created_at"].(time.Time)
	c.UpdatedAt = raw["updated_at"].(time.Time)
	c.IsActive = raw["is_active"].(bool)
	c.Position = raw["position"].(models.Position)

	pemData := raw["pem"].([]byte)
	// ignore rest as we expect only PEM data in the DB
	p, _ := pem.Decode(pemData)
	if p == nil {
		return errors.New("error parsing certificate")
	}
	c.Cert, _ = x509.ParseCertificate(p.Bytes) // ignore error for now
	return nil
}

func (c *ParsedCert) CompanyId() string {
	if c.Cert == nil {
		return ""
	}
	return c.Cert.Subject.SerialNumber
}

func ParseCerts(data []byte) ([]*ParsedCert, error) {
	if len(data) == 0 {
		return nil, errors.New("no data provided")
	}
	certs := []*ParsedCert{}
	for {
		p, rest := pem.Decode(data)
		if p == nil {
			return nil, errors.New("error parsing certificate")
		}
		x509Cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, err
		}
		var cert ParsedCert
		cert.Cert = x509Cert
		certs = append(certs, &cert)
		if len(rest) == 0 {
			break
		}
		data = rest
	}
	return certs, nil
}

func (c *ParsedCert) OBScopes() ([]models.Scope, error) {
	roleToScope := func(role models.ObRole) models.Scope {
		switch role {
		case "PSP_PI":
			return models.ScopePIS
		case "PSP_AI":
			return models.ScopeAIS
		default:
			return models.ScopeUnknown
		}
	}
	for _, ext := range c.Cert.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}) {
			continue
		}
		var qcStatements []QCStatement
		_, err := asn1.Unmarshal(ext.Value, &qcStatements)
		if err != nil {
			return nil, err
		}

		for _, stmt := range qcStatements {
			switch {
			// case stmt.ID.Equal(asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}):
			// 	var urlStructs []URLStruct
			// 	_, err := asn1.Unmarshal(stmt.Value.FullBytes, &urlStructs)
			// 	if err != nil {
			// 		fmt.Println(err)
			// 	}
			// 	for _, urlStruct := range urlStructs {
			// 		fmt.Println(urlStruct.URL, urlStruct.Lang)
			// 	}
			case stmt.ID.Equal(asn1.ObjectIdentifier{0, 4, 0, 19495, 2}):
				var psd2 PSD2QcType
				_, err := asn1.Unmarshal(stmt.Value.FullBytes, &psd2)
				if err != nil {
					return nil, err
				}
				roles := make([]models.Scope, 0)
				for _, role := range psd2.RolesOfPSP {
					roles = append(roles, roleToScope(role.Value))
				}
				return roles, nil
			}
		}
	}
	return nil, nil
}

func (c *ParsedCert) Usage() models.CertUsage {
	// Maybe this should be identified based on certificate policy
	switch c.Cert.KeyUsage {
	case x509.KeyUsageKeyEncipherment:
		return models.QWAC
	case x509.KeyUsageContentCommitment:
		return models.QSEAL
	default:
		// perhaps identify based on the extended key usage or certificate policy
		log.Printf("Unknown certificate usage: %v", c.Cert.KeyUsage)
		return models.UNKNOWN
	}
}

func (c *ParsedCert) Sha256() string {
	checksum := sha256.Sum256(c.Cert.Raw)
	return hex.EncodeToString(checksum[:])
}

func (c *ParsedCert) NCA() (*NCA, error) {
	for _, ext := range c.Cert.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}) {
			continue
		}
		var qcStatements []QCStatement
		_, err := asn1.Unmarshal(ext.Value, &qcStatements)
		if err != nil {
			return nil, err
		}

		for _, stmt := range qcStatements {
			switch {
			// case stmt.ID.Equal(asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}):
			// 	var urlStructs []URLStruct
			// 	_, err := asn1.Unmarshal(stmt.Value.FullBytes, &urlStructs)
			// 	if err != nil {
			// 		fmt.Println(err)
			// 	}
			// 	for _, urlStruct := range urlStructs {
			// 		fmt.Println(urlStruct.URL, urlStruct.Lang)
			// 	}
			case stmt.ID.Equal(asn1.ObjectIdentifier{0, 4, 0, 19495, 2}):
				var psd2 PSD2QcType
				_, err := asn1.Unmarshal(stmt.Value.FullBytes, &psd2)
				if err != nil {
					return nil, err
				}
				country := psd2.NCAId[:2]
				return &NCA{Country: country, Name: psd2.NCAName, Id: psd2.NCAId}, nil
			}
		}
	}
	return nil, nil
}
