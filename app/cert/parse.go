package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/botsman/tppVerifier/app/models"
	"github.com/fullsailor/pkcs7"
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
	Cert      *x509.Certificate `json:"-"` // not serialized
	Registers []models.Register `bson:"registers" json:"registers"`
	CreatedAt time.Time         `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time         `bson:"updated_at" json:"updated_at"`
	IsActive  bool              `bson:"is_active" json:"is_active"`
	Position  models.Position   `bson:"position" json:"position"`
}

type certFormat string

const (
	CertFormatPEM    certFormat = "PEM"
	CertFormatRawPEM certFormat = "RawPEM" // PEM without headers
	CertFormatDER    certFormat = "DER"
	CertFormatPKCS7  certFormat = "PKCS7"
)

func GetCertFormat(crtContent []byte) (certFormat, error) {
	if len(crtContent) == 0 {
		return "", errors.New("certificate content is empty")
	}
	block, _ := pem.Decode(crtContent)
	if block != nil {
		if block.Type != "CERTIFICATE" {
			return "", errors.New("invalid PEM block type, expected CERTIFICATE")
		}
		return CertFormatPEM, nil
	}
	if _, err := base64.StdEncoding.DecodeString(string(crtContent)); err == nil {
		return CertFormatRawPEM, nil
	}
	if _, err := x509.ParseCertificate(crtContent); err == nil {
		return CertFormatDER, nil
	}
	if _, err := pkcs7.Parse(crtContent); err == nil {
		return CertFormatPKCS7, nil
	}
	return "", errors.New("unknown certificate format")

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
		"is_active":     c.IsActive,
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
	if arr, ok := raw["registers"].(primitive.A); ok {
		c.Registers = make([]models.Register, len(arr))
		for i, v := range arr {
			// If Register is a string type, convert directly
			if s, ok := v.(string); ok {
				c.Registers[i] = models.Register(s)
			} else {
				return errors.New("invalid register type in BSON")
			}
		}
	}
	c.CreatedAt = raw["created_at"].(primitive.DateTime).Time()
	c.UpdatedAt = raw["updated_at"].(primitive.DateTime).Time()
	// c.IsActive = raw["is_active"].(bool)
	if posStr, ok := raw["position"].(string); ok {
		c.Position = models.Position(posStr)
	} else {
		return errors.New("invalid position type in BSON")
	}

	pemData := raw["pem"].(primitive.Binary).Data
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
	for _, name := range c.Cert.Subject.Names {
		if name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 97}) {
			return name.Value.(string)
		}
	}
	return ""
}

func ParseCerts(data []byte) ([]*ParsedCert, error) {
	if len(data) == 0 {
		return nil, errors.New("no data provided")
	}
	certFormat, err := GetCertFormat(data)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	switch certFormat {
	case CertFormatPEM:
		certs, err = parsePEMCerts(data)
		if err != nil {
			return nil, err
		}
	case CertFormatRawPEM:
		certs, err = parseRawPEMCerts(data) // treat raw PEM as PEM without headers
		if err != nil {
			return nil, err
		}
	case CertFormatDER:
		certs, err = parseDERCerts(data)
		if err != nil {
			return nil, err
		}
	case CertFormatPKCS7:
		certs, err = parsePKCS7Certs(data)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unknown certificate format")
	}
	parsedCerts := []*ParsedCert{}
	for _, cert := range certs {
		parsedCerts = append(parsedCerts, &ParsedCert{
			Cert: cert,
		})
	}
	return parsedCerts, nil
}

func parsePEMCerts(data []byte) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}
	for {
		p, rest := pem.Decode(data)
		if p == nil {
			break // no more PEM blocks
		}
		if p.Type != "CERTIFICATE" {
			return nil, errors.New("invalid PEM block type, expected CERTIFICATE")
		}
		x509Certs, err := x509.ParseCertificates(p.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, x509Certs...)
		data = rest
	}
	if len(certs) == 0 {
		return nil, errors.New("no valid PEM certificates found")
	}
	return certs, nil
}

func parseRawPEMCerts(data []byte) ([]*x509.Certificate, error) {
	derBytes, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("no valid raw PEM certificates found")
	}
	return certs, nil
}

func parseDERCerts(data []byte) ([]*x509.Certificate, error) {
	cert, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, err
	}
	if len(cert) == 0 {
		return nil, errors.New("no valid DER certificates found")
	}
	return cert, nil
}

func parsePKCS7Certs(data []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	if len(p7.Certificates) == 0 {
		return nil, errors.New("no valid PKCS7 certificates found")
	}
	return p7.Certificates, nil
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
