package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/botsman/tppVerifier/app/cert"
	"github.com/botsman/tppVerifier/app/models"
)

func parseCert(crt RawCert) (models.ParsedCert, error) {
	var certPem = crt.Pem
	formattedCert, err := cert.FormatCertContent([]byte(certPem))
	if err != nil {
		return models.ParsedCert{}, err
	}
	var block, _ = pem.Decode(formattedCert)
	if block == nil {
		return models.ParsedCert{}, fmt.Errorf("failed to parse certificate")
	}
	x509Cert, err := x509.ParseCertificate([]byte(block.Bytes))
	if err != nil {
		return models.ParsedCert{}, err
	}

	return models.ParsedCert{
		Pem:          crt.Pem,
		SerialNumber: x509Cert.SerialNumber.String(),
		Sha256:       cert.GetSha256(x509Cert),
		Registers:    []models.Register{models.EBA},
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		Type:         crt.Type,
		Position:     models.Root,
	}, nil
}
