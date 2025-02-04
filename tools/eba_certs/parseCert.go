package ebacerts

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"
)

type ParsedCert struct {
	Pem          string
	SerialNumber string
	Sha256       string
	// Links        []string
	Registers    []Register
	NotBefore    time.Time
	NotAfter     time.Time
	Type         CertType // types?
	Scopes       []Scope
	Order        int
	RootSha256   string
	// CRLs		 []string ??
}

const certPrefix = "-----BEGIN CERTIFICATE-----"
const certSuffix = "-----END CERTIFICATE-----"


func parseCert(cert RawCert) (ParsedCert, error) {
	var certPem = cert.Pem
	formattedCert := fmt.Sprintf("%s\n%s\n%s", certPrefix, certPem, certSuffix)
	var block, _ = pem.Decode([]byte(formattedCert))
	if block == nil {
		return ParsedCert{}, fmt.Errorf("failed to parse certificate")
	}
	x509Cert, err := x509.ParseCertificate([]byte(block.Bytes))
	if err != nil {
		return ParsedCert{}, err
	}

	return ParsedCert{
		Pem:          cert.Pem,
		SerialNumber: x509Cert.SerialNumber.String(),
		Sha256:       getSha256(x509Cert),
		// Links:        x509Cert.IssuingCertificateURL,
		Registers:    []Register{EBA},
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		Type:         cert.Type,
		Order:        0, // Trusted certificates have order 0
	}, nil
}

func getSha256(cert *x509.Certificate) string {
	checksum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(checksum[:])
}
