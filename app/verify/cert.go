package verify

import (
	"crypto/x509"

	"github.com/gin-gonic/gin"
)


type parsedCert struct {
	cert        *x509.Certificate
	companyId   string
	isSandbox   bool
	scopes      []string
	parentLinks []string
	crls        []string
	usage       string // qseal/qwac
	serial      string
	sha256      string
}

func parseCert(c *gin.Context, data string) (parsedCert, error) {
	x509Cert, err := x509.ParseCertificate([]byte(data))
	var cert parsedCert
	if err != nil {
		return cert, err
	}
	cert.cert = x509Cert

	return cert, nil
}
