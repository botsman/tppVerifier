package verify

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

var pemData, _ = pem.Decode([]byte(certContent))
var x509Cert, _ = x509.ParseCertificate(pemData.Bytes)

func TestParseCert_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)

	parsedCert, err := parseCert(c, []byte(certContent))
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	t.Log(parsedCert)

	certContentNoPaddings := strings.Replace(certContent, "-----BEGIN CERTIFICATE-----", "", 1)
	certContentNoPaddings = strings.Replace(certContentNoPaddings, "-----END CERTIFICATE-----", "", 1)
	certContentNoPaddings = strings.ReplaceAll(certContentNoPaddings, "\n", "")
	parsedCert, err = parseCert(c, []byte(certContent))
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	t.Log(parsedCert)
}

func TestGetCertOBScopes_Success(t *testing.T) {
	scopes, err := getCertOBScopes(x509Cert)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	t.Log(scopes)
	if len(scopes) == 0 {
		t.Errorf("Expected at least one scope, got none")
	}
}

func TestGetCertNCA_Success(t *testing.T) {
	nca, err := getCertNCA(x509Cert)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	t.Log(nca)
	if len(nca.Country) == 0 {
		t.Errorf("Expected NCA, got none")
	}
}

func TestGetCertUsage_Success(t *testing.T) {
	usage := getCertUsage(x509Cert)
	t.Log(usage)
	if usage == "" || usage == UNKNOWN {
		t.Errorf("Expected usage, got none")
	}
}

func TestGetSha256_Success(t *testing.T) {
	sha256 := getSha256(x509Cert)
	t.Log(sha256)
	if sha256 == "" {
		t.Errorf("Expected sha256, got none")
	}
}


func TestFormatCertContent_Success(t *testing.T) {
	certPrefix := "-----BEGIN CERTIFICATE-----"
	certSuffix := "-----END CERTIFICATE-----"
	formattedContent, err := formatCertContent([]byte(certContent))
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if certContent != string(formattedContent) {
		t.Errorf("Expected %v, got %v", certContent, string(formattedContent))
	}
	certContentString, _ := strings.CutPrefix(certContent, certPrefix)
	formattedContent, err = formatCertContent([]byte(certContentString))
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if certContent != string(formattedContent) {
		t.Errorf("Expected %v, got %v", certContent, string(formattedContent))
	}
	certContentString, _ = strings.CutSuffix(certContentString, certSuffix)
	formattedContent, err = formatCertContent([]byte(certContentString))
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if certContent != string(formattedContent) {
		t.Errorf("Expected %v, got %v", certContent, string(formattedContent))
	}
	certContentString = strings.ReplaceAll(certContentString, "\n", "")
	if certContent != string(formattedContent) {
		t.Errorf("Expected %v, got %v", certContent, string(formattedContent))
	}
}
