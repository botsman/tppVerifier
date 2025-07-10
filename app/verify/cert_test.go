package verify

// import (
// 	"crypto/x509"
// 	"encoding/pem"
// 	// "os"
// 	"strings"
// 	"testing"

// 	"github.com/gin-gonic/gin"
// )

// var pemData, _ = pem.Decode([]byte(certContent))
// var x509Cert, _ = x509.ParseCertificate(pemData.Bytes)

// func TestParseCert_Success(t *testing.T) {
// 	gin.SetMode(gin.TestMode)
// 	c, _ := gin.CreateTestContext(nil)

// 	parsedCert, err := parseCert(c, []byte(certContent))
// 	if err != nil {
// 		t.Errorf("Expected no error, got %v", err)
// 	}
// 	t.Log(parsedCert)

// 	certContentNoPaddings := strings.Replace(certContent, "-----BEGIN CERTIFICATE-----", "", 1)
// 	certContentNoPaddings = strings.Replace(certContentNoPaddings, "-----END CERTIFICATE-----", "", 1)
// 	certContentNoPaddings = strings.ReplaceAll(certContentNoPaddings, "\n", "")
// 	parsedCert, err = parseCert(c, []byte(certContent))
// 	if err != nil {
// 		t.Errorf("Expected no error, got %v", err)
// 	}
// 	t.Log(parsedCert)
// }

// func TestGetCertOBScopes_Success(t *testing.T) {
// 	scopes, err := getCertOBScopes(x509Cert)
// 	if err != nil {
// 		t.Errorf("Expected no error, got %v", err)
// 	}
// 	t.Log(scopes)
// 	if len(scopes) == 0 {
// 		t.Errorf("Expected at least one scope, got none")
// 	}
// }

// func TestGetCertNCA_Success(t *testing.T) {
// 	nca, err := getCertNCA(x509Cert)
// 	if err != nil {
// 		t.Errorf("Expected no error, got %v", err)
// 	}
// 	t.Log(nca)
// 	if len(nca.Country) == 0 {
// 		t.Errorf("Expected NCA, got none")
// 	}
// }

// func TestGetCertUsage_Success(t *testing.T) {
// 	usage := getCertUsage(x509Cert)
// 	t.Log(usage)
// 	if usage == "" || usage == UNKNOWN {
// 		t.Errorf("Expected usage, got none")
// 	}
// }

// func TestGetSha256_Success(t *testing.T) {
// 	sha256 := getSha256(x509Cert)
// 	t.Log(sha256)
// 	if sha256 == "" {
// 		t.Errorf("Expected sha256, got none")
// 	}
// }


// func TestFormatCertContent_Success(t *testing.T) {
// 	certPrefix := "-----BEGIN CERTIFICATE-----"
// 	certSuffix := "-----END CERTIFICATE-----"
// 	formattedContent, err := formatCertContent([]byte(certContent))
// 	if err != nil {
// 		t.Errorf("Expected no error, got %v", err)
// 	}
// 	if certContent != string(formattedContent) {
// 		t.Errorf("Expected %v, got %v", certContent, string(formattedContent))
// 	}
// 	certContentString, _ := strings.CutPrefix(certContent, certPrefix)
// 	formattedContent, err = formatCertContent([]byte(certContentString))
// 	if err != nil {
// 		t.Errorf("Expected no error, got %v", err)
// 	}
// 	if certContent != string(formattedContent) {
// 		t.Errorf("Expected %v, got %v", certContent, string(formattedContent))
// 	}
// 	certContentString, _ = strings.CutSuffix(certContentString, certSuffix)
// 	formattedContent, err = formatCertContent([]byte(certContentString))
// 	if err != nil {
// 		t.Errorf("Expected no error, got %v", err)
// 	}
// 	if certContent != string(formattedContent) {
// 		t.Errorf("Expected %v, got %v", certContent, string(formattedContent))
// 	}
// 	certContentString = strings.ReplaceAll(certContentString, "\n", "")
// 	formattedContent, err = formatCertContent([]byte(certContentString))
// 	if err != nil {
// 		t.Errorf("Expected no error, got %v", err)
// 	}
// 	if certContent != string(formattedContent) {
// 		t.Errorf("Expected %v, got %v", certContent, string(formattedContent))
// 	}
// }


// func Test_loadCertChain(t *testing.T) {
// 	links := []string{
// 		// "http://aia.entrust.net/esqseal1-g4.p7c", // TODO
// 		"http://www.e-szigno.hu/qcpca2012.crt", // der
// 		// "http://aia.entrust.net/esqseal2-chain.p7c", // TODO
// 	}
// 	c, _ := gin.CreateTestContext(nil)
// 	for _, link := range links {
// 		chain, err := loadCertChain(c, link)
// 		if err != nil {
// 			t.Errorf("Expected no error, got %v", err)
// 		}
// 		if len(chain) == 0 {
// 			t.Errorf("Expected non-empty certificate chain, got none")
// 		}
// 	}
// }

// // func Test_loadP7CCerts(t *testing.T) {
// // 	c, _ := gin.CreateTestContext(nil)

// // 	p7cPath := "../../testdata/esqseal1-g4.p7c"

// // 	body, err := os.Open(p7cPath)
// // 	if err != nil {
// // 		t.Errorf("Expected no error, got %v", err)
// // 	}
// // 	defer body.Close()

// // 	certs, err := loadP7CCerts(c, body)
// // 	if err != nil {
// // 		t.Errorf("Expected no error, got %v", err)
// // 	}
// // 	if len(certs) == 0 {
// // 		t.Errorf("Expected non-empty certificate list, got none")
// // 	}
// // }
