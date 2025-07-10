package verify

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"github.com/botsman/tppVerifier/app/models"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ocsp"
)

const certContent = `-----BEGIN CERTIFICATE-----
MIIJTjCCBzagAwIBAgIBATANBgkqhkiG9w0BAQsFADBdMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBFRl
c3QxDTALBgNVBAsMBFRlc3QxCzAJBgNVBAMMAmNhMB4XDTI1MDIwNDEyNDk1OVoX
DTI2MDIwNDEyNDk1OVowgYYxCzAJBgNVBAYTAkZJMREwDwYDVQQHDAhIRUxTSU5L
STEaMBgGA1UECgwRU29tZSBDb21wYW55IE5hbWUxIDAeBgNVBGEMF1BTREZJTi1G
SU5GU0EtMTIzNDU2Ny04MRMwEQYDVQQDDApkb21haW4uY29tMREwDwYDVQQFEwgx
MjM0NTY3ODCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJMr9uCLTKzo
iY8672oni/lRoKr1HMO5VtB55svOS2QL5TQRlKJbKwYMwuDU1ov+9WMOARYVaZPr
MwwIp/HfhBpnQrpmYcf6QBachZ/EKYRtbmtU8lbnKimqpP8O1nrvDMdyy5R/MLm/
NhQTCaFZM51R4UJ7reb/gx7CR7cdrAHcvpy2Uv3btBQP7Y5aAmOvlspfUT22Z7LH
oCFjwrsGJ/aKwoDS57FO9HAMRJY1zYd0ZsvEzc+tiy2/Rw7GUU4V7tHpAuq1uqiA
ZkUbaMgM6CJ3gc9kdKREhRqx8S1jGp2/BCFP9HhF6Maj4u8+yah8Ma5l60UcHoVE
OU3+eUSJ8b2AKZ99YJmwJ4JpXckQnsoBy9SkMdsJEvSH1rcNW8kR/ow2lR/n2L13
074hLsH/TVrruXR1+KD+wucR+V6+ubT8jQmYO+SloXN7GCRsBYSfOGOahyvtaAZs
muxJOu4cxnoZF2yby7IYpsgVWqfWRvydZXsmcoUZfMwWxHsjqR5h0WUEMP1E70b+
tVUnbrQBJZGToYmxIBp2C5IlSiWbhekDk6hg8nQPoRzKyhq4XgiRYso+Xofce7fj
o0myLsZ7VWfFNyBt/SDavERcMUKb4rHtdKm5m5zdzpYG+3MFw4McnZG1g8DAK+Fm
TALA6cv0XjouTVjCkhVodMrsOCzhZ+HBAgMBAAGjggPtMIID6TAMBgNVHRMBAf8E
AjAAMA4GA1UdDwEB/wQEAwIGQDCCAdEGA1UdIASCAcgwggHEMIIBwAYMKwYBBAGB
qBgCAQFkMIIBrjAkBggrBgEFBQcCARYYaHR0cHM6Ly9leGFtcGxlLmNvbS9xY3Bz
MEYGCCsGAQUFBwICMDoaOFRlc3QgcXVhbGlmaWVkIGNlcnRpZmljYXRlIGZvciBl
bGVjdHJvbmljIHNlYWwgKEJyb256ZSkuMIGlBggrBgEFBQcCAjCBmBqBlVRoZSBw
cm92aWRlciBwcmVzZXJ2ZXMgcmVnaXN0cmF0aW9uIGRhdGEgZm9yIDEwIHllYXJz
IGFmdGVyIHRoZSBleHBpcmF0aW9uIG9mIHRoZSBjZXJ0aWZpY2F0ZS4gVGhlIHN1
YmplY3Qgb2YgdGhlIHRlc3QgY2VydGlmaWNhdGUgaXMgYSBsZWdhbCBwZXJzb24u
MIGVBggrBgEFBQcCAjCBiBqBhVRFU1QgY2VydGlmaWNhdGUgaXNzdWVkIG9ubHkg
Zm9yIHRlc3RpbmcgcHVycG9zZXMuIFRoZSBpc3N1ZXIgaXMgbm90IGxpYWJsZSBm
b3IgYW55IGRhbWFnZXMgYXJpc2luZyBmcm9tIHRoZSB1c2Ugb2YgdGhpcyBjZXJ0
aWZpY2F0ZSEwIwYDVR0RBBwwGqAYBggrBgEFBQcIA6AMDApkb21haW4uY29tMDAG
A1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly90ZXN0LmNvbXBhbnkuaHUvU29tZS5jcmww
ZAYIKwYBBQUHAQEEWDBWMCkGCCsGAQUFBzABhh1odHRwOi8vdGVzdC5jb21wYW55
Lmh1L3Rlc3RjYTApBggrBgEFBQcwAoYdaHR0cDovL3Rlc3QuY29tcGFueS5odS9D
QS5jcnQwgfYGCCsGAQUFBwEDBIHpMIHmMAgGBgQAjkYBATALBgYEAI5GAQMCAQow
UAYGBACORgEFMEYwIQwbaHR0cHM6Ly9leGFtcGxlLmNvbS9xY3BzX2VuEwJlbjAh
DBtodHRwczovL2V4YW1wbGUuY29tL3FjcHNfaHUTAmh1MBMGBgQAjkYBBjAJBgcE
AI5GAQYCMGYGBgQAgZgnAjBcMCYwEQYHBACBmCcBAQwGUFNQX1BJMBEGBwQAgZgn
AQIMBlBTUF9BSRMnRmlubmlzaCBGaW5hbmNpYWwgU3VwZXJ2aXNvcnkgQXV0aG9y
aXR5EwlGSS1GSU5GU0EwHQYDVR0OBBYEFAB1c7GxJnFlzhLDWMSSGXz25qn4MB8G
A1UdIwQYMBaAFMbl8grJ3a0NR6YAZkntS2MwxjDOMA0GCSqGSIb3DQEBCwUAA4IC
AQB64mZza7oWTmfuyHlh+izdijN9nAgAwPj2Xn49N8iVaCUPcdTyEZhRvBnBve1h
7EpX1VPg0NPafObZ6oWsQsuzDoCUkkMflVOfKopa1iQeOZi2OhgnuJP1vrDFjc+Z
SNzOf5WLNkUzCRf1Uyl64D2irU9FhvjAsktZYDuSZxmNKKUL6p3mM/XS4p49mQcU
DORmwdRW05NDw5BRceQlyd1wvJ6ZkIOvyqBPDiPcBbFgpnPC/V7/x5OVdr9m7nBK
94rl10/CEi2VkdPyGyH9QP7c0Eqm7LhUQfZ+vF5au437AcIXi8MqfMtopwmlsQKS
A9Nd1UapKGpFyexKIJN4zbZ3jRV55GSig9KEWI+opkJfKyxaD4wjyUOEmLK1yoPQ
m+aEbRPHlnqTQ39QVfOYQuoeiLWP/E6LwiRKdnIdo49b8qZG12u5iNY/7Qpm5SU8
pU/WakgJGtLYp/zWhDE2ySgVlVOrEt4aCWXDpKFjlx9A0xdRt+Ir0IIf2gEpEImk
pVr1rkfanj6J68lEvY+8+MMk2b/MB8oVlDa20ZG/eMBoHzeH6ZsPIIf+XKe3ElLn
xATrtuTrc1kaX09wMf2RE7A/7ZZzEzVO89u/iRZZVnVFMX4fHG5Jlw0idnsRPitw
yg7QQy0XpA2r/vN/PrCUiZ0leQVwtN+1q6TzcMKaBf+hjQ==
-----END CERTIFICATE-----`

type MockDb struct {
}

func (m *MockDb) GetTpp(ctx context.Context, id string) (*models.TPP, error) {
	switch id {
	case "12345678":
		return &models.TPP{
			Id:         "12345678",
			NameLatin:  "Test TPP",
			NameNative: "Teszt TPP",
			Authority:  "Test Authority",
			Services: map[string][]models.Service{
				"FI": {models.AIS, models.PIS},
			},
			AuthorizedAt: time.Now(),
			WithdrawnAt:  time.Time{},
			Type:         "TPP",
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			Registry:     "Test Registry",
		}, nil
	default:
		return nil, nil // Simulate no TPP found
	}
}

func NewMockDb() *MockDb {
	return &MockDb{}
}

type MockHttpClient struct {
	chainPath string
}

func (m *MockHttpClient) SetChainPath(path string) {
	m.chainPath = path
}

func (m *MockHttpClient) Do(req *http.Request) (*http.Response, error) {
	switch req.URL.String() {
	case "http://test.company.hu/CA.crt":
		projectRoot, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		path := projectRoot + "/../../testdata/chains/1/ca.pem"
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(data)),
		}, nil
	case "http://yourdomain.com/certs/intermediate.crt":
		projectRoot, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		path := projectRoot + "/../../testdata/chains/1/intermediate.pem"
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(data)),
		}, nil
	// OCSP response simulation
	case "http://test.company.hu/testca":
		// certId := "166265749521381119151001480319330331692166129911"
		// serial, ok := new(big.Int).SetString(certId, 10)
		// if !ok {
		// 	return nil, nil // Simulate error in serial number parsing
		// }
		response := m.getMockOCSPResponseBody(req)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(response)),
		}, nil
	default:
		return nil, nil // Simulate no response for other URLs
	}
}

// getMockOCSPResponseBody generates a minimal OCSP response (DER-encoded)
// that will pass parsing by ParseResponseForCert. It returns a []byte with a single "good" status.
// This is for testing/mocking purposes only.
func (m *MockHttpClient) getMockOCSPResponseBody(req *http.Request) []byte {
	// Get leaf and ca (issuer) certs from the m.chainPath
	leafCertPath := path.Join(m.chainPath, "leaf.pem")
	leafCertBytes, err := os.ReadFile(leafCertPath)
	if err != nil {
		panic("failed to read leaf certificate: " + err.Error())
	}
	leafPem, _ := pem.Decode(leafCertBytes)
	leafCert, err := x509.ParseCertificate(leafPem.Bytes)
	if err != nil {
		panic("failed to parse leaf certificate: " + err.Error())
	}
	issuerCertPath := path.Join(m.chainPath, "ca.pem")
	issuerCertBytes, err := os.ReadFile(issuerCertPath)
	if err != nil {
		panic("failed to read issuer certificate: " + err.Error())
	}
	issuerPem, _ := pem.Decode(issuerCertBytes)
	if issuerPem == nil {
		panic("failed to decode issuer certificate PEM")
	}
	// Parse issuer certificate
	issuerCert, err := x509.ParseCertificate(issuerPem.Bytes)
	if err != nil {
		panic("failed to parse issuer certificate: " + err.Error())
	}
	// Get signer key (private key of the issuer)
	signerKeyPath := path.Join(m.chainPath, "ca.key")
	signerKeyBytes, err := os.ReadFile(signerKeyPath)
	if err != nil {
		panic("failed to read signer key: " + err.Error())
	}
	signerKeyPem, _ := pem.Decode(signerKeyBytes)
	if signerKeyPem == nil {
		panic("failed to decode signer key PEM")
	}
	// Try PKCS8 first, then PKCS1
	var signerKey *rsa.PrivateKey
	keyAny, err := x509.ParsePKCS8PrivateKey(signerKeyPem.Bytes)
	if err == nil {
		var ok bool
		signerKey, ok = keyAny.(*rsa.PrivateKey)
		if !ok {
			panic("parsed PKCS8 key is not RSA private key")
		}
	} else {
		signerKey, err = x509.ParsePKCS1PrivateKey(signerKeyPem.Bytes)
		if err != nil {
			panic("failed to parse signer key: " + err.Error())
		}
	}

	// Create OCSP response template
	template := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leafCert.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(1 * time.Hour),
	}

	// Generate OCSP response
	respDER, err := ocsp.CreateResponse(issuerCert, issuerCert, template, signerKey)
	if err != nil {
		panic("failed to create mock OCSP response: " + err.Error())
	}
	return respDER
}

func NewMockHttpClient() *MockHttpClient {
	return &MockHttpClient{}
}

func TestNewVerifySvc(t *testing.T) {
	db := NewMockDb()
	if db == nil {
		t.Fatal("Expected non-nil MockDb")
	}
	httpClient := NewMockHttpClient()
	svc := NewVerifySvc(db, httpClient)
	if svc == nil {
		t.Fatal("Expected non-nil VerifySvc")
	}
}

func TestParseCert(t *testing.T) {
	db := NewMockDb()
	if db == nil {
		t.Fatal("Expected non-nil MockDb")
	}
	httpClient := NewMockHttpClient()
	svc := NewVerifySvc(db, httpClient)
	if svc == nil {
		t.Fatal("Expected non-nil VerifySvc")
	}
	ctx := gin.Context{}

	cert, err := svc.parseCert(&ctx, []byte(certContent))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	t.Logf("Parsed certificate: %+v", cert)
	if cert.CompanyId != "12345678" {
		t.Errorf("Expected CompanyId '12345678', got '%s'", cert.CompanyId)
	}
	if len(cert.Scopes) == 0 {
		t.Error("Expected non-empty Scopes, got none")
	}
	if cert.Scopes[0] != PSP_PI || cert.Scopes[1] != PSP_AI {
		t.Errorf("Expected Scopes to contain PSP_AI and PSP_PI, got %v", cert.Scopes)
	}
	if len(cert.ParentLinks) == 0 {
		t.Error("Expected non-empty ParentLinks, got none")
	}
	if cert.ParentLinks[0] != "http://test.company.hu/CA.crt" {
		t.Errorf("Expected ParentLinks to contain 'http://test.company.hu/CA.crt', got %s", cert.ParentLinks[0])
	}
	if len(cert.CRLs) == 0 {
		t.Error("Expected non-empty CRLs, got none")
	}
	if cert.CRLs[0] != "http://test.company.hu/Some.crl" {
		t.Errorf("Expected CRLs to contain 'http://test.company.hu/Some.crl', got %s", cert.CRLs[0])
	}
	if cert.Sha256 == "" {
		t.Error("Expected non-empty SHA256, got empty string")
	}
	if cert.Sha256 != "ef2527a44ccee556b6a5cabde31dda68e45165b2ec2ae67270b17cf01f4e8f1a" {
		t.Errorf("Expected SHA256 'ef2527a44ccee556b6a5cabde31dda68e45165b2ec2ae67270b17cf01f4e8f1a', got '%s'", cert.Sha256)
	}
	if cert.NCA.Country != "FI" {
		t.Errorf("Expected NCA Country 'FI', got '%s'", cert.NCA.Country)
	}
	if cert.NCA.Name != "Finnish Financial Supervisory Authority" {
		t.Errorf("Expected NCA Name 'Finnish Financial Supervisory Authority', got '%s'", cert.NCA.Name)
	}
	if cert.NCA.Id != "FI-FINFSA" {
		t.Errorf("Expected NCA Id 'FI-FINFSA', got '%s'", cert.NCA.Id)
	}
}

func TestGetTpp(t *testing.T) {
	db := NewMockDb()
	if db == nil {
		t.Fatal("Expected non-nil MockDb")
	}
	httpClient := NewMockHttpClient()
	svc := NewVerifySvc(db, httpClient)
	if svc == nil {
		t.Fatal("Expected non-nil VerifySvc")
	}
	ctx := gin.Context{}
	companyId := "12345678"
	tpp, err := svc.getTpp(&ctx, companyId)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	t.Logf("Retrieved TPP: %+v", tpp)
	if tpp == nil {
		t.Fatal("Expected non-nil TPP")
	}
	if tpp.Id != companyId {
		t.Errorf("Expected TPP Id '%s', got '%s'", companyId, tpp.Id)
	}
	if tpp.NameLatin != "Test TPP" {
		t.Errorf("Expected TPP NameLatin 'Test TPP', got '%s'", tpp.NameLatin)
	}
	if tpp.NameNative != "Teszt TPP" {
		t.Errorf("Expected TPP NameNative 'Teszt TPP', got '%s'", tpp.NameNative)
	}
	if tpp.Authority != "Test Authority" {
		t.Errorf("Expected TPP Authority 'Test Authority', got '%s'", tpp.Authority)
	}
	if len(tpp.Services) == 0 {
		t.Error("Expected non-empty TPP Services, got none")
	}
}

func TestVerifyCert(t *testing.T) {
	db := NewMockDb()
	if db == nil {
		t.Fatal("Expected non-nil MockDb")
	}
	httpClient := NewMockHttpClient()
	svc := NewVerifySvc(db, httpClient)
	if svc == nil {
		t.Fatal("Expected non-nil VerifySvc")
	}
	ctx := gin.Context{}
	projectRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get project root: %v", err)
		return
	}
	chainsPath := path.Join(projectRoot, "/../../testdata/chains/")
	entries, err := os.ReadDir(chainsPath)
	if err != nil {
		t.Fatalf("Failed to read chains directory: %v", err)
		return
	}
	if len(entries) == 0 {
		t.Fatal("Expected non-empty chains directory, got none")
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		httpClient.SetChainPath(path.Join(chainsPath, entry.Name()))
		certPath := path.Join(chainsPath, entry.Name(), "leaf.pem")
		certContent, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatalf("Failed to read certificate file %s: %v", certPath, err)
			return
		}
		cert, err := svc.parseCert(&ctx, []byte(certContent))
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		t.Logf("Parsed certificate: %+v", cert)
		// Simulate a successful verification

		verifyRes, err := svc.verifyCert(&ctx, cert)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if !verifyRes.Valid {
			t.Error("Expected certificate to be verified successfully, but it was not")
		}
	}

}

// func TestVerify_Success(t *testing.T) {
// 	gin.SetMode(gin.TestMode)

// 	var verifyRequest VerifyRequest
// 	verifyRequest.Cert = []byte(certContent)
// 	body, err := json.Marshal(verifyRequest)
// 	if err != nil {
// 		t.Fatalf("Couldn't marshal request: %v\n", err)
// 	}

// 	req, err := http.NewRequest(http.MethodPost, "/verify", bytes.NewBuffer(body))
// 	if err != nil {
// 		t.Fatalf("Couldn't create request: %v\n", err)
// 	}
// 	req.Header.Set("Content-Type", "application/json")

// 	w := httptest.NewRecorder()
// 	c, _ := gin.CreateTestContext(w)
// 	c.Request = req

// 	Verify(c)

// 	if w.Code != http.StatusOK {
// 		t.Fatalf("Expected status code 200, got %d\n", w.Code)
// 	}
// 	log.Printf("Response: %s\n", w.Body.String())

// 	certContentNoPaddings := strings.Replace(certContent, "-----BEGIN CERTIFICATE-----", "", 1)
// 	certContentNoPaddings = strings.Replace(certContentNoPaddings, "-----END CERTIFICATE-----", "", 1)
// 	certContentNoPaddings = strings.ReplaceAll(certContentNoPaddings, "\n", "")

// 	verifyRequest.Cert = []byte(certContentNoPaddings)
// 	body, err = json.Marshal(verifyRequest)
// 	if err != nil {
// 		t.Fatalf("Couldn't marshal request: %v\n", err)
// 	}

// 	req, err = http.NewRequest(http.MethodPost, "/verify", bytes.NewBuffer(body))
// 	if err != nil {
// 		t.Fatalf("Couldn't create request: %v\n", err)
// 	}
// 	req.Header.Set("Content-Type", "application/json")

// 	w = httptest.NewRecorder()
// 	c.Request = req

// 	Verify(c)

// 	if w.Code != http.StatusOK {
// 		t.Fatalf("Expected status code 200, got %d\n", w.Code)
// 	}
// 	log.Printf("Response: %s\n", w.Body.String())
// }

// func TestVerify_BadRequest(t *testing.T) {
// 	gin.SetMode(gin.TestMode)

// 	var verifyRequest VerifyRequest
// 	verifyRequest.Cert = []byte("invalid")
// 	body, err := json.Marshal(verifyRequest)
// 	if err != nil {
// 		t.Fatalf("Couldn't marshal request: %v\n", err)
// 	}

// 	req, err := http.NewRequest(http.MethodPost, "/verify", bytes.NewBuffer(body))
// 	if err != nil {
// 		t.Fatalf("Couldn't create request: %v\n", err)
// 	}
// 	req.Header.Set("Content-Type", "application/json")

// 	w := httptest.NewRecorder()
// 	c, _ := gin.CreateTestContext(w)
// 	c.Request = req

// 	Verify(c)

// 	if w.Code != http.StatusBadRequest {
// 		t.Fatalf("Expected status code 400, got %d\n", w.Code)
// 	}
// }
