package verify

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
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

func TestVerify_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var verifyRequest VerifyRequest
	verifyRequest.Cert = []byte(certContent)
	body, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("Couldn't marshal request: %v\n", err)
	}

	req, err := http.NewRequest(http.MethodPost, "/verify", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Couldn't create request: %v\n", err)
	}
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	Verify(c)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status code 200, got %d\n", w.Code)
	}

	certContentNoPaddings := strings.Replace(certContent, "-----BEGIN CERTIFICATE-----", "", 1)
	certContentNoPaddings = strings.Replace(certContentNoPaddings, "-----END CERTIFICATE-----", "", 1)
	certContentNoPaddings = strings.ReplaceAll(certContentNoPaddings, "\n", "")

	verifyRequest.Cert = []byte(certContentNoPaddings)
	body, err = json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("Couldn't marshal request: %v\n", err)
	}

	req, err = http.NewRequest(http.MethodPost, "/verify", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Couldn't create request: %v\n", err)
	}
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	c.Request = req

	Verify(c)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status code 200, got %d\n", w.Code)
	}

}

func TestVerify_BadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var verifyRequest VerifyRequest
	verifyRequest.Cert = []byte("invalid")
	body, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("Couldn't marshal request: %v\n", err)
	}

	req, err := http.NewRequest(http.MethodPost, "/verify", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Couldn't create request: %v\n", err)
	}
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	Verify(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected status code 400, got %d\n", w.Code)
	}
}
