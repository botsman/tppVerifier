package verify

import (
	"testing"

	"github.com/gin-gonic/gin"
)

func TestParseCert_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)

	data := "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Q2k5Z5Z5Z5Z5Z5Z5Z5Z\n-----END CERTIFICATE-----"

	parsedCert, err := parseCert(c, data)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	t.Log(parsedCert)
}
