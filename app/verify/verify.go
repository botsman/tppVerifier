package verify

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type VerifyRequest struct {
	Cert string `json:"cert"`
}

type VerifyResult struct {
	Valid  bool                `json:"valid"`
	Scopes map[string][]string `json:"scopes"`
	Reason string              `json:"reason,omitempty"`
}

func Verify(c *gin.Context) {
	// 1. Parse the certificate
	// 2. Extract the TPP ID
	// 3. Query the database for the TPP
	// 4. Verify the certificate:
	//    - Check if the certificate is valid
	//    - Check if the certificate is not expired
	//    - Check if the certificate is not revoked
	//    - Check if the certificate is signed by a trusted CA
	//    - Check if the certificate is not sandbox
	//    - Check certificate's scopes
	// 5. Intersect the TPP's scopes with the certificate's scopes
	// 5. Return the result
	var req VerifyRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	var res = "asd"
	cert, err := parseCert(c, req.Cert)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	fmt.Println(cert)
	c.JSON(http.StatusOK, res)
}
