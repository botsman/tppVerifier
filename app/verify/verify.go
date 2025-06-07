package verify

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/botsman/tppVerifier/app/models"
)

type VerifyRequest struct {
	Cert []byte `json:"cert"`
}

type VerifyResult struct {
	Certificate *ParsedCert         `json:"cert"`
	TPP         *models.TPP         `json:"tpp"`
	Valid       bool                `json:"valid"`
	Scopes      map[string][]string `json:"scopes"`
	Reason      string              `json:"reason,omitempty"`
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
	// 5. Intersect the TPP's scopes with the certificate's scopes
	// 5. Return the result
	var req VerifyRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	result := VerifyResult{}
	cert, err := parseCert(c, req.Cert)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	result.Certificate = &cert
	tpp, err := getTpp(c, cert.CompanyId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	result.TPP = tpp

	// certVerifyResult, err := verifyCert(c, cert, tpp)
	// if err != nil {
	// 	c.JSON(http.StatusInternalServerError, gin.H{
	// 		"error": err.Error(),
	// 	})
	// 	return
	// }

	// result, err := calculateResult(certVerifyResult, tpp)
	// if err != nil {
	// 	c.JSON(http.StatusInternalServerError, gin.H{
	// 		"error": err.Error(),
	// 	})
	// 	return
	// }
	c.JSON(http.StatusOK, result)
}
