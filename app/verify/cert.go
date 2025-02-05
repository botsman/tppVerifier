package verify

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ocsp"
)

type parsedCert struct {
	cert        *x509.Certificate
	companyId   string
	scopes      []scope
	parentLinks []string
	crls        []string
	ocsps       []string
	usage       CertUsage
	serial      string
	sha256      string
	nca         NCA
}

type CertUsage string

const (
	QWAC    CertUsage = "QWAC"
	QSEAL   CertUsage = "QSEAL"
	UNKNOWN CertUsage = "UNKNOWN"
)

type scope string

const (
	PSP_AS scope = "PSP_AS"
	PSP_PI scope = "PSP_PI"
	PSP_AI scope = "PSP_AI"
	PSP_IC scope = "PSP_IC"
)

type QCStatement struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"optional"`
}

type Role struct {
	OID   asn1.ObjectIdentifier
	Value scope
}

type PSD2QcType struct {
	RolesOfPSP []Role
	NCAName    string
	NCAId      string
}

type NCA struct {
	Country string
	Name    string
	Id      string
}

type URLStruct struct {
	URL  string
	Lang string
}

func getCertOBScopes(cert *x509.Certificate) ([]scope, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}) {
			continue
		}
		var qcStatements []QCStatement
		_, err := asn1.Unmarshal(ext.Value, &qcStatements)
		if err != nil {
			return nil, err
		}

		for _, stmt := range qcStatements {
			switch {
			// case stmt.ID.Equal(asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}):
			// 	var urlStructs []URLStruct
			// 	_, err := asn1.Unmarshal(stmt.Value.FullBytes, &urlStructs)
			// 	if err != nil {
			// 		fmt.Println(err)
			// 	}
			// 	for _, urlStruct := range urlStructs {
			// 		fmt.Println(urlStruct.URL, urlStruct.Lang)
			// 	}
			case stmt.ID.Equal(asn1.ObjectIdentifier{0, 4, 0, 19495, 2}):
				var psd2 PSD2QcType
				_, err := asn1.Unmarshal(stmt.Value.FullBytes, &psd2)
				if err != nil {
					return nil, err
				}
				roles := make([]scope, 0)
				for _, role := range psd2.RolesOfPSP {
					roles = append(roles, role.Value)
				}
				return roles, nil
			}
		}
	}
	return nil, nil
}

func getCertNCA(cert *x509.Certificate) (NCA, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}) {
			continue
		}
		var qcStatements []QCStatement
		_, err := asn1.Unmarshal(ext.Value, &qcStatements)
		if err != nil {
			return NCA{}, err
		}

		for _, stmt := range qcStatements {
			switch {
			// case stmt.ID.Equal(asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}):
			// 	var urlStructs []URLStruct
			// 	_, err := asn1.Unmarshal(stmt.Value.FullBytes, &urlStructs)
			// 	if err != nil {
			// 		fmt.Println(err)
			// 	}
			// 	for _, urlStruct := range urlStructs {
			// 		fmt.Println(urlStruct.URL, urlStruct.Lang)
			// 	}
			case stmt.ID.Equal(asn1.ObjectIdentifier{0, 4, 0, 19495, 2}):
				var psd2 PSD2QcType
				_, err := asn1.Unmarshal(stmt.Value.FullBytes, &psd2)
				if err != nil {
					return NCA{}, err
				}
				country := psd2.NCAId[:2]
				return NCA{Country: country, Name: psd2.NCAName, Id: psd2.NCAId}, nil
			}
		}
	}
	return NCA{}, nil
}

func getCertUsage(cert *x509.Certificate) CertUsage {
	// Maybe this should be identified based on certificate policy
	switch cert.KeyUsage {
	case x509.KeyUsageKeyEncipherment:
		return QWAC
	case x509.KeyUsageContentCommitment:
		return QSEAL
	default:
		// perhaps identify based on the extended key usage or certificate policy
		log.Printf("Unknown certificate usage: %v", cert.KeyUsage)
		return UNKNOWN
	}
}

func getSha256(cert *x509.Certificate) string {
	checksum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(checksum[:])
}

func IsRevoked(c, issuer *x509.Certificate) bool {
	ocspServer := c.OCSPServer[0]
	//ocspUrl, err := url.Parse(ocspServer)
	//if err != nil {
	//	log.Printf("Error parsing OCSP server URL: %s", err)
	//	return false
	//}
	req, err := ocsp.CreateRequest(c, issuer, nil)
	if err != nil {
		log.Printf("Error creating OCSP request: %s", err)
		return false
	}
	httpRequest, err := http.NewRequest("POST", ocspServer, bytes.NewReader(req))
	if err != nil {
		log.Printf("Error creating OCSP request: %s", err)
		return false
	}
	httpRequest.Header.Set("Content-Type", "application/ocsp-request")
	httpRequest.Header.Set("Accept", "application/ocsp-response")
	//httpRequest.Header.Set("host", ocspUrl.Hostname())
	httpResponse, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		log.Printf("Error sending OCSP request: %s", err)
		return false
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Printf("Error closing OCSP response body: %s", err)
		}
	}(httpResponse.Body)
	if httpResponse.StatusCode != http.StatusOK {
		log.Printf("OCSP server returned status %d", httpResponse.StatusCode)
		return false
	}
	body, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		log.Printf("Error reading OCSP response: %s", err)
		return false
	}
	ocspResponse, err := ocsp.ParseResponseForCert(body, c, issuer)
	if err != nil {
		log.Printf("Error parsing OCSP response: %s", err)
		return false
	}
	return ocspResponse.Status == ocsp.Revoked
}

func formatCertContent(content []byte) ([]byte, error) {
	certPrefix := "-----BEGIN CERTIFICATE-----"
	certSuffix := "-----END CERTIFICATE-----"
	pemLineLength := 64
	contentString := string(content)
	contentString = strings.Replace(contentString, certPrefix, "", 1)
	contentString = strings.Replace(contentString, certSuffix, "", 1)
	contentString = strings.ReplaceAll(contentString, "\n", "")
	contentString = strings.ReplaceAll(contentString, " ", "")
	contentString = strings.ReplaceAll(contentString, "\r", "")
	var buffer bytes.Buffer
	buffer.WriteString(certPrefix)
	buffer.WriteString("\n")
	for i := 0; i < len(contentString); i += pemLineLength {
		end := i + pemLineLength
		if end > len(contentString) {
			end = len(contentString)
		}
		buffer.WriteString(contentString[i:end])
		buffer.WriteString("\n")
	}
	buffer.WriteString(certSuffix)
	return buffer.Bytes(), nil
}

func parseCert(c *gin.Context, data []byte) (parsedCert, error) {
	data, err := formatCertContent(data)
	if err != nil {
		return parsedCert{}, err
	}
	p, _ := pem.Decode(data) // ignore rest for now, maybe use it later
	if p == nil {
		return parsedCert{}, errors.New("Error parsing certificate")
	}
	x509Cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return parsedCert{}, err
	}
	var cert parsedCert
	cert.cert = x509Cert
	cert.companyId = x509Cert.Subject.Organization[0]
	scopes, err := getCertOBScopes(x509Cert)
	if err != nil {
		return parsedCert{}, err
	}
	cert.scopes = scopes
	cert.parentLinks = x509Cert.IssuingCertificateURL
	cert.crls = x509Cert.CRLDistributionPoints
	cert.ocsps = x509Cert.OCSPServer
	cert.usage = getCertUsage(x509Cert)
	cert.serial = x509Cert.SerialNumber.String()
	cert.sha256 = getSha256(x509Cert)
	nca, err := getCertNCA(x509Cert)
	if err != nil {
		return parsedCert{}, err
	}
	cert.nca = nca
	return cert, nil
}
