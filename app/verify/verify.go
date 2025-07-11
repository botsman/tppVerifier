package verify

import (
	"net/http"
	"slices"

	"github.com/botsman/tppVerifier/app/db"
	vhttp "github.com/botsman/tppVerifier/app/http"
	"github.com/botsman/tppVerifier/app/models"

	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ocsp"
)

type VerifySvc struct {
	db         db.TppRepository
	httpClient vhttp.Client
	roots      *x509.CertPool
}

func NewVerifySvc(db db.TppRepository, httpClient vhttp.Client) *VerifySvc {
	return &VerifySvc{
		db:         db,
		httpClient: httpClient,
	}
}

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

func (s *VerifySvc) SetRoots(roots *x509.CertPool) {
	s.roots = roots
}

func (s *VerifySvc) Verify(c *gin.Context) {
	// 1. Parse the certificate
	// 2. Extract the TPP ID
	// 3. Query the database for the TPP
	// 4. Verify the certificate:
	//    - Check if the certificate is valid
	//    - Check if the certificate is not expired
	//    - Check if the certificate is not revoked
	//    - Check if the certificate is signed by a trusted CA
	// 5. Intersect the TPP's services with the certificate's scopes
	// 5. Return the result
	var req VerifyRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	result := VerifyResult{}
	cert, err := s.parseCert(c, req.Cert)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	result.Certificate = &cert
	tpp, err := s.getTpp(c, cert.CompanyId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	result.TPP = tpp

	certVerifyResult, err := s.verifyCert(c, cert)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	result.Valid = certVerifyResult.Valid
	result.Reason = certVerifyResult.Reason
	result.Scopes = s.getScopes(c, cert, tpp)
	if len(result.Scopes) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No valid scopes found in the certificate",
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

func (s *VerifySvc) getTpp(c *gin.Context, id string) (*models.TPP, error) {
	tpp, err := s.db.GetTpp(c, id)
	if err != nil {
		return nil, err
	}
	return tpp, nil
}

type ParsedCert struct {
	cert        *x509.Certificate
	CompanyId   string
	Scopes      []Scope
	ParentLinks []string
	CRLs        []string
	OCSPs       []string
	Usage       CertUsage
	Serial      string
	Sha256      string
	NCA         NCA
}

type CertUsage string

const (
	QWAC    CertUsage = "QWAC"
	QSEAL   CertUsage = "QSEAL"
	UNKNOWN CertUsage = "UNKNOWN"
)

type Scope string

const (
	// PSP_AS Scope = "PSP_AS"
	PSP_PI Scope = "PSP_PI"
	PSP_AI Scope = "PSP_AI"
	// PSP_IC Scope = "PSP_IC"
)

type QCStatement struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"optional"`
}

type Role struct {
	OID   asn1.ObjectIdentifier
	Value Scope
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

type certVerifyResult struct {
	Valid  bool
	Reason string
}

func getCertOBScopes(cert *x509.Certificate) ([]Scope, error) {
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
				roles := make([]Scope, 0)
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

func (s *VerifySvc) isRevoked(c, issuer *x509.Certificate) (bool, error) {
	ocspServer := c.OCSPServer[0]
	// ocspUrl, err := url.Parse(ocspServer)
	// if err != nil {
	// 	log.Printf("Error parsing OCSP server URL: %s", err)
	// 	return false
	// }
	req, err := ocsp.CreateRequest(c, issuer, nil)
	if err != nil {
		log.Printf("Error creating OCSP request: %s", err)
		return false, err
	}
	httpRequest, err := http.NewRequest("POST", ocspServer, bytes.NewReader(req))
	if err != nil {
		log.Printf("Error creating OCSP request: %s", err)
		return false, err
	}
	httpRequest.Header.Set("Content-Type", "application/ocsp-request")
	httpRequest.Header.Set("Accept", "application/ocsp-response")
	// httpRequest.Header.Set("host", ocspUrl.Hostname())
	httpResponse, err := s.httpClient.Do(httpRequest)
	if err != nil {
		log.Printf("Error sending OCSP request: %s", err)
		return false, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Printf("Error closing OCSP response body: %s", err)
		}
	}(httpResponse.Body)
	if httpResponse.StatusCode != http.StatusOK {
		log.Printf("OCSP server returned status %d", httpResponse.StatusCode)
		return false, errors.New("OCSP server returned non-OK status")
	}
	body, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		log.Printf("Error reading OCSP response: %s", err)
		return false, err
	}
	ocspResponse, err := ocsp.ParseResponseForCert(body, c, issuer)
	if err != nil {
		log.Printf("Error parsing OCSP response: %s", err)
		return false, err
	}
	return ocspResponse.Status == ocsp.Revoked, nil
}

func (s *VerifySvc) isTrusted(cert *x509.Certificate, chain []*x509.Certificate) (bool, error) {
	return true, nil // TODO: Implement certificate trust verification logic
	// intermediatePool := x509.NewCertPool()
	// for _, intermediate := range chain {
	// 	intermediatePool.AddCert(intermediate)
	// }
	// opts := x509.VerifyOptions{
	// 	Roots:         s.roots,
	// 	Intermediates: intermediatePool,
	// }
	// _, err := cert.Verify(opts)
	// if err != nil {
	// 	log.Printf("Certificate verification failed: %s", err)
	// 	if _, ok := err.(x509.UnknownAuthorityError); ok {
	// 		log.Printf("Certificate is not trusted")
	// 		return false, nil
	// 	}
	// }
	// log.Printf("Certificate is trusted")
	// return true, nil
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

func (s *VerifySvc) parseCert(_ *gin.Context, data []byte) (ParsedCert, error) {
	data, err := formatCertContent(data)
	if err != nil {
		return ParsedCert{}, err
	}
	p, _ := pem.Decode(data) // ignore rest for now, maybe use it later
	if p == nil {
		return ParsedCert{}, errors.New("error parsing certificate")
	}
	x509Cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return ParsedCert{}, err
	}
	var cert ParsedCert
	cert.cert = x509Cert
	cert.CompanyId = x509Cert.Subject.SerialNumber
	scopes, err := getCertOBScopes(x509Cert)
	if err != nil {
		return ParsedCert{}, err
	}
	cert.Scopes = scopes
	cert.ParentLinks = x509Cert.IssuingCertificateURL
	cert.CRLs = x509Cert.CRLDistributionPoints
	cert.OCSPs = x509Cert.OCSPServer
	cert.Usage = getCertUsage(x509Cert)
	cert.Serial = x509Cert.SerialNumber.String()
	cert.Sha256 = getSha256(x509Cert)
	nca, err := getCertNCA(x509Cert)
	if err != nil {
		return ParsedCert{}, err
	}
	cert.NCA = nca
	return cert, nil
}

func (s *VerifySvc) verifyCert(c *gin.Context, cert ParsedCert) (certVerifyResult, error) {
	result := certVerifyResult{
		Valid:  true,
		Reason: "",
	}
	if cert.Usage == UNKNOWN {
		result.Valid = false
		result.Reason = "Unknown certificate usage"
		return result, nil
	}

	certChain, err := s.loadCertChain(c, cert.cert.IssuingCertificateURL[0])
	if err != nil {
		log.Printf("Error loading certificate chain: %s", err)
		result.Valid = false
		result.Reason = "Error loading certificate chain"
		return result, nil
	}
	if len(certChain) == 0 {
		log.Printf("No certificate chain found for the certificate")
		result.Valid = false
		result.Reason = "No certificate chain found for the certificate"
		return result, nil
	}
	isTrusted, err := s.isTrusted(cert.cert, certChain)
	if err != nil {
		log.Printf("Error checking if certificate is trusted: %s", err)
		result.Valid = false
		result.Reason = "Error checking if certificate is trusted"
		return result, nil
	}
	if !isTrusted {
		log.Printf("Certificate is not trusted")
		result.Valid = false
		result.Reason = "Certificate is not trusted"
		return result, nil
	}

	isRevoked, err := s.isRevoked(cert.cert, certChain[len(certChain)-1])
	if err != nil {
		log.Printf("Error checking certificate revocation: %s", err)
		result.Valid = false
		result.Reason = "Error checking certificate revocation"
		return result, nil
	}
	if isRevoked {
		log.Printf("Certificate is revoked")
		result.Valid = false
		result.Reason = "Certificate is revoked"
		return result, nil
	}

	return result, nil
}

func (s *VerifySvc) loadCertChain(c *gin.Context, link string) ([]*x509.Certificate, error) {
	// This function gets the certificate chain for the given certificate
	var certChain []*x509.Certificate
	// First it queries the database for the certificate chain
	// If the chain is not found, it tries to download it from the OCSP server
	// and then saves it to the database
	// For now we will not query the database and always try to download the chain
	prevParentLink := ""
	parentLink := link
	for parentLink != "" && parentLink != prevParentLink {
		prevParentLink = parentLink
		req, err := http.NewRequest("GET", parentLink, nil)
		if err != nil {
			log.Printf("Error creating request to download certificate chain: %s", err)
			return nil, err
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			log.Printf("Error downloading certificate chain: %s", err)
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("Error downloading certificate chain: %s", resp.Status)
			return nil, errors.New("error downloading certificate chain")
		}
		certs, err := loadCerts(c, resp.Body)
		if err != nil {
			log.Printf("Error loading certificates from response body: %s", err)
			return nil, err
		}
		if len(certs) == 0 {
			log.Printf("No certificates found in certificate chain response")
			return nil, errors.New("no certificates found in certificate chain response")
		}
		certChain = append(certChain, certs...)
		parentCert := certs[len(certs)-1] // Get the last certificate in the chain
		if len(parentCert.IssuingCertificateURL) == 0 {
			log.Printf("No parent certificate link found in the last certificate of the chain")
			break
		}
		parentLink = certs[len(certs)-1].IssuingCertificateURL[0] // Get the parent link from the last certificate in the chain
	}
	return certChain, nil
}

func loadCerts(_ *gin.Context, body io.ReadCloser) ([]*x509.Certificate, error) {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		log.Printf("Error reading response body: %s", err)
		return nil, err
	}
	p, _ := pem.Decode(bodyBytes) // ignore rest for now, maybe use it later
	if p == nil {
		return nil, errors.New("error parsing certificate")
	}
	certs, err := x509.ParseCertificates(p.Bytes)
	if err != nil {
		log.Printf("Error parsing certificates from response body: %s", err)
		return nil, err
	}
	return certs, nil
}

func (s *VerifySvc) getScopes(c *gin.Context, cert ParsedCert, tpp *models.TPP) map[string][]string {
	certServices := getCertServices(cert)
	if len(certServices) == 0 {
		log.Printf("No services found in the certificate for TPP %s", tpp.Id)
		return nil
	}
	scopes := make(map[string][]string)
	for country, services := range tpp.Services {
		for _, service := range services {
			if slices.Contains(certServices, service) {
				scopes[country] = append(scopes[country], string(service))
			}
		}
	}
	return scopes
}

func getCertServices(cert ParsedCert) []models.Service {
	services := make([]models.Service, 0)
	for _, scope := range cert.Scopes {
		switch scope {
		case PSP_PI:
			services = append(services, models.PIS)
		case PSP_AI:
			services = append(services, models.AIS)
		default:
			log.Printf("Unknown scope in certificate: %s", scope)
			continue
		}
	}
	return services
}
