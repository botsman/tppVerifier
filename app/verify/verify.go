package verify

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/botsman/tppVerifier/app/cert"
	"github.com/botsman/tppVerifier/app/db"
	vhttp "github.com/botsman/tppVerifier/app/http"
	"github.com/botsman/tppVerifier/app/models"

	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"log"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ocsp"
)

type VerifySvc struct {
	db            db.TppRepository
	httpClient    vhttp.Client
	roots         *x509.CertPool
	intermediates *x509.CertPool
	haveLinks     map[string]bool // used to avoid duplicate links
}

func NewVerifySvc(db db.TppRepository, httpClient vhttp.Client) *VerifySvc {
	return &VerifySvc{
		db:         db,
		httpClient: httpClient,
	}
}

type VerifyRequest struct {
	Cert string `json:"cert"`
}

type VerifyResult struct {
	Certificate *cert.ParsedCert    `json:"cert"`
	TPP         *models.TPP         `json:"tpp"`
	Valid       bool                `json:"valid"`
	Scopes      map[string][]string `json:"scopes"`
	Reason      string              `json:"reason,omitempty"`
}

func (s *VerifySvc) AddRoot(cert *x509.Certificate) {
	if s.roots == nil {
		s.roots = x509.NewCertPool()
	}
	s.roots.AddCert(cert)
	for _, link := range cert.IssuingCertificateURL {
		if link == "" {
			continue
		}
		if !s.addLink(link) {
			log.Printf("Link %s already exists, skipping", link)
			continue
		}
	}
}

func (s *VerifySvc) AddIntermediate(cert *x509.Certificate) {
	if s.intermediates == nil {
		s.intermediates = x509.NewCertPool()
	}
	s.intermediates.AddCert(cert)
	for _, link := range cert.IssuingCertificateURL {
		if link == "" {
			continue
		}
		if !s.addLink(link) {
			log.Printf("Link %s already exists, skipping", link)
			continue
		}
	}
}

func (s *VerifySvc) addLink(link string) bool {
	if s.haveLinks == nil {
		s.haveLinks = make(map[string]bool)
	}
	if _, exists := s.haveLinks[link]; exists {
		return false
	}
	s.haveLinks[link] = true
	return true
}

func (s *VerifySvc) LinkExists(link string) bool {
	if s.haveLinks == nil {
		return false
	}
	_, exists := s.haveLinks[link]
	return exists
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
	certs, err := cert.ParseCerts([]byte(req.Cert))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	if len(certs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No valid certificate found",
		})
		return
	}
	cert := certs[0]
	result.Certificate = cert
	tpp, err := s.getTpp(c, cert.CompanyId())
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

func normalizeTppId(id string) string {
	// TPPs are stored in the format "PSD{country}-{authority}-{id}". Eg. PSDFI-FINFSA-123456789
	// However, some countries put dash into the id, so we need to normalize it to remove the dash

	parts := strings.Split(id, "-")
	if len(parts) < 3 {
		return id // If the format is not as expected, return the original ID
	}
	// Join the parts back together, removing the dash from the last part
	return fmt.Sprintf("%s-%s-%s", parts[0], parts[1], strings.Join(parts[2:], ""))
}

func (s *VerifySvc) getTpp(c *gin.Context, id string) (*models.TPP, error) {
	id = normalizeTppId(id)
	tpp, err := s.db.GetTpp(c, id)
	if err != nil {
		return nil, err
	}
	return tpp, nil
}

type Role struct {
	OID   asn1.ObjectIdentifier
	Value models.Scope
}

type URLStruct struct {
	URL  string
	Lang string
}

type certVerifyResult struct {
	Valid  bool
	Reason string
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

func RawCertToPEM(raw []byte) ([]byte, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: raw,
	})
	if pemBytes == nil {
		return nil, errors.New("error encoding certificate to PEM format")
	}
	return pemBytes, nil
}

func (s *VerifySvc) isTrusted(cert *x509.Certificate, intermediateChain []*cert.ParsedCert) (bool, []*x509.Certificate, error) {
	intermediates := s.intermediates.Clone()
	for _, c := range intermediateChain {
		intermediates.AddCert(c.Cert)
	}
	opts := x509.VerifyOptions{
		Roots:         s.roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}
	chains, err := cert.Verify(opts)
	if err != nil {
		log.Printf("Certificate verification failed: %s", err)
		return false, nil, err
	}
	log.Printf("Certificate is trusted")
	return true, chains[0], nil
}

func (s *VerifySvc) verifyCert(c *gin.Context, crt *cert.ParsedCert) (certVerifyResult, error) {
	result := certVerifyResult{
		Valid:  true,
		Reason: "",
	}
	if crt.Usage() == models.UNKNOWN {
		result.Valid = false
		result.Reason = "Unknown certificate usage"
		return result, nil
	}

	intermediateChain, err := s.loadCertChain(c, crt.Cert.IssuingCertificateURL[0])
	if err != nil {
		log.Printf("Error loading certificate chain: %s", err)
		result.Valid = false
		result.Reason = "Error loading certificate chain"
		return result, nil
	}
	isTrusted, chain, err := s.isTrusted(crt.Cert, intermediateChain)
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
	s.updateIntermediates(c, intermediateChain)

	isRevoked, err := s.isRevoked(crt.Cert, chain[len(chain)-1])
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

func (s *VerifySvc) updateIntermediates(c *gin.Context, certs []*cert.ParsedCert) error {
	for _, crt := range certs {
		if !s.LinkExists(crt.Cert.IssuingCertificateURL[0]) {
			s.AddIntermediate(crt.Cert)
			s.addLink(crt.Cert.IssuingCertificateURL[0])
			s.db.AddCertificate(c, crt)
			log.Printf("Added intermediate certificate with SHA256 %s", crt.Sha256())
		} else {
			log.Printf("Intermediate certificate with SHA256 %s already exists", crt.Sha256())
		}
	}
	return nil
}

func (s *VerifySvc) loadCertChain(c *gin.Context, link string) ([]*cert.ParsedCert, error) {
	// This function gets the certificate chain for the given certificate
	// First it queries the database for the certificate chain
	// If the chain is not found, it tries to download it from the OCSP server
	// and then saves it to the database
	// For now we will not query the database and always try to download the chain
	prevParentLink := ""
	parentLink := link
	chain := make([]*cert.ParsedCert, 0)
	for parentLink != "" && parentLink != prevParentLink {
		if s.LinkExists(parentLink) {
			log.Printf("Link %s already exists, skipping", parentLink)
			break
		}
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
		certs, err := s.loadCerts(c, resp.Body)
		if err != nil {
			log.Printf("Error loading certificates from response body: %s", err)
			return nil, err
		}
		if len(certs) == 0 {
			log.Printf("No certificates found in certificate chain response")
			return nil, errors.New("no certificates found in certificate chain response")
		}
		for _, crt := range certs {
			for _, link := range crt.Cert.IssuingCertificateURL {
				if s.LinkExists(link) {
					log.Printf("Link %s already exists, skipping", link)
					return chain, nil
				}
				s.addLink(link)
				chain = append(chain, crt)
			}
			// Add the certificate to the intermediate pool
			s.AddIntermediate(crt.Cert)
			log.Printf("Added certificate with SHA256 %s to the intermediate pool", crt.Sha256())
		}
		parentCert := certs[len(certs)-1].Cert // Get the last certificate in the chain
		if len(parentCert.IssuingCertificateURL) == 0 {
			log.Printf("No parent certificate link found in the last certificate of the chain")
			break
		}
		parentLink = certs[len(certs)-1].Cert.IssuingCertificateURL[0] // Get the parent link from the last certificate in the chain
	}
	return chain, nil
}

func (s *VerifySvc) loadCerts(c *gin.Context, body io.ReadCloser) ([]*cert.ParsedCert, error) {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		log.Printf("Error reading response body: %s", err)
		return nil, err
	}
	certs, err := cert.ParseCerts(bodyBytes)
	if err != nil {
		log.Printf("Error parsing certificate: %s", err)
		return nil, err
	}
	return certs, nil
}

func (s *VerifySvc) getScopes(c *gin.Context, crt *cert.ParsedCert, tpp *models.TPP) map[string][]string {
	certServices := getCertServices(*crt)
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

func getCertServices(crt cert.ParsedCert) []models.Service {
	services := make([]models.Service, 0)
	scopes, err := crt.OBScopes()
	if err != nil {
		log.Printf("Error getting OB scopes from certificate: %s", err)
		return nil
	}
	for _, scope := range scopes {
		switch scope {
		case models.ScopePIS:
			services = append(services, models.PISP)
		case models.ScopeAIS:
			services = append(services, models.AISP)
		default:
			log.Printf("Unknown scope in certificate: %s", scope)
			continue
		}
	}
	return services
}
