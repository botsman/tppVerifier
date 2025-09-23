package certdb

import (
	"github.com/botsman/tppVerifier/app/models"
)

type TrustServiceStatusList struct {
	TrustServiceProviders []TrustServiceProvider `xml:"TrustServiceProviderList>TrustServiceProvider"`
}

type TrustServiceProvider struct {
	TSPServices []TSPService `xml:"TSPServices>TSPService"`
}

type TSPService struct {
	ServiceInformation ServiceInformation `xml:"ServiceInformation"`
}

type ServiceInformation struct {
	ServiceStatus                string                       `xml:"ServiceStatus"`
	ServiceTypeIdentifier        string                       `xml:"ServiceTypeIdentifier"`
	ServiceInformationExtensions ServiceInformationExtensions `xml:"ServiceInformationExtensions"`
	ServiceDigitalIdentity       ServiceDigitalIdentity       `xml:"ServiceDigitalIdentity"`
}

func (si ServiceInformation) isValidStatus() bool {
	return si.ServiceStatus == "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
}

func (si ServiceInformation) getType() models.CertUsage {
	for _, ext := range si.ServiceInformationExtensions.Extensions {
		if ext.AdditionalServiceInformation.URI == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication" {
			return models.QWAC
		}
		if ext.AdditionalServiceInformation.URI == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals" {
			return models.QSEAL
		}
	}
	return ""
}

func (si ServiceInformation) getPemCert() string {
	for _, di := range si.ServiceDigitalIdentity.DigitalIds {
		if di.X509Certificate != "" {
			return di.X509Certificate
		}
	}
	return ""
}

type ServiceInformationExtensions struct {
	Extensions []Extension `xml:"Extension"`
}

type Extension struct {
	AdditionalServiceInformation AdditionalServiceInformation `xml:"AdditionalServiceInformation"`
}

type AdditionalServiceInformation struct {
	URI string `xml:"URI"`
}

type ServiceDigitalIdentity struct {
	DigitalIds []DigitalId `xml:"DigitalId"`
}

type DigitalId struct {
	X509Certificate string `xml:"X509Certificate"`
}
