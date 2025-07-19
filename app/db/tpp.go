package db

import (
	"context"

	"github.com/botsman/tppVerifier/app/models"
	"github.com/botsman/tppVerifier/app/cert"
)

type TppRepository interface {
	GetTpp(ctx context.Context, id string) (*models.TPP, error)
	GetRootCertificates(ctx context.Context) ([]string, error)
	AddIntermediateCertificate(ctx context.Context, cert *cert.ParsedCert) error
}
