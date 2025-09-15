package db

import (
	"context"

	"github.com/botsman/tppVerifier/app/cert"
	"github.com/botsman/tppVerifier/app/models"
)

type TppRepository interface {
	GetTpp(ctx context.Context, id string) (*models.TPP, error)
	GetRootCertificates(ctx context.Context) ([]string, error)
	AddCertificate(ctx context.Context, cert *cert.ParsedCert) error
}
