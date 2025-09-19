package certsdb

import (
	"context"
	"github.com/botsman/tppVerifier/app/cert"
)

import "time"

type CertDb interface {
	SaveCert(ctx context.Context, cert *cert.ParsedCert) error
	CleanupInactive(ctx context.Context, now time.Time) (int64, error)
	Disconnect(ctx context.Context) error
}
