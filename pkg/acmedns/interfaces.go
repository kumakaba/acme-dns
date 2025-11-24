package acmedns

import (
	"context"

	"database/sql"

	"github.com/google/uuid"
)

type AcmednsDB interface {
	Register(ctx context.Context, cidrslice Cidrslice) (ACMETxt, error)
	GetByUsername(ctx context.Context, u uuid.UUID) (ACMETxt, error)
	GetTXTForDomain(ctx context.Context, domain string) ([]string, error)
	Update(ctx context.Context, a ACMETxtPost) error
	GetBackend() *sql.DB
	SetBackend(*sql.DB)
	Close()
	GetDBVersion() int
}

type AcmednsNS interface {
	Start(errorChannel chan error)
	SetOwnAuthKey(key string)
	SetNotifyStartedFunc(func())
	ParseRecords()
	Shutdown(ctx context.Context) error
	GetVersion() string
}
