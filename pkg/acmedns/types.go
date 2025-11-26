package acmedns

import (
	"github.com/google/uuid"
)

type Account struct {
	Username  string
	Password  string
	Subdomain string
}

// AcmeDnsConfig holds the config structure
type AcmeDnsConfig struct {
	General   general    `toml:"general" validate:"required"`
	Database  dbsettings `toml:"database" validate:"required"`
	API       httpapi    `toml:"api" validate:"required"`
	Logconfig logconfig  `toml:"logconfig" validate:"required"`
}

// Config file general section
type general struct {
	Listen        string   `toml:"listen" validate:"required"`
	Proto         string   `toml:"protocol" validate:"required,oneof=both both4 both6 udp udp4 udp6 tcp tcp4 tcp6"`
	Domain        string   `toml:"domain" validate:"required,fqdn"`
	Nsname        string   `toml:"nsname" validate:"required,fqdn"`
	Nsadmin       string   `toml:"nsadmin" validate:"required"`
	Debug         bool     `toml:"debug"`
	DoTListen     string   `toml:"dot_listen"`
	TlsCertFile   string   `toml:"tls_cert_filepath"`
	TlsKeyFile    string   `toml:"tls_key_filepath"`
	StaticRecords []string `toml:"records" validate:"required,dive,required"`
}

type dbsettings struct {
	Engine     string `toml:"engine" validate:"required,oneof=sqlite sqlite3 postgres"`
	Connection string `toml:"connection" validate:"required"`
}

// API config
type httpapi struct {
	Domain              string   `toml:"api_domain"`
	IP                  string   `toml:"ip" validate:"required,ip"`
	DisableRegistration bool     `toml:"disable_registration"`
	AutocertPort        string   `toml:"autocert_port"`
	Port                string   `toml:"port" validate:"required,numeric"`
	TLS                 string   `toml:"tls" validate:"required,oneof=letsencrypt letsencryptstaging cert none"`
	TLSCertPrivkey      string   `toml:"tls_cert_privkey"`
	TLSCertFullchain    string   `toml:"tls_cert_fullchain"`
	ACMECacheDir        string   `toml:"acme_cache_dir"`
	NotificationEmail   string   `toml:"notification_email" validate:"omitempty,email"`
	CorsOrigins         []string `toml:"corsorigins" validate:"required"`
	UseHeader           bool     `toml:"use_header"`
	HeaderName          string   `toml:"header_name"`
}

// Logging config
type logconfig struct {
	Level   string `toml:"loglevel" validate:"required,oneof=error warning info debug"`
	Logtype string `toml:"logtype" validate:"required,oneof=stdout file both"`
	File    string `toml:"logfile"`
	Format  string `toml:"logformat" validate:"required,oneof=json text"`
}

// ACMETxt is the default structure for the user controlled record
type ACMETxt struct {
	Username uuid.UUID
	Password string
	ACMETxtPost
	AllowFrom Cidrslice
}

// ACMETxtPost holds the DNS part of the ACMETxt struct
type ACMETxtPost struct {
	Subdomain string `json:"subdomain"`
	Value     string `json:"txt"`
}
