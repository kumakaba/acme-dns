package acmedns

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/go-playground/validator/v10"
)

const (
	ApiTlsProviderNone               = "none"
	ApiTlsProviderLetsEncrypt        = "letsencrypt"
	ApiTlsProviderLetsEncryptStaging = "letsencryptstaging"
	ApiTlsProviderCert               = "cert"
)

func FileIsAccessible(fname string) bool {
	_, err := os.Stat(fname)
	if err != nil {
		return false
	}
	f, err := os.Open(fname)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func readTomlConfig(fname string) (AcmeDnsConfig, error) {
	var conf AcmeDnsConfig
	_, err := toml.DecodeFile(fname, &conf)
	if err != nil {
		// Return with config file parsing errors from toml package
		return conf, err
	}
	return prepareConfig(conf)
}

// prepareConfig checks that mandatory values exist, and can be used to set default values in the future
func prepareConfig(conf AcmeDnsConfig) (AcmeDnsConfig, error) {

	// Default values for options added to config to keep backwards compatibility with old config
	if conf.API.ACMECacheDir == "" {
		conf.API.ACMECacheDir = "api-certs"
	}

	conf.General.Nsadmin = strings.ReplaceAll(conf.General.Nsadmin, "@", ".")

	if conf.Database.Engine == "" {
		return conf, errors.New("missing database configuration option \"engine\"")
	}
	// Use sqlite if the database is not postgres
	// Note: Some users mistakenly specify 'sqlite3', so we treat it as 'sqlite'
	if conf.Database.Engine != "postgres" {
		conf.Database.Engine = "sqlite"
	}

	if conf.Database.Connection == "" {
		return conf, errors.New("missing database configuration option \"connection\"")
	}

	switch conf.API.TLS {
	case ApiTlsProviderCert, ApiTlsProviderLetsEncrypt, ApiTlsProviderLetsEncryptStaging, ApiTlsProviderNone:
		// we have a good value
	default:
		return conf, fmt.Errorf("invalid value for api.tls, expected one of [%s, %s, %s, %s]", ApiTlsProviderCert, ApiTlsProviderLetsEncrypt, ApiTlsProviderLetsEncryptStaging, ApiTlsProviderNone)
	}

	return conf, nil
}

func ReadConfig(configFile, fallback string) (AcmeDnsConfig, string, error) {
	var usedConfigFile string
	var config AcmeDnsConfig
	var err error
	if FileIsAccessible(configFile) {
		usedConfigFile = configFile
		config, err = readTomlConfig(configFile)
	} else if FileIsAccessible(fallback) {
		usedConfigFile = fallback
		config, err = readTomlConfig(fallback)
	} else {
		err = fmt.Errorf("configuration file not found")
	}
	if err != nil {
		err = fmt.Errorf("encountered an error while trying to read configuration file:  %w", err)
	}

	// Validation
	validate := validator.New()
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		// get toml-tag
		name := strings.SplitN(fld.Tag.Get("toml"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
	verr := validate.Struct(config)
	if verr != nil {
		if validationErrors, ok := verr.(validator.ValidationErrors); ok {
			for _, fieldError := range validationErrors {
				ns := fieldError.Namespace()
				ns = strings.TrimPrefix(ns, "AcmeDnsConfig.")
				parts := strings.Split(ns, ".")
				formattedName := ""
				if len(parts) > 1 && len(parts) < 5 {
					section := strings.Join(parts[:len(parts)-1], ".")
					key := parts[len(parts)-1]
					formattedName = fmt.Sprintf("[%s] %s", section, key)
				} else {
					formattedName = ns
				}
				fmt.Printf("configuration validation error: %s (%s)\n", formattedName, fieldError.Tag())
			}
		}
		return config, usedConfigFile, errors.New("configuration validation error")
	}

	return config, usedConfigFile, err
}
