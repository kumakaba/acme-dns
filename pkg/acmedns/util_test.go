package acmedns

import (
	"fmt"
	"math/rand/v2"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/bcrypt"
)

func fakeConfig() AcmeDnsConfig {
	conf := AcmeDnsConfig{}
	conf.Logconfig.Logtype = "stdout"
	return conf
}

func TestSetupLogging(t *testing.T) {
	conf := fakeConfig()
	for i, test := range []struct {
		format   string
		level    string
		expected zapcore.Level
	}{
		{"text", "warn", zap.WarnLevel},
		{"json", "debug", zap.DebugLevel},
		{"text", "info", zap.InfoLevel},
		{"json", "error", zap.ErrorLevel},
		{"text", "debug", zap.DebugLevel},
		{"json", "info", zap.InfoLevel},
	} {
		conf.Logconfig.Format = test.format
		conf.Logconfig.Level = test.level
		logger, err := SetupLogging(conf)
		if err != nil {
			t.Errorf("Got unexpected error: %s", err)
		} else {
			if logger.Sugar().Level() != test.expected {
				t.Errorf("Test %d: Expected loglevel %s but got %s", i, test.expected, logger.Sugar().Level())
			}
		}
	}
}

func TestSetupLoggingError(t *testing.T) {
	conf := fakeConfig()
	for _, test := range []struct {
		format      string
		level       string
		file        string
		both        bool
		errexpected bool
	}{
		{"text", "warn", "", false, false},
		{"json", "debug", "", false, false},
		{"text", "info", "", false, false},
		{"json", "error", "", false, false},
		{"text", "something", "", false, true},
		{"text", "info", "a path with\" in its name.txt", false, false},
		{"text", "something", "", true, true},
		{"json", "info", "a path with\" in its name.txt", true, false},
	} {
		conf.Logconfig.Format = test.format
		conf.Logconfig.Level = test.level
		if test.file != "" {
			conf.Logconfig.File = test.file
			conf.Logconfig.Logtype = "file"
		}
		if test.both {
			conf.Logconfig.Logtype = "both"
		}
		_, err := SetupLogging(conf)
		if test.errexpected && err == nil {
			t.Errorf("Expected error but did not get one for loglevel: %s", err)
		} else if !test.errexpected && err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		// clean up the file zap creates
		if test.file != "" {
			_ = os.Remove(test.file)
		}
	}
}

func TestReadConfig(t *testing.T) {
	for i, test := range []struct {
		inFile []byte
		output AcmeDnsConfig
	}{
		{
			[]byte("[general]\nlisten = \":53\"\ndebug = true\n[api]\napi_domain = \"something.strange\""),
			AcmeDnsConfig{
				General: general{
					Listen: ":53",
					Debug:  true,
				},
				API: httpapi{
					Domain: "something.strange",
				},
			},
		},

		{
			[]byte("[\x00[[[[[[[[[de\nlisten =]"),
			AcmeDnsConfig{},
		},
	} {
		tmpfile, err := os.CreateTemp("", "acmedns")
		if err != nil {
			t.Fatalf("Could not create temporary file: %s", err)
		}
		defer os.Remove(tmpfile.Name())

		if _, err := tmpfile.Write(test.inFile); err != nil {
			t.Error("Could not write to temporary file")
		}

		if err := tmpfile.Close(); err != nil {
			t.Error("Could not close temporary file")
		}
		ret, _, _ := ReadConfig(tmpfile.Name(), "")
		if ret.General.Listen != test.output.General.Listen {
			t.Errorf("Test %d: Expected listen value %s, but got %s", i, test.output.General.Listen, ret.General.Listen)
		}
		if ret.API.Domain != test.output.API.Domain {
			t.Errorf("Test %d: Expected HTTP API domain %s, but got %s", i, test.output.API.Domain, ret.API.Domain)
		}
	}
}

func TestReadConfigNotFallbackAtEmptyPath(t *testing.T) {
	var (
		path string
		err  error
	)

	testPath := "testdata/test_read_fallback_config.toml"

	path, err = getNonExistentPath()
	if err != nil {
		t.Errorf("failed getting non existant path: %s", err)
	}

	// Does not fallback if filepath is specified
	_, _, err = ReadConfig(path, testPath)
	if err == nil {
		t.Fatalf("Expect error configuration file not found, but noerror")
	}

}

func TestReadConfigFallback(t *testing.T) {
	var (
		err error
	)

	testPath := "testdata/test_read_fallback_config.toml"

	// fallback if filepath is empty
	cfg, used, err := ReadConfig("", testPath)
	if err != nil {
		t.Fatalf("failed to read a config file when we should have: %s", err)
	}

	if used != testPath {
		t.Fatalf("we read from the wrong file. got: %s, want: %s", used, testPath)
	}

	expected := AcmeDnsConfig{
		General: general{
			Listen:  "127.0.0.1:53",
			Proto:   "both",
			Domain:  "test.example.org",
			Nsname:  "test.example.org",
			Nsadmin: "test.example.org",
			Debug:   true,
			StaticRecords: []string{
				"test.example.org. A 127.0.0.1",
				"test.example.org. NS test.example.org.",
			},
		},
		Database: dbsettings{
			Engine:     "sqlite",
			Connection: "roar",
		},
		API: httpapi{
			Domain:              "",
			IP:                  "0.0.0.0",
			DisableRegistration: false,
			AutocertPort:        "",
			Port:                "443",
			TLS:                 "none",
			TLSCertPrivkey:      "/etc/tls/example.org/privkey.pem",
			TLSCertFullchain:    "/etc/tls/example.org/fullchain.pem",
			ACMECacheDir:        "api-certs",
			NotificationEmail:   "",
			CorsOrigins:         []string{"*"},
			UseHeader:           true,
			HeaderName:          "X-is-gonna-give-it-to-ya",
		},
		Logconfig: logconfig{
			Level:   "info",
			Logtype: "stdout",
			File:    "./acme-dns.log",
			Format:  "json",
		},
	}

	if !reflect.DeepEqual(cfg, expected) {
		t.Errorf("Did not read the config correctly: got %+v, want: %+v", cfg, expected)
	}

}

func TestReadConfigFallback2(t *testing.T) {
	var (
		err error
	)

	testPath := "testdata/test_read_fallback_config2.toml"

	// fallback if filepath is empty
	cfg, used, err := ReadConfig("", testPath)
	if err != nil {
		t.Fatalf("failed to read a config file when we should have: %s", err)
	}

	if used != testPath {
		t.Fatalf("we read from the wrong file. got: %s, want: %s", used, testPath)
	}

	expected := AcmeDnsConfig{
		General: general{
			Listen:  "127.0.0.1:53",
			Proto:   "both",
			Domain:  "test.example.org",
			Nsname:  "test.example.org",
			Nsadmin: "test.example.org",
			Debug:   false,
			StaticRecords: []string{
				"test.example.org. A 127.0.0.1",
				"test.example.org. NS test.example.org.",
			},
		},
		Database: dbsettings{
			Engine:     "postgres",
			Connection: "wong",
		},
		API: httpapi{
			Domain:              "",
			IP:                  "0.0.0.0",
			DisableRegistration: true,
			AutocertPort:        "",
			Port:                "443",
			TLS:                 "none",
			TLSCertPrivkey:      "/etc/tls/example.org/privkey.pem",
			TLSCertFullchain:    "/etc/tls/example.org/fullchain.pem",
			ACMECacheDir:        "api-certs",
			NotificationEmail:   "",
			CorsOrigins:         []string{"*"},
			UseHeader:           false,
			HeaderName:          "X-is-gonna-give-it-to-ya",
		},
		Logconfig: logconfig{
			Level:   "info",
			Logtype: "both",
			File:    "./acme-dns.log",
			Format:  "text",
		},
	}

	if !reflect.DeepEqual(cfg, expected) {
		t.Errorf("Did not read the config correctly: got %+v, want: %+v", cfg, expected)
	}
}

func TestReadConfigValidationError(t *testing.T) {
	var (
		err error
	)

	testPath := "testdata/test_read_validationerror_config.toml"

	cfg, used, err := ReadConfig("", testPath)
	if err == nil {
		t.Fatal("Expect validation error, but not error")
	}
	// check prepareConfig error
	if !strings.Contains(err.Error(), "encountered an error while trying to read") {
		t.Errorf("Expected validation message, got: %s", err)
	}
	if used != testPath {
		t.Errorf("Expect use testPath, but %v", used)
	}
	if cfg.General.Nsadmin != "replace_at_to_dot.hoge.example.com" {
		t.Errorf("Expect replaced nsadmin strings, but %s", cfg.General.Nsadmin)
	}
}

func TestReadConfigValidationErrorOfValidator(t *testing.T) {
	var (
		err error
	)

	testPath := "testdata/test_read_validationerror_config2.toml"

	_, used, err := ReadConfig("", testPath)
	if err == nil {
		t.Fatal("Expect validation error, but not error")
	}
	if !strings.Contains(err.Error(), "validation") {
		t.Errorf("Expected validation message, got: %s", err)
	}
	if used != testPath {
		t.Errorf("Expect use testPath, but %v", used)
	}
}

func getNonExistentPath() (string, error) {
	path := fmt.Sprintf("/some/path/that/should/not/exist/on/any/filesystem/%10d.cfg", rand.Int())

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path, nil
	}

	return "", fmt.Errorf("attempted non existant file exists!?: %s", path)
}

// TestReadConfigFallbackError makes sure we error when we do not have a fallback config file
func TestReadConfigFallbackError(t *testing.T) {
	var (
		badPaths []string
		i        int
	)
	for len(badPaths) < 2 && i < 10 {
		i++

		if path, err := getNonExistentPath(); err == nil {
			badPaths = append(badPaths, path)
		}
	}

	if len(badPaths) != 2 {
		t.Fatalf("did not create exactly 2 bad paths")
	}

	// Extract configuration file not found (badPaths[0] not empty)
	_, used, err := ReadConfig(badPaths[0], badPaths[1])
	if err == nil {
		t.Fatalf("Should have error reading non existant file: %s", err)
	}
	if !strings.Contains(err.Error(), "configuration file not found") {
		t.Errorf("Expected not found message, got: %s", err)
	}
	if used != badPaths[0] {
		t.Errorf("Should have same usedconfig reading non existant file: %s", used)
	}

	// Extract configuration file not found (badPaths[0] empty)
	_, used, err = ReadConfig("", badPaths[1])
	if err == nil {
		t.Fatalf("Should have error reading non existant file: %s", err)
	}
	// t.Errorf("[%+v]",  err)
	if !strings.Contains(err.Error(), "configuration file not found") {
		t.Errorf("Expected not found message, got: %s", err)
	}
	if used != badPaths[1] {
		t.Errorf("Should have same usedconfig reading non existant file: %s", used)
	}
}

func TestFileCheckPermissionDenied(t *testing.T) {
	uid := syscall.Getuid()
	if uid == 0 {
		t.Skip("Skipping permission denial test as root user can bypass 0000 permissions.")
		return
	}
	tmpfile, err := os.CreateTemp("", "acmedns")
	if err != nil {
		t.Fatalf("Could not create temporary file: %s", err)
	}
	defer os.Remove(tmpfile.Name())
	_ = syscall.Chmod(tmpfile.Name(), 0000)
	if FileIsAccessible(tmpfile.Name()) {
		t.Errorf("File should not be accessible")
	}
	_ = syscall.Chmod(tmpfile.Name(), 0644)
}

func TestFileCheckNotExists(t *testing.T) {
	if FileIsAccessible("/path/that/does/not/exist") {
		t.Errorf("File should not be accessible")
	}
}

func TestFileCheckOK(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "acmedns")
	if err != nil {
		t.Fatalf("Could not create temporary file: %s", err)
	}
	defer os.Remove(tmpfile.Name())
	if !FileIsAccessible(tmpfile.Name()) {
		t.Errorf("File should be accessible")
	}
}

func TestPrepareConfig(t *testing.T) {
	for i, test := range []struct {
		input       AcmeDnsConfig
		shoulderror bool
	}{
		{AcmeDnsConfig{
			Database: dbsettings{Engine: "whatever", Connection: "whatever_too"},
			API:      httpapi{TLS: ApiTlsProviderNone},
		}, false},
		{AcmeDnsConfig{Database: dbsettings{Engine: "", Connection: "whatever_too"},
			API: httpapi{TLS: ApiTlsProviderNone},
		}, true},
		{AcmeDnsConfig{Database: dbsettings{Engine: "whatever", Connection: ""},
			API: httpapi{TLS: ApiTlsProviderNone},
		}, true},
		{AcmeDnsConfig{
			Database: dbsettings{Engine: "whatever", Connection: "whatever_too"},
			API:      httpapi{TLS: "whatever"},
		}, true},
	} {
		_, err := prepareConfig(test.input)
		if test.shoulderror {
			if err == nil {
				t.Errorf("Test %d: Expected error with prepareConfig input data [%v]", i, test.input)
			}
		} else {
			if err != nil {
				t.Errorf("Test %d: Expected no error with prepareConfig input data [%v]", i, test.input)
			}
		}
	}
}

func TestSanitizeString(t *testing.T) {
	for i, test := range []struct {
		input    string
		expected string
	}{
		{"abcd!abcd", "abcdabcd"},
		{"ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz0123456789", "ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz0123456789"},
		{"ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopq=@rstuvwxyz0123456789", "ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz0123456789"},
	} {
		if SanitizeString(test.input) != test.expected {
			t.Errorf("Expected SanitizeString to return %s for test %d, but got %s instead", test.expected, i, SanitizeString(test.input))
		}
	}
}

func TestCorrectPassword(t *testing.T) {
	testPass, _ := bcrypt.GenerateFromPassword([]byte("nevergonnagiveyouup"), 10)
	for i, test := range []struct {
		input    string
		expected bool
	}{
		{"abcd", false},
		{"nevergonnagiveyouup", true},
		{"@rstuvwxyz0123456789", false},
	} {
		if test.expected && !CorrectPassword(test.input, string(testPass)) {
			t.Errorf("Expected CorrectPassword to return %t for test %d", test.expected, i)
		}
		if !test.expected && CorrectPassword(test.input, string(testPass)) {
			t.Errorf("Expected CorrectPassword to return %t for test %d", test.expected, i)
		}
	}
}
