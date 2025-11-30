package nameserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"

	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"sync"
	"testing"

	"net"
	"os"
	"time"

	"github.com/erikstmartin/go-testdb"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/kumakaba/acme-dns/pkg/acmedns"
	"github.com/kumakaba/acme-dns/pkg/database"
)

type resolver struct {
	server string
}

var records = []string{
	"auth.example.org. A 192.168.1.100",
	"ns1.auth.example.org. A 192.168.1.101",
	"cn.example.org CNAME something.example.org.",
	"!''b', unparseable ",
	"ns2.auth.example.org. A 192.168.1.102",
}

func loggerHasEntryWithMessage(message string, logObserver *observer.ObservedLogs) bool {
	return len(logObserver.FilterMessage(message).All()) > 0
}

func fakeConfigAndLogger() (acmedns.AcmeDnsConfig, *zap.SugaredLogger, *observer.ObservedLogs) {
	c := acmedns.AcmeDnsConfig{}
	c.Database.Engine = "sqlite"
	c.Database.Connection = ":memory:"
	obsCore, logObserver := observer.New(zap.DebugLevel)
	obsLogger := zap.New(obsCore).Sugar()
	return c, obsLogger, logObserver
}

func setupDNS() (acmedns.AcmednsNS, acmedns.AcmednsDB, *observer.ObservedLogs) {
	config, logger, logObserver := fakeConfigAndLogger()
	config.General.Domain = "auth.example.org"
	config.General.Listen = "127.0.0.1:15353"
	config.General.Proto = "udp"
	config.General.Nsname = "ns1.auth.example.org"
	config.General.Nsadmin = "admin.example.org"
	config.General.StaticRecords = records
	config.General.Debug = false
	db, _ := database.Init(&config, logger)
	server := Nameserver{Config: &config, DB: db, Logger: logger, personalAuthKey: ""}
	server.Domains = make(map[string]Records)
	server.Server = &dns.Server{Addr: config.General.Listen, Net: config.General.Proto}
	server.ParseRecords()
	server.OwnDomain = "auth.example.org."
	server.version = "v0.0.0-fake-version"
	return &server, db, logObserver
}

func startTestDNS(t *testing.T) (acmedns.AcmednsNS, acmedns.AcmednsDB, *observer.ObservedLogs) {
	server, db, logObserver := setupDNS()
	errChan := make(chan error, 1)
	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.SetNotifyStartedFunc(waitLock.Unlock)
	go server.Start(errChan)
	t.Cleanup(func() {
		if ns, ok := server.(*Nameserver); ok {
			_ = ns.Shutdown(t.Context())
		}
	})
	waitLock.Lock()
	return server, db, logObserver
}

func (r *resolver) lookup(host string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{Name: dns.Fqdn(host), Qtype: qtype, Qclass: dns.ClassINET}
	in, err := dns.Exchange(msg, r.server)
	if err != nil {
		return in, fmt.Errorf("Error querying the server [%v]", err)
	}
	if in != nil && in.Rcode != dns.RcodeSuccess {
		return in, fmt.Errorf("Received error from the server [%s]", dns.RcodeToString[in.Rcode])
	}
	return in, nil
}

func TestCheckVersion(t *testing.T) {
	server, _, _ := setupDNS()

	ns, ok := server.(*Nameserver)
	if !ok {
		t.Fatal("Could not cast interface to *Nameserver")
	}

	ver := ns.GetVersion()

	if ver != "v0.0.0-fake-version" {
		t.Errorf("Expected server version string, but got %s", ver)
	}
}

func TestShutdownNilServer(t *testing.T) {
	ns := &Nameserver{
		Server: nil,
	}

	err := ns.Shutdown(t.Context())

	if err != nil {
		t.Errorf("Expected nil error when shutting down nil server, but got %v", err)
	}
}

func TestShutdownError(t *testing.T) {
	server, _, _ := setupDNS()

	ns, ok := server.(*Nameserver)
	if !ok {
		t.Fatal("Could not cast interface to *Nameserver")
	}

	err := ns.Shutdown(t.Context())

	if err == nil {
		t.Error("Expected error 'dns: not started', but got nil")
		return
	}

	expectedMsg := "dns: server not started"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error %q, but got %q", expectedMsg, err.Error())
	}
}

func TestQuestionDBError(t *testing.T) {
	config, logger, _ := fakeConfigAndLogger()
	config.General.Listen = "127.0.0.1:15353"
	config.General.Proto = "udp"
	config.General.Domain = "auth.example.org"
	config.General.Nsname = "ns1.auth.example.org"
	config.General.Nsadmin = "admin.example.org"
	config.General.StaticRecords = records
	config.General.Debug = false
	db, _ := database.Init(&config, logger)
	server := Nameserver{Config: &config, DB: db, Logger: logger, personalAuthKey: ""}
	server.Domains = make(map[string]Records)
	server.ParseRecords()
	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{"Username", "Password", "Subdomain", "Value", "LastActive"}
		return testdb.RowsFromSlice(columns, [][]driver.Value{}), errors.New("Prepared query error")
	})

	defer testdb.Reset()

	tdb, err := sql.Open("testdb", "")
	if err != nil {
		t.Errorf("Got error: %v", err)
	}
	oldDb := db.GetBackend()

	db.SetBackend(tdb)
	defer db.SetBackend(oldDb)

	q := dns.Question{Name: dns.Fqdn("whatever.tld"), Qtype: dns.TypeTXT, Qclass: dns.ClassINET}
	_, err = server.answerTXT(t.Context(), q)
	if err == nil {
		t.Errorf("Expected error but got none")
	}
}

func TestParse(t *testing.T) {
	config, logger, logObserver := fakeConfigAndLogger()
	config.General.Listen = "127.0.0.1:15353"
	config.General.Proto = "udp"
	config.General.Domain = ")"
	config.General.Nsname = "ns1.auth.example.org"
	config.General.Nsadmin = "admin.example.org"
	config.General.StaticRecords = records
	config.General.Debug = false
	config.General.StaticRecords = []string{}
	db, _ := database.Init(&config, logger)
	server := Nameserver{Config: &config, DB: db, Logger: logger, personalAuthKey: ""}
	server.Domains = make(map[string]Records)
	server.ParseRecords()
	if !loggerHasEntryWithMessage("Error while adding SOA record", logObserver) {
		t.Errorf("Expected SOA parsing to return error, but did not find one")
	}
}

func TestResolveA(t *testing.T) {
	_, _, _ = startTestDNS(t)
	resolv := resolver{server: "127.0.0.1:15353"}
	answer, err := resolv.lookup("auth.example.org", dns.TypeA)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	if len(answer.Answer) == 0 {
		t.Error("No answer for DNS query")
		return
	}

	_, err = resolv.lookup("nonexistent.domain.tld", dns.TypeA)
	if err == nil {
		t.Errorf("Was expecting error because of NXDOMAIN but got none")
		return
	}
}

func TestEDNS(t *testing.T) {
	_, _, _ = startTestDNS(t)
	resolv := resolver{server: "127.0.0.1:15353"}
	answer, _ := resolv.lookup("auth.example.org", dns.TypeOPT)
	if answer.Rcode != dns.RcodeSuccess {
		t.Errorf("Was expecing NOERROR rcode for OPT query, but got [%s] instead.", dns.RcodeToString[answer.Rcode])
	}
}

func TestEDNSA(t *testing.T) {
	_, _, _ = startTestDNS(t)
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{Name: dns.Fqdn("auth.example.org"), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	// Set EDNS0 with DO=1
	msg.SetEdns0(512, true)
	in, err := dns.Exchange(msg, "127.0.0.1:15353")
	if err != nil {
		t.Errorf("Error querying the server [%v]", err)
	}
	if in != nil && in.Rcode != dns.RcodeSuccess {
		t.Errorf("Received error from the server [%s]", dns.RcodeToString[in.Rcode])
	}
	opt := in.IsEdns0()
	if opt == nil {
		t.Errorf("Should have got OPT back")
	}
}

func TestEDNSBADVERS(t *testing.T) {
	_, _, _ = startTestDNS(t)
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{Name: dns.Fqdn("auth.example.org"), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	// Set EDNS0 with version 1
	o := new(dns.OPT)
	o.SetVersion(1)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	msg.Extra = append(msg.Extra, o)
	in, err := dns.Exchange(msg, "127.0.0.1:15353")
	if err != nil {
		t.Errorf("Error querying the server [%v]", err)
	}
	if in != nil && in.Rcode != dns.RcodeBadVers {
		t.Errorf("Received unexpected rcode from the server [%s]", dns.RcodeToString[in.Rcode])
	}
}

func TestResolveCNAME(t *testing.T) {
	_, _, _ = startTestDNS(t)
	resolv := resolver{server: "127.0.0.1:15353"}
	expected := "cn.example.org.	3600	IN	CNAME	something.example.org."
	answer, err := resolv.lookup("cn.example.org", dns.TypeCNAME)
	if err != nil {
		t.Errorf("Got unexpected error: %s", err)
	}
	if len(answer.Answer) != 1 {
		t.Errorf("Expected exactly 1 RR in answer, but got %d instead.", len(answer.Answer))
	}
	if answer.Answer[0].Header().Rrtype != dns.TypeCNAME {
		t.Errorf("Expected a CNAME answer, but got [%s] instead.", dns.TypeToString[answer.Answer[0].Header().Rrtype])
	}
	if answer.Answer[0].String() != expected {
		t.Errorf("Expected CNAME answer [%s] but got [%s] instead.", expected, answer.Answer[0].String())
	}
}

func TestAuthoritative(t *testing.T) {
	_, _, _ = startTestDNS(t)
	resolv := resolver{server: "127.0.0.1:15353"}
	answer, _ := resolv.lookup("nonexistent.auth.example.org", dns.TypeA)
	if answer.Rcode != dns.RcodeNameError {
		t.Errorf("Was expecing NXDOMAIN rcode, but got [%s] instead.", dns.RcodeToString[answer.Rcode])
	}
	if len(answer.Ns) != 1 {
		t.Errorf("Was expecting exactly one answer (SOA) for invalid subdomain, but got %d", len(answer.Ns))
	}
	if answer.Ns[0].Header().Rrtype != dns.TypeSOA {
		t.Errorf("Was expecting SOA record as answer for NXDOMAIN but got [%s]", dns.TypeToString[answer.Ns[0].Header().Rrtype])
	}
	if !answer.Authoritative {
		t.Errorf("Was expecting authoritative bit to be set")
	}
	soa, _ := answer.Ns[0].(*dns.SOA)
	if soa.Hdr.Ttl != 1 {
		t.Errorf("Expected SOA TTL to be 1, but got %d", soa.Hdr.Ttl)
	}
	if soa.Minttl != 1 {
		t.Errorf("Expected SOA Minttl to be 1, but got %d", soa.Minttl)
	}
	// REFUSED test
	nanswer, _ := resolv.lookup("nonexsitent.nonauth.tld", dns.TypeA)
	if nanswer.Rcode != dns.RcodeRefused {
		t.Errorf("Was expecing REFUSED rcode, but got [%s] instead.", dns.RcodeToString[nanswer.Rcode])
	}
	if len(nanswer.Ns) > 0 {
		t.Errorf("Was expecting non authority (SOA) for refused, but got %d", len(nanswer.Ns))
	}
	if len(nanswer.Answer) > 0 {
		t.Errorf("Didn't expect answers for non authotitative domain query")
	}
	if nanswer.Authoritative {
		t.Errorf("Authoritative bit should not be set for non-authoritative domain.")
	}
}

func TestResolveTXT(t *testing.T) {
	_, db, _ := startTestDNS(t)
	resolv := resolver{server: "127.0.0.1:15353"}
	validTXT := "______________valid_response_______________"

	atxt, err := db.Register(t.Context(), acmedns.Cidrslice{})
	if err != nil {
		t.Errorf("Could not initiate db record: [%v]", err)
		return
	}
	atxt.Value = validTXT

	err = db.Update(t.Context(), atxt.ACMETxtPost)
	if err != nil {
		t.Errorf("Could not update db record: [%v]", err)
		return
	}

	for i, test := range []struct {
		subDomain   string
		expTXT      string
		getAnswer   bool
		getNodata   bool
		getSOA      bool
		validAnswer bool
	}{
		{"", "", true, true, true, false},
		{"ns1", "", true, true, true, false},
		{"ns2", "", true, true, true, false},
		{"nxdomain", "", false, false, true, false},
		{atxt.Subdomain, validTXT, true, false, false, true},
		{atxt.Subdomain, "invalid", true, false, false, false},
		{atxt.Subdomain, "", true, false, false, false},
		{"invalid0-52cc-4569-90c8-7a4b97c6eba8", validTXT, false, false, true, false},
	} {
		targetFQDN := "auth.example.org"
		if test.subDomain != "" {
			targetFQDN = test.subDomain + "." + targetFQDN
		}
		answer, err := resolv.lookup(targetFQDN, dns.TypeTXT)
		if err != nil {
			if answer.Rcode == dns.RcodeNameError {
				if !test.getAnswer {
					// got NXDOMAIN
					continue
				}
				t.Errorf("Test %d: Expected answer but got NXDOMAIN.", i)
				continue
			} else {
				if test.getAnswer {
					t.Fatalf("Test %d: Expected answer but got: %v", i, err)
				}
			}
		} else {
			if !test.getAnswer {
				t.Errorf("Test %d: Expected no answer, but got one.", i)
			}
		}

		if len(answer.Answer) > 0 {
			if test.getNodata {
				t.Errorf("Test %d: Expected NODATA, but got: [%q]", i, answer)
			}
			if !test.getAnswer && answer.Answer[0].Header().Rrtype != dns.TypeSOA {
				t.Errorf("Test %d: Expected no answer, but got: [%q]", i, answer)
			}
			if test.getAnswer {
				err = hasExpectedTXTAnswer(answer.Answer, test.expTXT)
				if err != nil {
					if test.validAnswer {
						t.Errorf("Test %d: %v", i, err)
					}
				} else {
					if !test.validAnswer {
						t.Errorf("Test %d: Answer was not expected to be valid, answer [%q], compared to [%s]", i, answer, test.expTXT)
					}
				}
			}
		} else {
			if !test.getNodata {
				if test.getAnswer {
					t.Errorf("Test %d: Expected answer, but didn't get one. (%d)", i, len(answer.Answer))
				}
			}
		}
		if test.getSOA {
			if len(answer.Ns) == 0 {
				t.Errorf("Test %d: Expected Authority SOA, but not exists", i)
			}

			soa, ok := answer.Ns[0].(*dns.SOA)
			if !ok {
				t.Fatalf("Test %d: Expected Authority record to be SOA, but got %T", i, answer.Ns[0])
			}

			if soa.Hdr.Ttl != 1 {
				t.Errorf("Test %d: Expected SOA TTL to be 1, but got %d", i, soa.Hdr.Ttl)
			}

			if soa.Minttl != 1 {
				t.Errorf("Test %d: Expected SOA Minttl to be 1, but got %d", i, soa.Minttl)
			}
		} else {
			if len(answer.Ns) > 0 {
				t.Errorf("Test %d: Expected not Authority SOA, but exists", i)
			}
		}
	}
}

func hasExpectedTXTAnswer(answer []dns.RR, cmpTXT string) error {
	for _, record := range answer {
		// We expect only one answer, so no need to loop through the answer slice
		if rec, ok := record.(*dns.TXT); ok {
			for _, txtValue := range rec.Txt {
				if txtValue == cmpTXT {
					return nil
				}
			}
		} else {
			errmsg := fmt.Sprintf("Got answer of unexpected type [%q]", answer[0])
			return errors.New(errmsg)
		}
	}
	return errors.New("Expected answer not found")
}

func TestCaseInsensitiveResolveA(t *testing.T) {
	_, _, _ = startTestDNS(t)
	resolv := resolver{server: "127.0.0.1:15353"}
	answer, err := resolv.lookup("aUtH.eXAmpLe.org", dns.TypeA)
	if err != nil {
		t.Errorf("%v", err)
	}

	if len(answer.Answer) == 0 {
		t.Error("No answer for DNS query")
	}
}

func TestCaseInsensitiveResolveSOA(t *testing.T) {
	_, _, _ = startTestDNS(t)
	resolv := resolver{server: "127.0.0.1:15353"}
	answer, _ := resolv.lookup("doesnotexist.aUtH.eXAmpLe.org", dns.TypeSOA)
	if answer.Rcode != dns.RcodeNameError {
		t.Errorf("Was expecing NXDOMAIN rcode, but got [%s] instead.", dns.RcodeToString[answer.Rcode])
	}

	if len(answer.Ns) == 0 {
		t.Fatalf("No SOA answer for DNS query")
	}

	soa, ok := answer.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("Expected Authority record to be SOA, but got %T", answer.Ns[0])
	}

	if soa.Hdr.Ttl != 1 {
		t.Errorf("Expected SOA TTL to be 1, but got %d", soa.Hdr.Ttl)
	}

	if soa.Minttl != 1 {
		t.Errorf("Expected SOA Minttl to be 1, but got %d", soa.Minttl)
	}
}

func TestNewDNSServerAllProto(t *testing.T) {
	config, logger, _ := fakeConfigAndLogger()
	config.General.Domain = "ExAmPlE.oRg"
	config.General.Listen = "127.0.0.1:15353"

	db, _ := database.Init(&config, logger)

	tests := []struct {
		name      string
		proto     string
		wantProto string
	}{
		{"UDPv4", "udp", "udp"},
		{"TCPv4", "tcp", "tcp"},
		{"DoT", "tcp-tls", "tcp-tls"}, // DoTの場合
		{"UDPv6", "udp6", "udp6"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nsInterface := NewDNSServer(&config, db, logger, tt.proto, "v1.0.0")

			ns, ok := nsInterface.(*Nameserver)
			if !ok {
				t.Fatal("NewDNSServer did not return *Nameserver struct")
			}

			if ns.Server.Net != tt.wantProto {
				t.Errorf("Expected Server.Net to be %q, got %q", tt.wantProto, ns.Server.Net)
			}

			if ns.Server.Addr != config.General.Listen {
				t.Errorf("Expected Server.Addr to be %q, got %q", config.General.Listen, ns.Server.Addr)
			}

			expectedDomain := "example.org."
			if ns.OwnDomain != expectedDomain {
				t.Errorf("Expected OwnDomain to be normalized to %q, got %q", expectedDomain, ns.OwnDomain)
			}

			if ns.Domains == nil {
				t.Error("Domains map was not initialized (is nil)")
			}

			if ns.GetVersion() == "" {
				t.Errorf("Expected version string, got empty")
			}
		})
	}
}

func TestInitAndStartSingleProtocols(t *testing.T) {

	config, logger, _ := fakeConfigAndLogger()
	config.General.Listen = "127.0.0.1:15353"
	config.General.Proto = "udp4"

	config.General.DoTListen = "127.0.0.1:28853"
	config.General.TlsCertFile = "/dev/null/non_existent_file"
	config.General.TlsKeyFile = "/dev/null/non_existent_file"

	db, _ := database.Init(&config, logger)

	errChan := make(chan error, 10)

	servers := InitAndStart(&config, db, logger, errChan, "vTest")

	t.Cleanup(func() {
		for _, s := range servers {
			if ns, ok := s.(*Nameserver); ok {
				_ = ns.Shutdown(t.Context())
			}
		}
	})

	expectedCount := 1
	if len(servers) != expectedCount {
		t.Errorf("Expected %d servers started, but got %d", expectedCount, len(servers))
	}

	protocols := make(map[string]bool)
	for _, s := range servers {
		ns := s.(*Nameserver)
		protocols[ns.Server.Net] = true
	}

	if !protocols["udp4"] {
		t.Error("UDP4 server not started")
	}
}

func TestInitAndStartBothProtocols(t *testing.T) {
	certPath, keyPath := generateSelfSignedCert(t)

	config, logger, _ := fakeConfigAndLogger()
	config.General.Listen = "127.0.0.1:15353"
	config.General.Proto = "both"

	config.General.DoTListen = "127.0.0.1:25853"
	config.General.TlsCertFile = certPath
	config.General.TlsKeyFile = keyPath

	db, _ := database.Init(&config, logger)

	errChan := make(chan error, 10)

	servers := InitAndStart(&config, db, logger, errChan, "vTest")

	t.Cleanup(func() {
		for _, s := range servers {
			if ns, ok := s.(*Nameserver); ok {
				_ = ns.Shutdown(t.Context())
			}
		}
	})

	expectedCount := 3
	if len(servers) != expectedCount {
		t.Errorf("Expected %d servers started, but got %d", expectedCount, len(servers))
	}

	protocols := make(map[string]bool)
	for _, s := range servers {
		ns := s.(*Nameserver)
		protocols[ns.Server.Net] = true
	}

	if !protocols["udp"] {
		t.Error("UDP server not started")
	}
	if !protocols["tcp"] {
		t.Error("TCP server not started")
	}

	if !protocols["tcp-tls"] && !protocols["tcp-tls4"] && !protocols["tcp-tls6"] {
		t.Error("DoT (tcp-tls) server not started")
	}
}

//////////////////////////////////////////////////
// DoT Test
//////////////////////////////////////////////////

func generateSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(1 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	tmpDir := t.TempDir()
	certFile, err := os.CreateTemp(tmpDir, "cert.pem")
	if err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	keyFile, err := os.CreateTemp(tmpDir, "key.pem")
	if err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("Failed to write cert pem: %v", err)
	}
	certFile.Close()

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		t.Fatalf("Failed to write key pem: %v", err)
	}
	keyFile.Close()

	return certFile.Name(), keyFile.Name()
}

func TestDoTResolve(t *testing.T) {
	certPath, keyPath := generateSelfSignedCert(t)

	config, logger, _ := fakeConfigAndLogger()
	config.General.Domain = "auth.example.org"
	config.General.Listen = "127.0.0.1:18853" // Use a different port for DoT test
	config.General.Proto = "tcp-tls"
	config.General.TlsCertFile = certPath
	config.General.TlsKeyFile = keyPath
	config.General.StaticRecords = records
	config.General.Nsname = "ns1.auth.example.org"
	config.General.Nsadmin = "admin.example.org"

	db, _ := database.Init(&config, logger)

	server := Nameserver{Config: &config, DB: db, Logger: logger, personalAuthKey: ""}
	server.Domains = make(map[string]Records)
	server.ParseRecords()
	server.OwnDomain = "auth.example.org."

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to load generated certs: %v", err)
	}

	server.Server = &dns.Server{
		Addr: config.General.Listen,
		Net:  "tcp-tls",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	errChan := make(chan error, 1)
	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.SetNotifyStartedFunc(waitLock.Unlock)

	go server.Start(errChan)

	t.Cleanup(func() {
		_ = server.Shutdown(t.Context())
	})

	waitLock.Lock()

	client := new(dns.Client)
	client.Net = "tcp-tls"

	// Important: Skip verification because we are using a self-signed cert
	client.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("auth.example.org"), dns.TypeA)
	in, _, err := client.Exchange(msg, config.General.Listen)

	if err != nil {
		t.Fatalf("DoT Exchange failed: %v", err)
	}
	if in == nil {
		t.Fatal("DoT Exchange returned nil message")
	}
	if in.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected RcodeSuccess, got %s", dns.RcodeToString[in.Rcode])
	}
	if len(in.Answer) == 0 {
		t.Error("No answer for DoT query")
	} else {
		if a, ok := in.Answer[0].(*dns.A); ok {
			if a.A.String() != "192.168.1.100" {
				t.Errorf("Expected 192.168.1.100, got %s", a.A.String())
			}
		}
	}
}

// ////////////////////////////////////////////////
// DoQ Test
// ////////////////////////////////////////////////

func TestDoQResolve(t *testing.T) {
	certPath, keyPath := generateSelfSignedCert(t)

	config, logger, _ := fakeConfigAndLogger()
	config.General.Domain = "auth.example.org"
	config.General.Listen = "127.0.0.1:28853"
	config.General.Proto = "udp-quic"
	config.General.DoQListen = config.General.Listen
	config.General.TlsCertFile = certPath
	config.General.TlsKeyFile = keyPath
	config.General.StaticRecords = records
	config.General.Nsname = "ns1.auth.example.org"
	config.General.Nsadmin = "admin.example.org"
	config.General.EnableDoQ = true

	db, _ := database.Init(&config, logger)

	serverInterface := NewDoQServer(&config, db, logger, "vTestDoQ")
	server := serverInterface.(*Nameserver)

	server.ParseRecords()
	server.OwnDomain = "auth.example.org."

	errChan := make(chan error, 1)
	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.SetNotifyStartedFunc(waitLock.Unlock)

	go server.Start(errChan)

	t.Cleanup(func() {
		_ = server.Shutdown(t.Context())
	})

	waitLock.Lock()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"doq"},
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, config.General.Listen, tlsConf, nil)
	if err != nil {
		t.Fatalf("Failed to dial QUIC: %v", err)
	}
	defer func() {
		_ = conn.CloseWithError(0, "")
	}()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("auth.example.org"), dns.TypeA)
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack DNS message: %v", err)
	}

	reqBuf := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(reqBuf[:2], uint16(len(packed)))
	copy(reqBuf[2:], packed)

	_, err = stream.Write(reqBuf)
	if err != nil {
		t.Fatalf("Failed to write to stream: %v", err)
	}

	lenBuf := make([]byte, 2)
	_, err = stream.Read(lenBuf)
	if err != nil {
		t.Fatalf("Failed to read length prefix: %v", err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf)

	respBuf := make([]byte, respLen)
	_, err = stream.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	respMsg := new(dns.Msg)
	err = respMsg.Unpack(respBuf)
	if err != nil {
		t.Fatalf("Failed to unpack response message: %v", err)
	}

	if respMsg.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected RcodeSuccess, got %s", dns.RcodeToString[respMsg.Rcode])
	}
	if len(respMsg.Answer) == 0 {
		t.Error("No answer for DoQ query")
	} else {
		if a, ok := respMsg.Answer[0].(*dns.A); ok {
			if a.A.String() != "192.168.1.100" {
				t.Errorf("Expected 192.168.1.100, got %s", a.A.String())
			}
		} else {
			t.Errorf("Expected A record, got %T", respMsg.Answer[0])
		}
	}
}

//////////////////////////////////////////////////
// Vulnerability Assessment Test
//////////////////////////////////////////////////

func TestResilienceToGarbageUDP(t *testing.T) {
	addr := "127.0.0.1:15353"
	_, _, _ = startTestDNS(t)

	var d net.Dialer
	conn, err := d.DialContext(context.Background(), "udp", addr)
	if err != nil {
		t.Fatalf("Could not connect to server: %v", err)
	}
	defer conn.Close()

	garbage := []byte("THIS_IS_NOT_A_DNS_PACKET_JUST_RANDOM_JUNK_DATA")
	_, err = conn.Write(garbage)
	if err != nil {
		t.Fatalf("Failed to send garbage: %v", err)
	}

	resolv := resolver{server: addr}

	time.Sleep(100 * time.Millisecond)

	_, err = resolv.lookup("auth.example.org", dns.TypeA)
	if err != nil {
		t.Errorf("Server seems to have crashed after receiving garbage data: %v", err)
	}
}

func TestRefuseRecursiveQuery(t *testing.T) {
	addr := "127.0.0.1:15353"
	_, _, _ = startTestDNS(t)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("google.com."), dns.TypeA)
	msg.RecursionDesired = true

	in, err := dns.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("Failed to exchange: %v", err)
	}

	if len(in.Answer) > 0 {
		t.Errorf("Security Risk: Server acted as an open resolver! Got answer for google.com: %v", in.Answer)
	}

	if in.Rcode != dns.RcodeRefused && in.Rcode != dns.RcodeNameError {
		t.Logf("Warning: Server did not refuse recursion explicitly (Rcode: %s). Ensure it didn't reach out to external networks.", dns.RcodeToString[in.Rcode])
	}
}

func TestConcurrencySafe(t *testing.T) {
	addr := "127.0.0.1:15353"
	_, _, _ = startTestDNS(t)

	resolv := resolver{server: addr}

	concurrency := 50
	errCh := make(chan error, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := resolv.lookup("auth.example.org", dns.TypeA)
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Errorf("Concurrent query failed: %v", err)
		}
	}
}

func TestLargePacketParsing(t *testing.T) {
	addr := "127.0.0.1:15353"
	_, _, _ = startTestDNS(t)

	msg := new(dns.Msg)
	longLabel := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890"
	longDomain := longLabel + "." + longLabel + "." + longLabel + ".auth.example.org."

	msg.SetQuestion(dns.Fqdn(longDomain), dns.TypeA)
	msg.SetEdns0(4096, true)

	in, err := dns.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("Exchange failed with large packet: %v", err)
	}

	if in == nil {
		t.Error("Got nil response for large packet")
	}
}
