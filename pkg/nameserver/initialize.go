package nameserver

import (
	"context"
	"crypto/tls"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/kumakaba/acme-dns/pkg/acmedns"
)

// Records is a slice of ResourceRecords
type Records struct {
	Records []dns.RR
}

type Nameserver struct {
	Config            *acmedns.AcmeDnsConfig
	DB                acmedns.AcmednsDB
	Logger            *zap.SugaredLogger
	Server            *dns.Server
	OwnDomain         string
	NotifyStartedFunc func()
	SOA               dns.RR
	personalAuthKey   string
	Domains           map[string]Records
	errChan           chan error
	version           string
}

func InitAndStart(config *acmedns.AcmeDnsConfig, db acmedns.AcmednsDB, logger *zap.SugaredLogger, errChan chan error, versionStr string) []acmedns.AcmednsNS {
	dnsservers := make([]acmedns.AcmednsNS, 0)
	waitLock := sync.Mutex{}
	if strings.HasPrefix(config.General.Proto, "both") {

		// Handle the case where DNS server should be started for both udp and tcp
		udpProto := "udp"
		tcpProto := "tcp"
		if strings.HasSuffix(config.General.Proto, "4") {
			udpProto += "4"
			tcpProto += "4"
		} else if strings.HasSuffix(config.General.Proto, "6") {
			udpProto += "6"
			tcpProto += "6"
		}
		dnsServerUDP := NewDNSServer(config, db, logger, udpProto, versionStr)
		dnsservers = append(dnsservers, dnsServerUDP)
		dnsServerUDP.ParseRecords()
		dnsServerTCP := NewDNSServer(config, db, logger, tcpProto, versionStr)
		dnsservers = append(dnsservers, dnsServerTCP)
		dnsServerTCP.ParseRecords()
		// wait for the server to get started to proceed
		waitLock.Lock()
		dnsServerUDP.SetNotifyStartedFunc(waitLock.Unlock)
		go dnsServerUDP.Start(errChan)
		waitLock.Lock()
		dnsServerTCP.SetNotifyStartedFunc(waitLock.Unlock)
		go dnsServerTCP.Start(errChan)
		waitLock.Lock()
	} else {
		dnsServer := NewDNSServer(config, db, logger, config.General.Proto, versionStr)
		dnsservers = append(dnsservers, dnsServer)
		dnsServer.ParseRecords()
		waitLock.Lock()
		dnsServer.SetNotifyStartedFunc(waitLock.Unlock)
		go dnsServer.Start(errChan)
		waitLock.Lock()
	}

	waitLock.Unlock()

	// DoT (DNS over TLS)
	dotListen := config.General.DoTListen
	tlsCert := config.General.TlsCertFile
	tlsKey := config.General.TlsKeyFile
	if tlsCert != "" && tlsKey != "" {
		tlsEnable := true
		if !acmedns.FileIsAccessible(tlsCert) {
			logger.Error("Not accessible tls certfile")
			tlsEnable = false
		}
		if !acmedns.FileIsAccessible(tlsKey) {
			logger.Error("Not accessible tls keyfile")
			tlsEnable = false
		}
		if tlsEnable {
			logger.Debugw("TLS config found setup for DoT", "tls_cert_filepath", tlsCert, "tls_key_filepath", tlsKey)
			dotProto := "tcp-tls"
			if strings.HasSuffix(config.General.Proto, "4") {
				dotProto += "4"
			} else if strings.HasSuffix(config.General.Proto, "6") {
				dotProto += "6"
			}

			dotServer := NewDNSServer(config, db, logger, dotProto, versionStr)

			if dotListen == "" {
				dotListen = "127.0.0.1:853"
			}
			dotServer.(*Nameserver).Server.Addr = dotListen

			cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
			if err != nil {
				logger.Errorw("Failed to load TLS certs for DoT", "error", err)
			} else {
				// logger.Debug("configure dotServer")
				dotServer.(*Nameserver).Server.TLSConfig = &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				}

				// logger.Debug("append dotServer")
				dnsservers = append(dnsservers, dotServer)
				// logger.Debug("dotServer.ParseRecords")
				dotServer.ParseRecords()

				waitLock.Lock()
				// logger.Debug("dotServer.SetNotifyStartedFunc")
				dotServer.SetNotifyStartedFunc(waitLock.Unlock)
				// logger.Debug("dotServer.Start")
				go dotServer.Start(errChan)
				waitLock.Lock()
			}
		} else {
			logger.Error("Failed to start DoT")
		}
	}

	return dnsservers
}

// NewDNSServer parses the DNS records from config and returns a new DNSServer struct
func NewDNSServer(config *acmedns.AcmeDnsConfig, db acmedns.AcmednsDB, logger *zap.SugaredLogger, proto string, versionStr string) acmedns.AcmednsNS {
	server := Nameserver{Config: config, DB: db, Logger: logger}
	server.Server = &dns.Server{Addr: config.General.Listen, Net: proto}
	domain := config.General.Domain
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	server.OwnDomain = strings.ToLower(domain)
	server.personalAuthKey = ""
	server.Domains = make(map[string]Records)
	server.version = versionStr
	return &server
}

func (n *Nameserver) Start(errorChannel chan error) {
	n.errChan = errorChannel

	mux := dns.NewServeMux()
	mux.HandleFunc(".", n.handleRequest)
	n.Server.Handler = mux

	n.Logger.Infow("Starting DNS listener",
		"addr", n.Server.Addr,
		"proto", n.Server.Net)
	if n.NotifyStartedFunc != nil {
		n.Server.NotifyStartedFunc = n.NotifyStartedFunc
	}
	err := n.Server.ListenAndServe()
	if err != nil {
		errorChannel <- err
	}
}

func (n *Nameserver) SetNotifyStartedFunc(fun func()) {
	n.Server.NotifyStartedFunc = fun
	n.Server.ReadTimeout = 3 * time.Second
	n.Server.WriteTimeout = 3 * time.Second
}

func (n *Nameserver) GetVersion() string {
	return n.version
}

func (n *Nameserver) Shutdown(ctx context.Context) error {
	if n.Server == nil {
		return nil
	}

	return n.Server.ShutdownContext(ctx)
}
