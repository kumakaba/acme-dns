package nameserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
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
	TLSCertificate    *tls.Certificate
	quicListener      *quic.Listener
	OwnDomain         string
	NotifyStartedFunc func()
	SOA               dns.RR
	personalAuthKey   string
	Domains           map[string]Records
	errChan           chan error
	version           string
}

func InitAndStart(config *acmedns.AcmeDnsConfig, db acmedns.AcmednsDB, logger *zap.SugaredLogger, errChan chan error, versionStr string, testRun bool) []acmedns.AcmednsNS {
	var protocols []string
	var loadedCert *tls.Certificate
	dnsservers := make([]acmedns.AcmednsNS, 0)

	nsListen := config.General.Listen
	dotListen := config.General.DoTListen
	doqListen := config.General.DoQListen
	tlsCert := config.General.TlsCertFile
	tlsKey := config.General.TlsKeyFile
	tlsEnable := false

	if tlsCert != "" && tlsKey != "" {
		tlsEnable = true
		if !acmedns.FileIsAccessible(tlsCert) {
			logger.Error("Not accessible tls certfile")
			tlsEnable = false
		}
		if !acmedns.FileIsAccessible(tlsKey) {
			logger.Error("Not accessible tls keyfile")
			tlsEnable = false
		}
		logger.Debugw("TLS config found setup for DoT/DoQ", "tls_cert_filepath", tlsCert, "tls_key_filepath", tlsKey)
		c, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			logger.Errorw("Failed to load TLS certs. disable DoT/DoQ", "error", err)
			tlsEnable = false
		} else {
			loadedCert = &c
		}
	}

	if strings.HasPrefix(config.General.Proto, "both") {
		if strings.HasSuffix(config.General.Proto, "4") {
			protocols = append(protocols, "udp4")
			protocols = append(protocols, "tcp4")
		} else if strings.HasSuffix(config.General.Proto, "6") {
			protocols = append(protocols, "udp6")
			protocols = append(protocols, "tcp6")
		} else {
			protocols = append(protocols, "udp")
			protocols = append(protocols, "tcp")
		}
	} else {
		protocols = append(protocols, config.General.Proto)
	}
	if tlsEnable {
		protocols = append(protocols, "tcp-tls")
		if config.General.EnableDoQ {
			protocols = append(protocols, "udp-quic")
		}
	}

nsloop:
	for i, protocol := range protocols {
		logger.Debugw("Init and Start Nameserver", "i", i, "protocol", protocol)
		var dnsListen string
		var certToPass *tls.Certificate
		serverProto := protocol

		switch protocol {
		case "udp", "udp4", "udp6":
			dnsListen = nsListen
			certToPass = nil
		case "tcp", "tcp4", "tcp6":
			dnsListen = nsListen
			certToPass = nil
		case "tcp-tls": // DoT
			if dotListen == "" {
				dnsListen = ":853"
			} else {
				dnsListen = dotListen
			}
			certToPass = loadedCert
		case "udp-quic": // DoQ
			if doqListen == "" {
				dnsListen = ":853"
			} else {
				dnsListen = doqListen
			}
			certToPass = loadedCert
		default:
			continue nsloop
		}
		dnsServer := NewDNSServer(config, db, logger, serverProto, versionStr, certToPass)
		dnsServer.(*Nameserver).Server.Addr = dnsListen

		switch protocol {
		case "tcp-tls": // DoT
			dnsServer.(*Nameserver).Server.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{*certToPass},
				MinVersion:   tls.VersionTLS12,
			}
		case "udp-quic": // DoQ
		default:
			break
		}
		// logger.Debugw("Complete setup Nameserver", "i", i, "protocol", serverProto, "listen", dnsListen)
		dnsservers = append(dnsservers, dnsServer)
		dnsServer.ParseRecords()

		if !testRun {
			var wg sync.WaitGroup
			wg.Add(1)
			dnsServer.SetNotifyStartedFunc(wg.Done)
			go dnsServer.Start(errChan)
			wg.Wait()
		}
	}

	return dnsservers
}

// NewDNSServer parses the DNS records from config and returns a new DNSServer struct
func NewDNSServer(config *acmedns.AcmeDnsConfig, db acmedns.AcmednsDB, logger *zap.SugaredLogger, proto string, versionStr string, cert *tls.Certificate) acmedns.AcmednsNS {
	server := Nameserver{
		Config:         config,
		DB:             db,
		Logger:         logger,
		TLSCertificate: cert,
	}
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
	if n.Server.Net == "udp-quic" {
		n.StartDoQ(errorChannel)
		return
	}

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

// DoQ
func NewDoQServer(config *acmedns.AcmeDnsConfig, db acmedns.AcmednsDB, logger *zap.SugaredLogger, versionStr string, cert *tls.Certificate) acmedns.AcmednsNS {
	server := NewDNSServer(config, db, logger, "udp-quic", versionStr, cert)
	return server
}

func (n *Nameserver) StartDoQ(errorChannel chan error) {
	n.errChan = errorChannel

	if n.TLSCertificate == nil {
		err := fmt.Errorf("TLS certificate not loaded for DoQ")
		errorChannel <- err
		if n.NotifyStartedFunc != nil {
			n.NotifyStartedFunc()
		}
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*n.TLSCertificate},
		NextProtos:   []string{"doq"}, // RFC 9250 ALPN
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := quic.ListenAddr(n.Server.Addr, tlsConfig, nil)
	if err != nil {
		errorChannel <- err
		if n.NotifyStartedFunc != nil {
			n.NotifyStartedFunc()
		}
		return
	}
	n.quicListener = listener

	n.Logger.Infow("Starting DNS listener", "addr", n.Server.Addr, "proto", "udp-quic")

	if n.NotifyStartedFunc != nil {
		n.NotifyStartedFunc()
	}

	for {
		conn, err := n.quicListener.Accept(context.Background())
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) {
				// n.Logger.Debug("DoQ listener closed gracefully")
			} else {
				n.Logger.Infow("DoQ listener stopped unexpectedly", "error", err)
			}
			return
		}

		go n.handleDoQConnection(conn)
	}
}

func (n *Nameserver) handleDoQConnection(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		go func(s *quic.Stream) {
			defer s.Close()

			for {
				// RFC 9250 Section 4.2: All DNS messages ... MUST be encoded as a 2-octet length field
				prefixBuf := make([]byte, 2)
				if _, err := io.ReadFull(s, prefixBuf); err != nil {
					if err != io.EOF {
						n.Logger.Debugw("Failed to read DoQ length prefix", "error", err)
					}
					return
				}

				msgLen := binary.BigEndian.Uint16(prefixBuf)

				buf := make([]byte, msgLen)
				if _, err := io.ReadFull(s, buf); err != nil {
					n.Logger.Errorw("Failed to read DoQ message body", "error", err, "expected_len", msgLen)
					return
				}

				req := new(dns.Msg)
				if err := req.Unpack(buf); err != nil {
					n.Logger.Errorw("DoQ Unpack failed", "error", err)
					return
				}

				w := &QuicResponseWriter{
					Stream:          s,
					Connection:      conn,
					UseLengthPrefix: true,
				}

				n.handleRequest(w, req)
			}
		}(stream)
	}
}

func (n *Nameserver) SetNotifyStartedFunc(fun func()) {
	n.Server.NotifyStartedFunc = fun
	n.NotifyStartedFunc = fun
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
	n.Logger.Debugw("Shutdown Nameserver", "proto", n.Server.Net)
	if n.Server.Net == "udp-quic" {
		if n.quicListener != nil {
			return n.quicListener.Close()
		}
		return nil
	}

	return n.Server.ShutdownContext(ctx)
}
