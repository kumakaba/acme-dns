package nameserver

import (
	"encoding/binary"
	"net"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// QuicResponseWriter wraps a QUIC stream to implement dns.ResponseWriter
type QuicResponseWriter struct {
	Stream          *quic.Stream
	Connection      *quic.Conn
	UseLengthPrefix bool
}

func (w *QuicResponseWriter) LocalAddr() net.Addr {
	return w.Connection.LocalAddr()
}

func (w *QuicResponseWriter) RemoteAddr() net.Addr {
	return w.Connection.RemoteAddr()
}

func (w *QuicResponseWriter) WriteMsg(msg *dns.Msg) error {
	data, err := msg.Pack()
	if err != nil {
		return err
	}

	if w.UseLengthPrefix {
		totalLen := 2 + len(data)
		fullData := make([]byte, totalLen)

		binary.BigEndian.PutUint16(fullData[:2], uint16(len(data)))
		copy(fullData[2:], data)

		_, err = w.Stream.Write(fullData)
		return err
	}

	_, err = w.Stream.Write(data)
	return err
}

func (w *QuicResponseWriter) Write(b []byte) (int, error) {
	return w.Stream.Write(b)
}

func (w *QuicResponseWriter) Close() error {
	return w.Stream.Close()
}

func (w *QuicResponseWriter) TsigStatus() error   { return nil }
func (w *QuicResponseWriter) TsigTimersOnly(bool) {}
func (w *QuicResponseWriter) Hijack()             {}
