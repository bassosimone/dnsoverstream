// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverstream

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"time"

	"github.com/bassosimone/dnscodec"
)

// NewTLSConfigDNSOverTLS returns the [*tls.Config] to use for DNS-over-TLS.
func NewTLSConfigDNSOverTLS(serverName string) *tls.Config {
	return &tls.Config{
		NextProtos: []string{"dot"},
		ServerName: serverName,
	}
}

// NewTLSDialerDNSOverTLS returns the [*tls.Dialer] to use for DNS-over-TLS.
func NewTLSDialerDNSOverTLS(serverName string) *tls.Dialer {
	return &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    NewTLSConfigDNSOverTLS(serverName),
	}
}

// TLSDialer is typically [*tls.Dialer] or a compatible TLS dialer such as utls.
type TLSDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// StreamOpenerDialerTLS implements [StreamOpenerDialer] for DNS over TLS.
//
// Construct using [NewStreamOpenerDialerTLS].
type StreamOpenerDialerTLS struct {
	// Dialer is the underlying [TLSDialer].
	Dialer TLSDialer
}

// NewStreamOpenerDialerTLS creates a new [*StreamOpenerDialerTLS].
//
// The caller is responsible for ensuring the dialer actually performs TLS.
func NewStreamOpenerDialerTLS(dialer TLSDialer) *StreamOpenerDialerTLS {
	return &StreamOpenerDialerTLS{Dialer: dialer}
}

var _ StreamOpenerDialer = &StreamOpenerDialerTLS{}

// NewTLSStreamOpener creates a [StreamOpener] from an existing TLS [net.Conn].
//
// This allows callers who already hold a TLS connection to use
// [*Transport.ExchangeWithStreamOpener] without dialing.
//
// The caller is responsible for ensuring the connection is actually a TLS connection.
func NewTLSStreamOpener(conn net.Conn) StreamOpener {
	return &tlsStreamConn{conn}
}

// DialContext implements [StreamOpenerDialer].
func (d *StreamOpenerDialerTLS) DialContext(ctx context.Context, address netip.AddrPort) (StreamOpener, error) {
	conn, err := d.Dialer.DialContext(ctx, "tcp", address.String())
	if err != nil {
		return nil, err
	}
	return &tlsStreamConn{conn}, nil
}

// tlsStreamConn implements [StreamOpener] for TLS.
type tlsStreamConn struct {
	conn net.Conn
}

// Close implements [StreamOpener].
func (s *tlsStreamConn) Close() error {
	return s.conn.Close()
}

// MutateQuery implements [StreamOpener].
func (s *tlsStreamConn) MutateQuery(msg *dnscodec.Query) {
	msg.Flags |= dnscodec.QueryFlagBlockLengthPadding | dnscodec.QueryFlagDNSSec
	msg.MaxSize = dnscodec.QueryMaxResponseSizeTCP
}

// OpenStream implements [StreamOpener].
func (s *tlsStreamConn) OpenStream() (Stream, error) {
	return &tlsStream{s.conn}, nil
}

// tlsStream implements [Stream] for TLS.
type tlsStream struct {
	conn net.Conn
}

// Close implements [Stream].
func (s *tlsStream) Close() error {
	// We do not close the stream midway for TLS.
	return nil
}

// Read implements [Stream].
func (s *tlsStream) Read(buff []byte) (int, error) {
	return s.conn.Read(buff)
}

// SetDeadline implements [Stream].
func (s *tlsStream) SetDeadline(t time.Time) error {
	return s.conn.SetDeadline(t)
}

// Write implements [Stream].
func (s *tlsStream) Write(data []byte) (int, error) {
	return s.conn.Write(data)
}
