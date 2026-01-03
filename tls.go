// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverstream

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"

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

// TLSDialer is typically [*tls.Dialer] or a compatible TLS dialer.
type TLSDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// NewTransportTLS returns a new [*Transport] for DNS over TLS using [*tls.Dialer].
func NewTransportTLS(dialer *tls.Dialer, endpoint netip.AddrPort) *Transport {
	return NewTransportTLSWithDialer(dialer, endpoint)
}

// NewTransportTLSWithDialer returns a new [*Transport] for DNS over TLS.
//
// The caller is responsible for ensuring the dialer actually performs TLS.
func NewTransportTLSWithDialer(dialer TLSDialer, endpoint netip.AddrPort) *Transport {
	return newTransportStream(&tlsStreamDialer{dialer}, endpoint)
}

// tlsStreamDialer implements [streamDialer] for TLS.
type tlsStreamDialer struct {
	nd TLSDialer
}

var _ streamDialer = &tlsStreamDialer{}

// DialContext implements [streamDialer].
func (d *tlsStreamDialer) DialContext(ctx context.Context, address netip.AddrPort) (streamConn, error) {
	conn, err := d.nd.DialContext(ctx, "tcp", address.String())
	if err != nil {
		return nil, err
	}
	return &tcpStreamConn{conn}, nil
}

// MutateQuery implements [streamDialer].
func (d *tlsStreamDialer) MutateQuery(msg *dnscodec.Query) {
	msg.Flags |= dnscodec.QueryFlagBlockLengthPadding | dnscodec.QueryFlagDNSSec
	msg.MaxSize = dnscodec.QueryMaxResponseSizeTCP
}
