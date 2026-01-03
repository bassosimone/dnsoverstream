//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Written by @roopeshsn and @bassosimone
//
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/dns/dnscore/doquic.go
// Adapted from: https://github.com/rbmk-project/dnscore/blob/v0.14.0/doquic.go
//
// See https://github.com/rbmk-project/dnscore/pull/18
//
// See https://datatracker.ietf.org/doc/rfc9250/
//

package dnsoverstream

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"

	"github.com/bassosimone/dnscodec"
	"github.com/quic-go/quic-go"
)

// NewTLSConfigDNSOverQUIC returns the [*tls.Config] to use for DNS-over-QUIC.
func NewTLSConfigDNSOverQUIC(serverName string) *tls.Config {
	return &tls.Config{
		NextProtos: []string{"doq"},
		ServerName: serverName,
	}
}

// QUICDialer allows to dial a [*quic.Conn] with a given [netip.AddrPort] and
// the [*quic.Config], [*tls.Config], and [*quic.Transport] fields.
type QUICDialer struct {
	// QUICConfig contains OPTIONAL [*quic.Config].
	QUICConfig *quic.Config

	// TLSConfig is the MANDATORY [*tls.Config].
	TLSConfig *tls.Config

	// Transport is the MANDATORY [*quic.Transport].
	Transport *quic.Transport
}

// NewQUICDialer creates a new [*QUICDialer] using the given serverName
// for the [*tls.Config] and [net.PacketConn] for QUIC.
func NewQUICDialer(pconn net.PacketConn, serverName string) *QUICDialer {
	return &QUICDialer{
		TLSConfig:  NewTLSConfigDNSOverQUIC(serverName),
		QUICConfig: &quic.Config{},
		Transport:  &quic.Transport{Conn: pconn},
	}
}

// Dial creates a [*quic.Conn] using the given argument and the structure fields.
func (qdd *QUICDialer) Dial(ctx context.Context, address netip.AddrPort) (*quic.Conn, error) {
	udpAddr := net.UDPAddrFromAddrPort(address)
	return qdd.Transport.Dial(ctx, udpAddr, qdd.TLSConfig, qdd.QUICConfig)
}

// NewTransportQUIC returns a new [*Transport] for DNS over QUIC.
func NewTransportQUIC(dialer *QUICDialer, endpoint netip.AddrPort) *Transport {
	return newTransportStream(&quicStreamDialer{dialer}, endpoint)
}

// quicStreamDialer implements [streamDialer] for QUIC.
type quicStreamDialer struct {
	qd *QUICDialer
}

var _ streamDialer = &quicStreamDialer{}

// DialContext implements [streamDialer].
func (d *quicStreamDialer) DialContext(ctx context.Context, address netip.AddrPort) (streamConn, error) {
	conn, err := d.qd.Dial(ctx, address)
	if err != nil {
		return nil, err
	}
	return &quicConnAdapter{conn, sync.Once{}}, nil
}

// MutateQuery implements [streamDialer].
func (d *quicStreamDialer) MutateQuery(msg *dnscodec.Query) {
	msg.Flags |= dnscodec.QueryFlagBlockLengthPadding | dnscodec.QueryFlagDNSSec
	msg.ID = 0
	msg.MaxSize = dnscodec.QueryMaxResponseSizeTCP
}

// quicConnAdapter adapts [*quic.Conn] to [streamConn].
type quicConnAdapter struct {
	qconn *quic.Conn
	once  sync.Once
}

// CloseWithError implements [streamConn].
func (q *quicConnAdapter) CloseWithError(code quic.ApplicationErrorCode, desc string) (err error) {
	q.once.Do(func() {
		err = q.qconn.CloseWithError(code, desc)
	})
	return
}

// OpenStream implements [streamConn].
func (q *quicConnAdapter) OpenStream() (stream, error) {
	return q.qconn.OpenStream()
}
