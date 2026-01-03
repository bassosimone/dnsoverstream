// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverstream

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/bassosimone/dnscodec"
	quic "github.com/quic-go/quic-go"
)

// NetDialer is typically [*net.Dialer] or [*tls.Dialer].
type NetDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// NewTransportTCP returns a new [*Transport] for DNS over TCP.
func NewTransportTCP(dialer NetDialer, endpoint netip.AddrPort) *Transport {
	return newTransportStream(&tcpStreamDialer{dialer}, endpoint)
}

// tcpStreamDialer implements [streamDialer] for TCP.
type tcpStreamDialer struct {
	nd NetDialer
}

var _ streamDialer = &tcpStreamDialer{}

// DialContext implements [streamDialer].
func (d *tcpStreamDialer) DialContext(ctx context.Context, address netip.AddrPort) (streamConn, error) {
	conn, err := d.nd.DialContext(ctx, "tcp", address.String())
	if err != nil {
		return nil, err
	}
	return &tcpStreamConn{conn}, nil
}

// MutateQuery implements [streamDialer].
func (d *tcpStreamDialer) MutateQuery(msg *dnscodec.Query) {
	msg.MaxSize = dnscodec.QueryMaxResponseSizeTCP
}

// tcpStreamConn implements both [streamConn] and [stream] for TCP or TLS.
type tcpStreamConn struct {
	Conn net.Conn
}

// CloseWithError implements [streamConn].
func (s *tcpStreamConn) CloseWithError(code quic.ApplicationErrorCode, desc string) error {
	return s.Conn.Close()
}

// OpenStream implements [streamConn].
func (s *tcpStreamConn) OpenStream() (stream, error) {
	return s, nil
}

// Close implements [stream].
func (s *tcpStreamConn) Close() error {
	// We do not close the stream midway for TCP or TLS.
	return nil
}

// Read implements [stream].
func (s *tcpStreamConn) Read(buff []byte) (int, error) {
	return s.Conn.Read(buff)
}

// SetDeadline implements [stream].
func (s *tcpStreamConn) SetDeadline(t time.Time) error {
	return s.Conn.SetDeadline(t)
}

// Write implements [stream].
func (s *tcpStreamConn) Write(data []byte) (int, error) {
	return s.Conn.Write(data)
}
