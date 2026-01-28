// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverstream

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/bassosimone/dnscodec"
)

// NetDialer is typically [*net.Dialer].
type NetDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// StreamOpenerDialerTCP implements [StreamOpenerDialer] for DNS over TCP.
//
// Construct using [NewStreamOpenerDialerTCP].
type StreamOpenerDialerTCP struct {
	// Dialer is the underlying [NetDialer].
	Dialer NetDialer
}

// NewStreamOpenerDialerTCP creates a new [*StreamOpenerDialerTCP].
func NewStreamOpenerDialerTCP(dialer NetDialer) *StreamOpenerDialerTCP {
	return &StreamOpenerDialerTCP{Dialer: dialer}
}

var _ StreamOpenerDialer = &StreamOpenerDialerTCP{}

// NewTCPStreamOpener creates a [StreamOpener] from an existing [net.Conn].
//
// This allows callers who already hold a TCP connection to use
// [*Transport.ExchangeWithStreamOpener] without dialing.
func NewTCPStreamOpener(conn net.Conn) StreamOpener {
	return &tcpStreamConn{conn: conn}
}

// DialContext implements [StreamOpenerDialer].
func (d *StreamOpenerDialerTCP) DialContext(ctx context.Context, address netip.AddrPort) (StreamOpener, error) {
	conn, err := d.Dialer.DialContext(ctx, "tcp", address.String())
	if err != nil {
		return nil, err
	}
	return &tcpStreamConn{conn: conn}, nil
}

// tcpStreamConn implements [StreamOpener] for TCP.
type tcpStreamConn struct {
	conn net.Conn
}

// Close implements [StreamOpener].
func (s *tcpStreamConn) Close() error {
	return s.conn.Close()
}

// MutateQuery implements [StreamOpener].
func (s *tcpStreamConn) MutateQuery(msg *dnscodec.Query) {
	msg.MaxSize = dnscodec.QueryMaxResponseSizeTCP
}

// OpenStream implements [StreamOpener].
func (s *tcpStreamConn) OpenStream() (Stream, error) {
	return &tcpStream{s.conn}, nil
}

// tcpStream implements [Stream] for TCP.
type tcpStream struct {
	conn net.Conn
}

// Close implements [Stream].
func (s *tcpStream) Close() error {
	// We do not close the stream midway for TCP.
	return nil
}

// Read implements [Stream].
func (s *tcpStream) Read(buff []byte) (int, error) {
	return s.conn.Read(buff)
}

// SetDeadline implements [Stream].
func (s *tcpStream) SetDeadline(t time.Time) error {
	return s.conn.SetDeadline(t)
}

// Write implements [Stream].
func (s *tcpStream) Write(data []byte) (int, error) {
	return s.conn.Write(data)
}
