//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Written by @roopeshsn and @bassosimone
//
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/dns/dnscore/dotcp.go
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/dnsovertcp.go
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/dns/dnscore/doquic.go
// Adapted from: https://github.com/rbmk-project/dnscore/blob/v0.14.0/doquic.go
//
// See https://github.com/rbmk-project/dnscore/pull/18
//
// See https://datatracker.ietf.org/doc/rfc9250/
//

package dnsoverstream

import (
	"bufio"
	"context"
	"io"
	"math"
	"net/netip"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/runtimex"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// stream is a stream suitable for DNS over TCP, TLS, or QUIC.
type stream interface {
	// SetDeadline sets the I/O deadline.
	SetDeadline(t time.Time) error

	// We can obviously do I/O with the stream.
	io.ReadWriter

	// The semantics of closing a stream depends on the
	// protocol we are actually using.
	//
	// For [net.Conn] and [*tls.Conn], this is a no-op since the
	// [Stream] is the [StreamConn].
	//
	// For [*quic.Stream], this actually closes the stream.
	io.Closer
}

// streamConn abstracts over [net.Conn], [*tls.Conn], or [*quic.Conn].
type streamConn interface {
	// CloseWithError closes the connection.
	//
	// For [net.Conn] and [*tls.Conn], this calls conn.Close.
	//
	// For [*quic.Conn], this calls conn.CloseWithError.
	CloseWithError(code quic.ApplicationErrorCode, desc string) error

	// OpenStream opens a new stream over the connection.
	//
	// For [net.Conn] and [*tls.Conn], this returns the connection itself.
	//
	// For [*quic.Conn] this opens a [*quic.Stream].
	OpenStream() (stream, error)
}

// streamDialer allows dialing a [net.Conn], [*tls.Conn], or [*quic.Conn].
type streamDialer interface {
	// DialContext creates a new [StreamConn].
	DialContext(ctx context.Context, address netip.AddrPort) (streamConn, error)

	// MutateQuery mutates the [*dnscodec.Query] to apply the correct
	// settings for the protocol that we are using.
	MutateQuery(msg *dnscodec.Query)
}

// Transport is a transport for DNS over TCP, TLS, and QUIC.
//
// Construct using [NewTransportTCP], [NewTransportTLS], [NewTransportQUIC].
//
// Transport creates a new connection for each Exchange call and targets the
// specific [netip.AddrPort] endpoint configured at construction time.
type Transport struct {
	// dialer is the [StreamDialer] to build the stream for exchanging messages.
	//
	// Set by [NewTransportStream] to the user-provided value.
	dialer streamDialer

	// endpoint is the server endpoint to use to query.
	//
	// Set by [NewTransportStream] to the user-provided value.
	endpoint netip.AddrPort
}

// newTransportStream creates a new [*Transport].
func newTransportStream(dialer streamDialer, endpoint netip.AddrPort) *Transport {
	return &Transport{dialer: dialer, endpoint: endpoint}
}

// Exchange sends a [*dnscodec.Query] and receives a [*dnscodec.Response].
func (dt *Transport) Exchange(ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error) {
	// 1. create the connection
	conn, err := dt.dialer.DialContext(ctx, dt.endpoint)
	if err != nil {
		return nil, err
	}

	// 2. Use a single connection for request, which is what the standard library
	// does as well for and is more robust in terms of residual censorship.
	//
	// Make sure we react to context being canceled early.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		// Closing w/o specific error -- RFC 9250 Sect. 4.3
		//
		// Obviously no error is sent for TCP/TLS.
		const quicNoError = 0x00
		<-ctx.Done()
		conn.CloseWithError(quicNoError, "")
	}()

	// 3. Open the stream for sending the DoTCP, DoT, or DoQ query.
	stream, err := conn.OpenStream()
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	// 4. Use the context deadline to limit the query lifetime
	// as documented in the [*Transport.Exchange] function.
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}

	// 5. Mutate and serialize the query.
	query = query.Clone()
	dt.dialer.MutateQuery(query)
	queryMsg, err := query.NewMsg()
	if err != nil {
		return nil, err
	}
	rawQuery, err := queryMsg.Pack()
	if err != nil {
		return nil, err
	}

	// 6. Wrap the query into a frame
	rawQueryFrame, err := newStreamMsgFrame(rawQuery)
	if err != nil {
		return nil, err
	}

	// 7. Send the query.
	if _, err := stream.Write(rawQueryFrame); err != nil {
		return nil, err
	}

	// 8. Ensure we close the stream when using DoQ to signal the
	// upstream server that it is okay to send a response.
	//
	// RFC 9250 is very clear in this respect:
	//
	//	4.2.  Stream Mapping and Usage
	//	client MUST send the DNS query over the selected stream and MUST
	//	indicate through the STREAM FIN mechanism that no further data will
	//	be sent on that stream.
	//
	// Empirical testing during https://github.com/rbmk-project/dnscore/pull/18
	// showed that, in fact, some servers misbehave if we don't do this.
	//
	// Obviously, this is a no-op for TCP/TLS
	stream.Close()

	// 9. Wrap the conn to avoid issuing too many reads
	// then read the response header and message
	br := bufio.NewReader(stream)
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, err
	}
	length := int(header[0])<<8 | int(header[1])
	// TODO(bassosimone): consider enforcing query.MaxSize here.
	rawResp := make([]byte, length)
	if _, err := io.ReadFull(br, rawResp); err != nil {
		return nil, err
	}

	// 10. Parse the response and return
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(rawResp); err != nil {
		return nil, err
	}
	return dnscodec.ParseResponse(queryMsg, respMsg)
}

// newStreamMsgFrame creates a new raw frame for sending a message over a stream.
func newStreamMsgFrame(rawMsg []byte) ([]byte, error) {
	// TODO(bassosimone): re-evaluate whether this can panic when we add more tests.
	runtimex.Assert(len(rawMsg) <= math.MaxUint16)
	rawMsgFrame := []byte{byte(len(rawMsg) >> 8)}
	rawMsgFrame = append(rawMsgFrame, byte(len(rawMsg)))
	rawMsgFrame = append(rawMsgFrame, rawMsg...)
	return rawMsgFrame, nil
}
