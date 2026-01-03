// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverstream

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

type streamOpenerStub struct {
	openStream func() (Stream, error)
}

// OpenStream implements [StreamOpener].
func (s *streamOpenerStub) OpenStream() (Stream, error) {
	return s.openStream()
}

// CloseWithError implements [StreamOpener].
func (s *streamOpenerStub) CloseWithError(code quic.ApplicationErrorCode, desc string) error {
	return nil
}

type streamStub struct {
	// setDeadline sets the stream deadline.
	setDeadline func(t time.Time) error

	// read reads from the stream.
	read func(p []byte) (int, error)

	// write writes to the stream.
	write func(p []byte) (int, error)

	// close closes the stream.
	close func() error
}

// SetDeadline implements [Stream].
func (s *streamStub) SetDeadline(t time.Time) error {
	return s.setDeadline(t)
}

// Read implements [Stream].
func (s *streamStub) Read(p []byte) (int, error) {
	return s.read(p)
}

// Write implements [Stream].
func (s *streamStub) Write(p []byte) (int, error) {
	return s.write(p)
}

// Close implements [Stream].
func (s *streamStub) Close() error {
	return s.close()
}

func TestExchangeWithStreamOpenerOpenStreamError(t *testing.T) {
	expected := errors.New("open stream failed")
	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			return nil, expected
		},
	}

	_, err := dt.ExchangeWithStreamOpener(context.Background(), conn, dnscodec.NewQuery("example.com", dns.TypeA))
	require.ErrorIs(t, err, expected)
}

func TestExchangeWithStreamOpenerNewMsgError(t *testing.T) {
	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			return &streamStub{
				close:       func() error { return nil },
			}, nil
		},
	}

	_, err := dt.ExchangeWithStreamOpener(context.Background(), conn, dnscodec.NewQuery("\t", dns.TypeA))
	require.Error(t, err)
}

func TestExchangeWithStreamOpenerPackError(t *testing.T) {
	tooLongLabel := strings.Repeat("a", 64)
	name := tooLongLabel + ".example.com"

	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			return &streamStub{
				close:       func() error { return nil },
			}, nil
		},
	}

	_, err := dt.ExchangeWithStreamOpener(context.Background(), conn, dnscodec.NewQuery(name, dns.TypeA))
	require.Error(t, err)
}

func TestExchangeWithStreamOpenerWriteError(t *testing.T) {
	expected := errors.New("write failed")
	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			return &streamStub{
				write:       func(p []byte) (int, error) { return 0, expected },
				close:       func() error { return nil },
			}, nil
		},
	}

	_, err := dt.ExchangeWithStreamOpener(context.Background(), conn, dnscodec.NewQuery("example.com", dns.TypeA))
	require.ErrorIs(t, err, expected)
}

func TestExchangeWithStreamOpenerReadHeaderError(t *testing.T) {
	expected := errors.New("read header failed")
	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			return &streamStub{
				read:        func(p []byte) (int, error) { return 0, expected },
				write:       func(p []byte) (int, error) { return len(p), nil },
				close:       func() error { return nil },
			}, nil
		},
	}

	_, err := dt.ExchangeWithStreamOpener(context.Background(), conn, dnscodec.NewQuery("example.com", dns.TypeA))
	require.ErrorIs(t, err, expected)
}

func TestExchangeWithStreamOpenerReadBodyError(t *testing.T) {
	expected := errors.New("read body failed")
	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			var calls int
			return &streamStub{
				read: func(p []byte) (int, error) {
					if calls == 0 {
						calls++
						p[0] = 0
						p[1] = 1
						return 2, nil
					}
					return 0, expected
				},
				write: func(p []byte) (int, error) { return len(p), nil },
				close: func() error { return nil },
			}, nil
		},
	}

	_, err := dt.ExchangeWithStreamOpener(context.Background(), conn, dnscodec.NewQuery("example.com", dns.TypeA))
	require.ErrorIs(t, err, expected)
}

func TestExchangeWithStreamOpenerUnpackError(t *testing.T) {
	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			var calls int
			return &streamStub{
				read: func(p []byte) (int, error) {
					if calls == 0 {
						calls++
						p[0] = 0
						p[1] = 1
						return 2, nil
					}
					p[0] = 0xff
					return 1, nil
				},
				write: func(p []byte) (int, error) { return len(p), nil },
				close: func() error { return nil },
			}, nil
		},
	}

	_, err := dt.ExchangeWithStreamOpener(context.Background(), conn, dnscodec.NewQuery("example.com", dns.TypeA))
	require.Error(t, err)
}

func TestExchangeWithStreamOpenerParseResponseError(t *testing.T) {
	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	query := dnscodec.NewQuery("example.com", dns.TypeA)
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			var calls int
			// Prepare a message that is not a response to get ErrInvalidResponse
			resp := &dns.Msg{}
			resp.SetRcode(&dns.Msg{Question: []dns.Question{{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}}}, dns.RcodeRefused)
			rawResp, err := resp.Pack()
			require.NoError(t, err)
			return &streamStub{
				read: func(p []byte) (int, error) {
					if calls == 0 {
						p[0] = byte(len(rawResp) >> 8)
						p[1] = byte(len(rawResp))
						calls++
						return 2, nil
					}
					copy(p, rawResp)
					return len(rawResp), nil
				},
				write: func(p []byte) (int, error) { return len(p), nil },
				close: func() error { return nil },
			}, nil
		},
	}

	_, err := dt.ExchangeWithStreamOpener(context.Background(), conn, query)
	require.ErrorIs(t, err, dnscodec.ErrInvalidResponse)
}
