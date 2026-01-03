// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverstream

import (
	"bytes"
	"context"
	"errors"
	"io"
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

// newStreamStub creates a stream stub with default no-op implementations.
func newStreamStub() *streamStub {
	return &streamStub{
		setDeadline: func(t time.Time) error { return nil },
		read:        func(p []byte) (int, error) { return 0, io.EOF },
		write:       func(p []byte) (int, error) { return 0, nil },
		close:       func() error { return nil },
	}
}

// buildRawResponseFromQuery packs a valid DNS response from a raw DNS query.
func buildRawResponseFromQuery(t *testing.T, rawQuery []byte) []byte {
	t.Helper()

	queryMsg := &dns.Msg{}
	require.NoError(t, queryMsg.Unpack(rawQuery))

	resp := &dns.Msg{}
	resp.SetReply(queryMsg)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   queryMsg.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    1,
		},
		A: net.ParseIP("1.1.1.1"),
	}}

	rawResp, err := resp.Pack()
	require.NoError(t, err)

	return rawResp
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

func TestExchangeWithStreamOpenerCloneAndMutateQuery(t *testing.T) {
	query := dnscodec.NewQuery("example.com", dns.TypeA)
	orig := *query
	var rawWritten []byte
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			stub := newStreamStub()
			stub.write = func(p []byte) (int, error) {
				rawWritten = append([]byte{}, p...)
				return len(p), nil
			}
			return stub, nil
		},
	}

	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	_, err := dt.ExchangeWithStreamOpener(context.Background(), conn, query)
	require.Error(t, err)
	require.NotEmpty(t, rawWritten)
	require.Equal(t, orig, *query)

	rawQuery := rawWritten[2:]
	msg := &dns.Msg{}
	require.NoError(t, msg.Unpack(rawQuery))
	require.True(t, msg.RecursionDesired)
	require.Equal(t, uint16(dnscodec.QueryMaxResponseSizeTCP), msg.IsEdns0().UDPSize())
}

func TestExchangeWithStreamOpenerObserveRawQuery(t *testing.T) {
	query := dnscodec.NewQuery("example.com", dns.TypeA)
	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	var (
		hookQuery  []byte
		rawWritten []byte
		rawResp    []byte
		respReader *bytes.Reader
	)
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			stub := newStreamStub()

			stub.write = func(p []byte) (int, error) {
				rawWritten = append([]byte{}, p...)
				rawResp = buildRawResponseFromQuery(t, rawWritten[2:])
				frame := append([]byte{byte(len(rawResp) >> 8), byte(len(rawResp))}, rawResp...)
				respReader = bytes.NewReader(frame)
				return len(p), nil
			}

			stub.read = func(p []byte) (int, error) {
				if respReader == nil {
					return 0, io.EOF
				}
				return respReader.Read(p)
			}

			return stub, nil
		},
	}

	dt.ObserveRawQuery = func(p []byte) {
		hookQuery = append([]byte{}, p...)
		if len(p) > 0 {
			p[0] ^= 0xff // mutate to verify we've got a copy
		}
	}

	_, err := dt.ExchangeWithStreamOpener(context.Background(), conn, query)
	require.NoError(t, err)
	require.Equal(t, rawWritten[2:], hookQuery)
}

func TestExchangeWithStreamOpenerFrameLength(t *testing.T) {
	var rawWritten []byte
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			stub := newStreamStub()
			stub.write = func(p []byte) (int, error) {
				rawWritten = append([]byte{}, p...)
				return len(p), nil
			}
			return stub, nil
		},
	}

	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	_, err := dt.ExchangeWithStreamOpener(context.Background(), conn, dnscodec.NewQuery("example.com", dns.TypeA))
	require.Error(t, err)
	require.GreaterOrEqual(t, len(rawWritten), 2)

	frameLen := int(rawWritten[0])<<8 | int(rawWritten[1])
	require.Equal(t, len(rawWritten)-2, frameLen)
}

func TestExchangeWithStreamOpenerObserveRawResponse(t *testing.T) {
	query := dnscodec.NewQuery("example.com", dns.TypeA)
	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	var (
		hookResp   []byte
		rawResp    []byte
		respReader *bytes.Reader
	)
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			stub := newStreamStub()

			stub.write = func(p []byte) (int, error) {
				rawResp = buildRawResponseFromQuery(t, p[2:])
				frame := append([]byte{byte(len(rawResp) >> 8), byte(len(rawResp))}, rawResp...)
				respReader = bytes.NewReader(frame)
				return len(p), nil
			}

			stub.read = func(p []byte) (int, error) {
				if respReader == nil {
					return 0, io.EOF
				}
				return respReader.Read(p)
			}

			return stub, nil
		},
	}

	dt.ObserveRawResponse = func(p []byte) {
		hookResp = append([]byte{}, p...)
		if len(p) > 0 {
			p[0] ^= 0xff // mutate to verify we've got a copy
		}
	}

	_, err := dt.ExchangeWithStreamOpener(context.Background(), conn, query)
	require.NoError(t, err)
	require.Equal(t, rawResp, hookResp)
}

func TestExchangeWithStreamOpenerSetsDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Second)
	var gotDeadline []time.Time
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			stub := newStreamStub()
			stub.setDeadline = func(t time.Time) error {
				gotDeadline = append(gotDeadline, t)
				return nil
			}
			return stub, nil
		},
	}

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	_, err := dt.ExchangeWithStreamOpener(ctx, conn, dnscodec.NewQuery("example.com", dns.TypeA))
	require.Error(t, err)
	require.True(t, len(gotDeadline) == 2)
	require.False(t, gotDeadline[0].IsZero())
	require.True(t, gotDeadline[1].IsZero())
	require.WithinDuration(t, deadline, gotDeadline[0], time.Second)
}

func TestExchangeWithStreamOpenerClosesStream(t *testing.T) {
	var closed bool
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			stub := newStreamStub()
			stub.close = func() error {
				closed = true
				return nil
			}
			return stub, nil
		},
	}

	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	_, err := dt.ExchangeWithStreamOpener(context.Background(), conn, dnscodec.NewQuery("example.com", dns.TypeA))
	require.Error(t, err)
	require.True(t, closed)
}

func TestExchangeWithStreamOpenerNewMsgError(t *testing.T) {
	dt := newTransportStream(&tcpStreamDialer{&net.Dialer{}}, netip.AddrPort{})
	conn := &streamOpenerStub{
		openStream: func() (Stream, error) {
			return &streamStub{
				close: func() error { return nil },
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
				close: func() error { return nil },
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
				write: func(p []byte) (int, error) { return 0, expected },
				close: func() error { return nil },
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
				read:  func(p []byte) (int, error) { return 0, expected },
				write: func(p []byte) (int, error) { return len(p), nil },
				close: func() error { return nil },
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
