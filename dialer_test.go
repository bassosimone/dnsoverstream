// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverstream

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"

	"github.com/bassosimone/dnscodec"
	"github.com/stretchr/testify/require"
)

func TestTCPStreamDialerDialContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dialer := &tcpStreamDialer{nd: &net.Dialer{}}
	_, err := dialer.DialContext(ctx, netip.MustParseAddrPort("127.0.0.1:53"))
	require.ErrorIs(t, err, context.Canceled)
}

func TestTLSStreamDialerDialContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dialer := &tlsStreamDialer{nd: &tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{}}}
	_, err := dialer.DialContext(ctx, netip.MustParseAddrPort("127.0.0.1:853"))
	require.ErrorIs(t, err, context.Canceled)
}

func TestQUICStreamDialerDialContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	lc := &net.ListenConfig{}
	pconn, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer pconn.Close()

	dialer := &quicStreamDialer{
		qd: NewQUICDialer(pconn, "example.com"),
	}
	_, err = dialer.DialContext(ctx, netip.MustParseAddrPort("127.0.0.1:853"))
	require.ErrorIs(t, err, context.Canceled)
}

func TestTransportExchangeDialContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dt := NewTransportTCP(&net.Dialer{}, netip.MustParseAddrPort("127.0.0.1:53"))
	_, err := dt.Exchange(ctx, dnscodec.NewQuery("example.com", 1))
	require.ErrorIs(t, err, context.Canceled)
}
