// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverstream

import (
	"context"
	"net"
	"testing"

	"github.com/bassosimone/dnscodec"
	"github.com/stretchr/testify/require"
)

func TestNewQUICStreamOpener(t *testing.T) {
	t.Run("returns valid StreamOpener", func(t *testing.T) {
		// We can't easily create a real *quic.Conn without a full QUIC handshake,
		// but we can verify the constructor returns a valid adapter
		opener := NewQUICStreamOpener(nil)
		require.NotNil(t, opener)
	})

	t.Run("MutateQuery sets correct flags", func(t *testing.T) {
		opener := NewQUICStreamOpener(nil)
		query := dnscodec.NewQuery("example.com", 1)
		query.ID = 12345

		opener.MutateQuery(query)

		require.Equal(t, uint16(dnscodec.QueryMaxResponseSizeTCP), query.MaxSize)
		require.NotZero(t, query.Flags&dnscodec.QueryFlagBlockLengthPadding)
		require.NotZero(t, query.Flags&dnscodec.QueryFlagDNSSec)
		require.Zero(t, query.ID, "QUIC should set ID to 0")
	})
}

func TestQuicConnAdapterMutateQuery(t *testing.T) {
	adapter := &quicConnAdapter{qconn: nil}
	query := dnscodec.NewQuery("example.com", 1)
	query.ID = 12345

	adapter.MutateQuery(query)

	require.Equal(t, uint16(dnscodec.QueryMaxResponseSizeTCP), query.MaxSize)
	require.NotZero(t, query.Flags&dnscodec.QueryFlagBlockLengthPadding)
	require.NotZero(t, query.Flags&dnscodec.QueryFlagDNSSec)
	require.Zero(t, query.ID, "QUIC should set ID to 0")
}

func TestNewTLSConfigDNSOverQUIC(t *testing.T) {
	cfg := NewTLSConfigDNSOverQUIC("dns.example.com")

	require.Equal(t, "dns.example.com", cfg.ServerName)
	require.Contains(t, cfg.NextProtos, "doq")
}

func TestNewQUICDialer(t *testing.T) {
	lc := &net.ListenConfig{}
	pconn, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer pconn.Close()

	dialer := NewQUICDialer(pconn, "dns.example.com")

	require.NotNil(t, dialer.Transport)
	require.NotNil(t, dialer.TLSConfig)
	require.NotNil(t, dialer.QUICConfig)
	require.Equal(t, "dns.example.com", dialer.TLSConfig.ServerName)
	require.Contains(t, dialer.TLSConfig.NextProtos, "doq")
}
