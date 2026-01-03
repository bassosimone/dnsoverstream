// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverstream_test

import (
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/dnsoverstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// run exchanges a query for dns.google with the given client and URL and
// verifies that the response is the one we expect.
func run(t *testing.T, dt *dnsoverstream.Transport) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	query := dnscodec.NewQuery("dns.google", dns.TypeA)
	resp, err := dt.Exchange(ctx, query)
	require.NoError(t, err)
	addrs, err := resp.RecordsA()
	require.NoError(t, err)
	slices.Sort(addrs)
	expectAddrs := []string{"8.8.4.4", "8.8.8.8"}
	assert.Equal(t, expectAddrs, addrs)
}

func TestIntegrationDNSOverTCPWorks(t *testing.T) {
	dt := dnsoverstream.NewTransportTCP(&net.Dialer{}, netip.MustParseAddrPort("8.8.8.8:53"))
	run(t, dt)
}

func TestIntegrationDNSOverTLSWorks(t *testing.T) {
	dialer := dnsoverstream.NewTLSDialerDNSOverTLS("dns.google")
	dt := dnsoverstream.NewTransportTLS(dialer, netip.MustParseAddrPort("8.8.8.8:853"))
	run(t, dt)
}

func TestIntegrationDNSOverQUICWorks(t *testing.T) {
	udpAddr, err := net.ResolveUDPAddr("udp4", "dns.adguard.com:853")
	require.NoError(t, err)

	lc := &net.ListenConfig{}
	pconn, err := lc.ListenPacket(context.Background(), "udp", ":0")
	require.NoError(t, err)
	defer pconn.Close()
	dialer := dnsoverstream.NewQUICDialer(pconn, "dns.adguard.com")

	dt := dnsoverstream.NewTransportQUIC(dialer, udpAddr.AddrPort())
	run(t, dt)
}

func TestMain(m *testing.M) {
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	os.Exit(m.Run())
}
