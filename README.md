# Golang DNS Transport for TCP, TLS, and QUIC

[![GoDoc](https://pkg.go.dev/badge/github.com/bassosimone/dnsoverstream)](https://pkg.go.dev/github.com/bassosimone/dnsoverstream) [![Build Status](https://github.com/bassosimone/dnsoverstream/actions/workflows/go.yml/badge.svg)](https://github.com/bassosimone/dnsoverstream/actions) [![codecov](https://codecov.io/gh/bassosimone/dnsoverstream/branch/main/graph/badge.svg)](https://codecov.io/gh/bassosimone/dnsoverstream)

The `dnsoverstream` Go package implements DNS transports for TCP, TLS,
and QUIC with a small API suited for measurements and testing.

Basic usage is like:

```Go
import (
	"context"
	"log"
	"net"
	"net/netip"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/dnsoverstream"
	"github.com/miekg/dns"
)

// 1a. create a DNS-over-TCP transport
tcpEndpoint := netip.MustParseAddrPort("8.8.8.8:53")
tcpTransport := dnsoverstream.NewTransportTCP(&net.Dialer{}, tcpEndpoint)

// 1b. create a DNS-over-TLS transport
tlsEndpoint := netip.MustParseAddrPort("8.8.8.8:853")
tlsDialer := dnsoverstream.NewTLSDialerDNSOverTLS("dns.google")
tlsTransport := dnsoverstream.NewTransportTLS(tlsDialer, tlsEndpoint)

// 1c. create a DNS-over-QUIC transport
lc := &net.ListenConfig{}
pconn, err := lc.ListenPacket(context.Background(), "udp", ":0")
if err != nil {
	log.Fatal(err)
}
defer pconn.Close()
quicDialer := dnsoverstream.NewQUICDialer(pconn, "dns.adguard.com")
quicEndpoint := netip.MustParseAddrPort("94.140.14.14:853")
quicTransport := dnsoverstream.NewTransportQUIC(quicDialer, quicEndpoint)

// 2. exchange the query with a response
query := dnscodec.NewQuery("dns.google", dns.TypeA)
resp, err := tcpTransport.Exchange(context.Background(), query)
if err != nil {
	log.Fatal(err)
}
```

## Features

- **Multiple protocols:** Supports TCP, TLS, and QUIC.

- **Small API:** One transport type with protocol-specific constructors.

- **Deterministic queries:** Mutates queries for each transport while
  keeping the caller's query intact.

- **Reusable connections:** Use `Transport.Dial` and
  `Transport.ExchangeWithStreamOpener` to reuse long-lived connections.

## Installation

To add this package as a dependency to your module:

```sh
go get github.com/bassosimone/dnsoverstream
```

## Development

To run the tests:

```sh
go test -v .
```

To measure test coverage:

```sh
go test -v -cover .
```

## License

```
SPDX-License-Identifier: GPL-3.0-or-later
```

## History

Adapted from [rbmk-project/rbmk](https://github.com/rbmk-project/rbmk/tree/v0.17.0).
