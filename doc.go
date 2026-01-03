// SPDX-License-Identifier: GPL-3.0-or-later

// Package dnsoverstream implements DNS over TCP, TLS, and QUIC transports.
//
// The API is intentionally small and designed for measurement use cases.
//
// Each Transport targets a single netip.AddrPort endpoint and does not reuse
// connections across requests.
package dnsoverstream
