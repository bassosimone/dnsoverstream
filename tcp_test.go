// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverstream

import (
	"errors"
	"testing"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/netstub"
	"github.com/stretchr/testify/require"
)

func TestNewTCPStreamOpener(t *testing.T) {
	t.Run("returns valid StreamOpener", func(t *testing.T) {
		conn := &netstub.FuncConn{
			CloseFunc: func() error { return nil },
		}
		opener := NewTCPStreamOpener(conn)
		require.NotNil(t, opener)
	})

	t.Run("OpenStream returns working stream", func(t *testing.T) {
		var written []byte
		conn := &netstub.FuncConn{
			WriteFunc: func(b []byte) (int, error) {
				written = append(written, b...)
				return len(b), nil
			},
			CloseFunc: func() error { return nil },
		}

		opener := NewTCPStreamOpener(conn)
		stream, err := opener.OpenStream()
		require.NoError(t, err)

		n, err := stream.Write([]byte("hello"))
		require.NoError(t, err)
		require.Equal(t, 5, n)
		require.Equal(t, []byte("hello"), written)

		// Close should be a no-op for TCP streams
		require.NoError(t, stream.Close())

		// Close the opener should close the underlying connection
		require.NoError(t, opener.Close())
	})

	t.Run("SetDeadline works", func(t *testing.T) {
		var gotDeadline time.Time
		conn := &netstub.FuncConn{
			SetDeadlineFunc: func(t time.Time) error {
				gotDeadline = t
				return nil
			},
		}

		opener := NewTCPStreamOpener(conn)
		stream, err := opener.OpenStream()
		require.NoError(t, err)

		deadline := time.Now().Add(time.Second)
		err = stream.SetDeadline(deadline)
		require.NoError(t, err)
		require.Equal(t, deadline, gotDeadline)
	})

	t.Run("Close closes underlying connection", func(t *testing.T) {
		var closed bool
		conn := &netstub.FuncConn{
			CloseFunc: func() error {
				closed = true
				return nil
			},
		}

		opener := NewTCPStreamOpener(conn)
		require.NoError(t, opener.Close())
		require.True(t, closed)
	})

	t.Run("Close propagates error", func(t *testing.T) {
		expected := errors.New("close failed")
		conn := &netstub.FuncConn{
			CloseFunc: func() error { return expected },
		}

		opener := NewTCPStreamOpener(conn)
		err := opener.Close()
		require.ErrorIs(t, err, expected)
	})
}

func TestTcpStreamConnMutateQuery(t *testing.T) {
	opener := NewTCPStreamOpener(nil)
	query := dnscodec.NewQuery("example.com", 1)

	opener.MutateQuery(query)

	require.Equal(t, uint16(dnscodec.QueryMaxResponseSizeTCP), query.MaxSize)
	require.Zero(t, query.Flags&dnscodec.QueryFlagBlockLengthPadding)
	require.Zero(t, query.Flags&dnscodec.QueryFlagDNSSec)
}
