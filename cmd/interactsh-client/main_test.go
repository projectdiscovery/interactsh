package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestElectionHint(t *testing.T) {
	t.Run("stays silent for a single server", func(t *testing.T) {
		// Nothing to disambiguate: the message already names the only server.
		require.Empty(t, electionHint("https://oast.pro"))
		require.Empty(t, electionHint(""))
		// A trailing comma still describes one server.
		require.Empty(t, electionHint("https://oast.pro,"))
	})

	t.Run("names the count when several were listed", func(t *testing.T) {
		hint := electionHint("oast.pro,oast.live,oast.site")
		require.Contains(t, hint, "3 servers")
		require.Contains(t, hint, "pass a single server with -file",
			"the hint must say what to do, not just what happened")
	})

	t.Run("ignores blank entries and whitespace", func(t *testing.T) {
		require.Empty(t, electionHint(" , "))
		require.Contains(t, electionHint("oast.pro, oast.live"), "2 servers")
	})

	t.Run("reads as a suffix to the failure sentence", func(t *testing.T) {
		hint := electionHint("a.example,b.example")
		require.True(t, strings.HasPrefix(hint, " ("), "must append cleanly after the message")
		require.True(t, strings.HasSuffix(hint, ")"))
	})
}
