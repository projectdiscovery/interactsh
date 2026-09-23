package main

import (
	"os"
	"path/filepath"
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

// -psf is a machine interface: one payload hostname per line, exactly -n of them.
// A consumer substitutes each line into a payload template, so a line carrying a
// full URL produces nonsense, and a missing trailing newline costs it the last
// record.
func TestWriteLines(t *testing.T) {
	t.Run("one record per line, newline terminated", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "payloads.txt")
		payloads := []string{
			"c6rj61aciaeutn2ae680ti6cc3rxeenc3.oast.pro",
			"c6rj61aciaeutn2ae680xk4tqy8pqhwmi.oast.pro",
		}
		require.NoError(t, writeLines(path, payloads))

		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, strings.Join(payloads, "\n")+"\n", string(raw))

		// What "while read" and "wc -l" see, which is the point of the terminator.
		require.Equal(t, len(payloads), strings.Count(string(raw), "\n"))
		require.Equal(t, payloads, strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n"))
	})

	t.Run("no record is a valid empty file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.txt")
		require.NoError(t, writeLines(path, nil))
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Empty(t, raw, "an empty list must not leave a stray newline")
	})

	t.Run("hosted file URLs stay in their own file", func(t *testing.T) {
		dir := t.TempDir()
		payloads := []string{"c6rj61aciaeutn2ae680ti6cc3rxeenc3.oast.pro"}
		fileURLs := []string{
			"https://c6rj61aciaeutn2ae680xk4tqy8pqhwmi.oast.pro/f/evil.dtd",
			"ftp://c6rj61aciaeutn2ae680xk4tqy8pqhwmi.oast.pro/.interactsh-user-uploads/c6rj61aciaeutn2ae680/evil.dtd",
		}
		payloadFile := filepath.Join(dir, "payloads.txt")
		urlFile := filepath.Join(dir, "files.txt")
		require.NoError(t, writeLines(payloadFile, payloads))
		require.NoError(t, writeLines(urlFile, fileURLs))

		gotPayloads, err := os.ReadFile(payloadFile)
		require.NoError(t, err)
		require.NotContains(t, string(gotPayloads), "://",
			"a payload file line must be a hostname, never a URL")

		gotURLs, err := os.ReadFile(urlFile)
		require.NoError(t, err)
		require.Equal(t, strings.Join(fileURLs, "\n")+"\n", string(gotURLs))
	})
}
