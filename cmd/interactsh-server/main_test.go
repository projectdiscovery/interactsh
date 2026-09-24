package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The FTP and upload roots decide whether hosted files are reachable over ftp://,
// so they have to be compared as directories rather than as the strings the
// operator typed: warning about a working configuration teaches them to ignore
// the warning that matters.
func TestSameDirectory(t *testing.T) {
	base := t.TempDir()
	shared := filepath.Join(base, "shared")
	require.NoError(t, os.Mkdir(shared, 0o700))
	other := filepath.Join(base, "other")
	require.NoError(t, os.Mkdir(other, 0o700))

	link := filepath.Join(base, "link")
	require.NoError(t, os.Symlink(shared, link))

	wd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(wd) })
	require.NoError(t, os.Chdir(base))

	t.Run("same directory in different spellings", func(t *testing.T) {
		for _, pair := range [][2]string{
			{shared, shared},
			{shared, shared + string(filepath.Separator)},
			{shared, filepath.Join(base, ".", "shared")},
			{shared, filepath.Join(base, "other", "..", "shared")},
			{"./shared", "shared"},
			{"./shared", shared},
			{link, shared},
		} {
			got, err := sameDirectory(pair[0], pair[1])
			require.NoError(t, err)
			require.True(t, got, "%q and %q are the same directory", pair[0], pair[1])
		}
	})

	t.Run("genuinely different directories", func(t *testing.T) {
		for _, pair := range [][2]string{
			{shared, other},
			{"./shared", "./other"},
			{shared, filepath.Join(base, "absent")},
		} {
			got, err := sameDirectory(pair[0], pair[1])
			require.NoError(t, err)
			require.False(t, got, "%q and %q are different directories", pair[0], pair[1])
		}
	})

	// EvalSymlinks fails on a path that does not exist, which is not a reason to
	// refuse to start: -ftp-dir may legitimately not exist yet.
	t.Run("missing paths compare by cleaned absolute form", func(t *testing.T) {
		missing := filepath.Join(base, "not-created-yet")
		got, err := sameDirectory(missing, missing+string(filepath.Separator))
		require.NoError(t, err)
		require.True(t, got)
	})
}
