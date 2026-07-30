package server

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/settings"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

func TestIsSafeUploadName(t *testing.T) {
	valid := []string{
		"evil.dtd", "a", "a-b_c.1", "payload.xml", "x.tar.gz",
		strings.Repeat("a", 128),
	}
	for _, name := range valid {
		require.True(t, isSafeUploadName(name), "expected %q to be accepted", name)
	}

	invalid := []string{
		"", ".", "..", "...",
		"../evil", "../../etc/passwd", "a/b", "/etc/passwd",
		`..\evil`, `a\b`, `C:\evil`,
		".hidden", "-leading-dash",
		"evil\x00.dtd", "evil\n.dtd", "evil\r.dtd", "tab\t.dtd",
		"space name.dtd", `quote".dtd`, "semi;colon", "pipe|d",
		"percent%2e%2e", "unicodeé.dtd", "emoji\U0001f600",
		strings.Repeat("a", 129),
	}
	for _, name := range invalid {
		require.False(t, isSafeUploadName(name), "expected %q to be rejected", name)
	}
}

func newTestUploadStore(t *testing.T, tune func(*Options)) *UploadStore {
	t.Helper()

	dir := t.TempDir()
	options := &Options{
		CorrelationIdLength: settings.CorrelationIdLengthDefault,
		UploadDirectory:     dir,
		UploadMaxFileSize:   1024,
		UploadMaxFiles:      5,
		UploadMaxTotalSize:  1 << 20,
		UploadTTL:           time.Hour,
	}
	if tune != nil {
		tune(options)
	}

	store, err := NewUploadStore(options)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// newCorrelationID returns an id of the default configured length.
func newCorrelationID(t *testing.T) string {
	t.Helper()
	id := xid.New().String() + strings.Repeat("z", settings.CorrelationIdLengthDefault)
	return id[:settings.CorrelationIdLengthDefault]
}

func TestUploadStoreSaveOpen(t *testing.T) {
	store := newTestUploadStore(t, nil)
	id := newCorrelationID(t)

	t.Run("round trip", func(t *testing.T) {
		content := []byte(`<!ENTITY % exfil SYSTEM "file:///etc/passwd">`)
		size, sum, err := store.Save(id, "evil.dtd", content, 0)
		require.NoError(t, err)
		require.EqualValues(t, len(content), size)
		require.Len(t, sum, 64, "sha256 hex digest")

		f, fi, err := store.Open(id, "evil.dtd")
		require.NoError(t, err)
		defer f.Close()

		got, err := io.ReadAll(f)
		require.NoError(t, err)
		require.Equal(t, content, got)
		require.EqualValues(t, len(content), fi.Size())
	})

	t.Run("no temp files left visible", func(t *testing.T) {
		entries, err := os.ReadDir(filepath.Join(store.sessionsRoot, id))
		require.NoError(t, err)
		for _, e := range entries {
			require.False(t, strings.HasPrefix(e.Name(), ".upload-"),
				"partial write %q should have been renamed into place", e.Name())
		}
	})

	t.Run("rejects unsafe name", func(t *testing.T) {
		_, _, err := store.Save(id, "../escape", []byte("x"), 0)
		require.Error(t, err)
		var ue *UploadError
		require.True(t, errors.As(err, &ue))
		require.Equal(t, UploadErrBadName, ue.Kind)
	})

	t.Run("rejects empty file", func(t *testing.T) {
		_, _, err := store.Save(id, "empty.dtd", nil, 0)
		require.Error(t, err)
	})

	t.Run("rejects oversize file", func(t *testing.T) {
		_, _, err := store.Save(id, "big.dtd", make([]byte, 2048), 0)
		require.Error(t, err)
		var ue *UploadError
		require.True(t, errors.As(err, &ue))
		require.Equal(t, UploadErrTooLarge, ue.Kind)
	})

	t.Run("rejects invalid correlation id", func(t *testing.T) {
		_, _, err := store.Save("../..", "x.dtd", []byte("x"), 0)
		require.Error(t, err)
	})

	t.Run("open rejects traversal", func(t *testing.T) {
		_, _, err := store.Open(id, "../../etc/passwd")
		require.Error(t, err)
	})

	t.Run("open rejects unknown file", func(t *testing.T) {
		_, _, err := store.Open(id, "absent.dtd")
		require.Error(t, err)
	})
}

func TestUploadStoreGlobalQuota(t *testing.T) {
	store := newTestUploadStore(t, func(o *Options) {
		o.UploadMaxFileSize = 1024
		o.UploadMaxTotalSize = 2048
	})

	id := newCorrelationID(t)
	_, _, err := store.Save(id, "a.bin", make([]byte, 1024), 0)
	require.NoError(t, err)
	_, _, err = store.Save(id, "b.bin", make([]byte, 1024), 0)
	require.NoError(t, err)

	_, _, err = store.Save(id, "c.bin", make([]byte, 1024), 0)
	require.Error(t, err, "third file should exhaust the global cap")
	var ue *UploadError
	require.True(t, errors.As(err, &ue))
	require.Equal(t, UploadErrOutOfSpace, ue.Kind)

	// Overwriting an existing name must account for the space it already holds
	// rather than double-counting it.
	_, _, err = store.Save(id, "a.bin", make([]byte, 1024), 1024)
	require.NoError(t, err, "replacing a file of equal size must not exceed the cap")
}

func TestUploadStoreRemoveSession(t *testing.T) {
	store := newTestUploadStore(t, nil)
	store.Start()

	id := newCorrelationID(t)
	_, _, err := store.Save(id, "evil.dtd", []byte("payload"), 0)
	require.NoError(t, err)
	require.DirExists(t, filepath.Join(store.sessionsRoot, id))

	store.RemoveSession(id)
	require.Eventually(t, func() bool {
		_, err := os.Stat(filepath.Join(store.sessionsRoot, id))
		return os.IsNotExist(err)
	}, 2*time.Second, 10*time.Millisecond)

	// Idempotent: a second removal of a gone session must not error or panic.
	store.RemoveSession(id)
	store.RemoveSession(newCorrelationID(t))
	time.Sleep(50 * time.Millisecond)
}

func TestUploadStoreSweep(t *testing.T) {
	store := newTestUploadStore(t, func(o *Options) { o.UploadTTL = time.Hour })

	stale := newCorrelationID(t)
	fresh := newCorrelationID(t)
	_, _, err := store.Save(stale, "old.dtd", []byte("old"), 0)
	require.NoError(t, err)
	_, _, err = store.Save(fresh, "new.dtd", []byte("new"), 0)
	require.NoError(t, err)

	// Operator files sharing the root (the -ftp-dir case) must survive, including
	// a directory whose name happens to look exactly like a correlation id: the
	// sweeper only ever descends into its own directory, so a collision in the
	// operator's namespace cannot cost them data.
	sibling := filepath.Join(store.Root(), "operator-notes.txt")
	require.NoError(t, os.WriteFile(sibling, []byte("keep me"), 0o600))
	siblingDir := filepath.Join(store.Root(), "operator-dir")
	require.NoError(t, os.Mkdir(siblingDir, 0o700))
	require.NoError(t, os.Chtimes(siblingDir, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour)))
	lookalike := filepath.Join(store.Root(), newCorrelationID(t))
	require.NoError(t, os.Mkdir(lookalike, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(lookalike, "payload.txt"), []byte("operator payload"), 0o600))
	require.NoError(t, os.Chtimes(lookalike, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour)))

	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(filepath.Join(store.sessionsRoot, stale), old, old))

	store.sweep()

	require.NoDirExists(t, filepath.Join(store.sessionsRoot, stale), "expired session should be swept")
	require.DirExists(t, filepath.Join(store.sessionsRoot, fresh), "live session should survive")
	require.FileExists(t, sibling, "non-session file must not be swept")
	require.DirExists(t, siblingDir, "non-session directory must not be swept even when old")
	require.FileExists(t, filepath.Join(lookalike, "payload.txt"),
		"an operator directory shaped like a correlation id must survive")
}

func TestUploadStorePurgeOnStart(t *testing.T) {
	dir := t.TempDir()

	orphan := newCorrelationID(t)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, uploadsDirName, orphan), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, uploadsDirName, orphan, "stale.dtd"), []byte("x"), 0o600))

	keepFile := filepath.Join(dir, "index.html")
	require.NoError(t, os.WriteFile(keepFile, []byte("operator content"), 0o600))
	keepDir := filepath.Join(dir, "assets")
	require.NoError(t, os.Mkdir(keepDir, 0o700))
	// The startup purge is name-shape driven, so an operator directory that
	// matches that shape has to be out of its reach structurally.
	lookalike := filepath.Join(dir, newCorrelationID(t))
	require.NoError(t, os.Mkdir(lookalike, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(lookalike, "payload.txt"), []byte("operator payload"), 0o600))

	store := newTestUploadStore(t, func(o *Options) { o.UploadDirectory = dir })

	require.NoDirExists(t, filepath.Join(dir, uploadsDirName, orphan), "orphaned session dir should be purged at startup")
	require.FileExists(t, keepFile, "operator file must survive startup purge")
	require.DirExists(t, keepDir, "operator directory must survive startup purge")
	require.FileExists(t, filepath.Join(lookalike, "payload.txt"),
		"an operator directory shaped like a correlation id must survive the purge")
	_ = store
}

func TestUploadStoreRootResolution(t *testing.T) {
	t.Run("prefers upload directory", func(t *testing.T) {
		up, ftp := t.TempDir(), t.TempDir()
		store, err := NewUploadStore(&Options{
			CorrelationIdLength: settings.CorrelationIdLengthDefault,
			UploadDirectory:     up, FTPDirectory: ftp, UploadTTL: time.Hour,
		})
		require.NoError(t, err)
		defer store.Close()
		require.Equal(t, up, store.Root())
	})

	t.Run("falls back to ftp directory", func(t *testing.T) {
		ftp := t.TempDir()
		store, err := NewUploadStore(&Options{
			CorrelationIdLength: settings.CorrelationIdLengthDefault,
			FTPDirectory:        ftp, UploadTTL: time.Hour,
		})
		require.NoError(t, err)
		defer store.Close()
		require.Equal(t, ftp, store.Root(), "sharing the FTP root is what makes FTP serving work")
	})

	t.Run("creates a shared ftp directory that does not exist yet", func(t *testing.T) {
		// -ftp alone never required -ftp-dir to exist, so adopting it as the
		// upload root must not turn a working deployment into a boot failure.
		ftp := filepath.Join(t.TempDir(), "not-created-yet")
		store, err := NewUploadStore(&Options{
			CorrelationIdLength: settings.CorrelationIdLengthDefault,
			FTPDirectory:        ftp, UploadTTL: time.Hour,
		})
		require.NoError(t, err)
		defer store.Close()
		require.DirExists(t, ftp)
		require.DirExists(t, filepath.Join(ftp, uploadsDirName))
	})

	t.Run("sessions live under the uploads directory", func(t *testing.T) {
		up := t.TempDir()
		store, err := NewUploadStore(&Options{
			CorrelationIdLength: settings.CorrelationIdLengthDefault,
			UploadDirectory:     up, UploadTTL: time.Hour, UploadMaxFileSize: 1024, UploadMaxTotalSize: 4096,
		})
		require.NoError(t, err)
		defer store.Close()

		id := newCorrelationID(t)
		_, _, err = store.Save(id, "evil.dtd", []byte("payload"), 0)
		require.NoError(t, err)
		require.FileExists(t, filepath.Join(up, uploadsDirName, id, "evil.dtd"))
		require.NoDirExists(t, filepath.Join(up, id), "nothing of ours belongs at the root")
	})

	t.Run("falls back to a temp directory", func(t *testing.T) {
		store, err := NewUploadStore(&Options{
			CorrelationIdLength: settings.CorrelationIdLengthDefault,
			UploadTTL:           time.Hour,
		})
		require.NoError(t, err)
		defer func() {
			root := store.Root()
			_ = store.Close()
			_ = os.RemoveAll(root)
		}()
		require.DirExists(t, store.Root())
	})
}

// A directory can exist and still be unwritable, in which case MkdirAll succeeds
// and every upload fails later. The server must refuse to start instead.
func TestUploadStoreRejectsUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses the permission bits this test relies on")
	}

	t.Run("read-only root", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "uploads")
		require.NoError(t, os.Mkdir(dir, 0o500))
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

		_, err := NewUploadStore(&Options{
			CorrelationIdLength: settings.CorrelationIdLengthDefault,
			UploadDirectory:     dir, UploadTTL: time.Hour,
		})
		require.Error(t, err, "an unwritable upload directory must not start the server")
		require.Contains(t, err.Error(), dir)
	})

	t.Run("sessions directory exists but is read-only", func(t *testing.T) {
		// The case MkdirAll cannot catch: the directory it would have created is
		// already there, so it returns nil and only a write reveals the problem.
		dir := t.TempDir()
		sessions := filepath.Join(dir, uploadsDirName)
		require.NoError(t, os.Mkdir(sessions, 0o500))
		t.Cleanup(func() { _ = os.Chmod(sessions, 0o700) })

		_, err := NewUploadStore(&Options{
			CorrelationIdLength: settings.CorrelationIdLengthDefault,
			UploadDirectory:     dir, UploadTTL: time.Hour,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not writable")
	})

	t.Run("writable root is accepted and left clean", func(t *testing.T) {
		dir := t.TempDir()
		store, err := NewUploadStore(&Options{
			CorrelationIdLength: settings.CorrelationIdLengthDefault,
			UploadDirectory:     dir, UploadTTL: time.Hour,
		})
		require.NoError(t, err)
		defer store.Close()

		entries, err := os.ReadDir(filepath.Join(dir, uploadsDirName))
		require.NoError(t, err)
		require.Empty(t, entries, "the probe file must not be left behind")
	})
}
