package server

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	ftpserver "goftp.io/server/v2"
)

func TestIsFTPRoot(t *testing.T) {
	for _, p := range []string{"/", "", ".", "//", "/.", "/../.."} {
		require.True(t, isFTPRoot(p), "expected %q to be treated as root", p)
	}
	for _, p := range []string{"/c6rj61aciaeutn2ae680", "/a/b", "/evil.dtd", "/dir/"} {
		require.False(t, isFTPRoot(p), "expected %q not to be treated as root", p)
	}
}

// countingDriver records which paths reached the wrapped driver, and reports the
// entries it was configured with for each of them.
type countingDriver struct {
	ftpserver.Driver
	listed  []string
	entries []string
}

func (d *countingDriver) ListDir(c *ftpserver.Context, s string, f func(os.FileInfo) error) error {
	d.listed = append(d.listed, s)
	for _, name := range d.entries {
		if err := f(dirEntryInfo(name)); err != nil {
			return err
		}
	}
	return nil
}

// dirEntryInfo is a minimal os.FileInfo standing in for a directory entry.
type dirEntryInfo string

func (d dirEntryInfo) Name() string       { return string(d) }
func (d dirEntryInfo) Size() int64        { return 0 }
func (d dirEntryInfo) Mode() os.FileMode  { return os.ModeDir | 0o700 }
func (d dirEntryInfo) ModTime() time.Time { return time.Time{} }
func (d dirEntryInfo) IsDir() bool        { return true }
func (d dirEntryInfo) Sys() interface{}   { return nil }

func TestIsUploadsDir(t *testing.T) {
	for _, p := range []string{
		"/" + uploadsDirName,
		"/" + uploadsDirName + "/",
		"//" + uploadsDirName,
		"/./" + uploadsDirName,
		"/other/../" + uploadsDirName,
		"/" + uploadsDirName + "/.",
	} {
		require.True(t, isUploadsDir(p), "expected %q to resolve to the uploads directory", p)
	}
	for _, p := range []string{
		"/",
		"/" + uploadsDirName + "/c6rj61aciaeutn2ae680",
		"/nested/" + uploadsDirName,
		"/" + uploadsDirName + "-other",
	} {
		require.False(t, isUploadsDir(p), "expected %q not to resolve to the uploads directory", p)
	}
}

// NopAuth accepts any credentials, so an unauthenticated client must not be able
// to enumerate the correlation ids that currently have hosted files.
func TestNopDriverHidesUploadsDir(t *testing.T) {
	t.Run("the uploads directory never enumerates", func(t *testing.T) {
		for _, p := range []string{
			"/" + uploadsDirName,
			"/" + uploadsDirName + "/",
			"//" + uploadsDirName,
			"/./" + uploadsDirName,
			"/pub/../" + uploadsDirName,
		} {
			inner := &countingDriver{entries: []string{"c6rj61aciaeutn2ae680", "c6rj61aciaeutn2ae681"}}
			driver := NewNopDriver(inner)

			var seen []string
			require.NoError(t, driver.ListDir(nil, p, func(fi os.FileInfo) error {
				seen = append(seen, fi.Name())
				return nil
			}))
			require.Empty(t, seen, "%q must not enumerate correlation ids", p)
			require.Empty(t, inner.listed, "%q must not even reach the filesystem", p)
		}
	})

	t.Run("the root lists operator content without the uploads directory", func(t *testing.T) {
		inner := &countingDriver{entries: []string{"index.html", uploadsDirName, "assets"}}
		driver := NewNopDriver(inner)

		var seen []string
		require.NoError(t, driver.ListDir(nil, "/", func(fi os.FileInfo) error {
			seen = append(seen, fi.Name())
			return nil
		}))
		require.Equal(t, []string{"index.html", "assets"}, seen,
			"-ftp-dir is documented as serving the operator's directory, minus our own")
	})

	t.Run("a session directory still lists for a client that knows its id", func(t *testing.T) {
		inner := &countingDriver{entries: []string{"evil.dtd"}}
		driver := NewNopDriver(inner)
		p := "/" + uploadsDirName + "/c6rj61aciaeutn2ae680"

		var seen []string
		require.NoError(t, driver.ListDir(nil, p, func(fi os.FileInfo) error {
			seen = append(seen, fi.Name())
			return nil
		}))
		require.Equal(t, []string{"evil.dtd"}, seen)
		require.Equal(t, []string{p}, inner.listed)
	})
}

func TestFTPDownloadCorrelation(t *testing.T) {
	newFTP := func(t *testing.T) (*FTPServer, *HTTPServer, string, string) {
		t.Helper()
		h, id, secret := uploadTestServer(t, true)
		h.options.Token = "shared-token"
		require.NoError(t, h.options.Storage.SetID(h.options.Token))

		resp := doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"evil.dtd": []byte("payload")}))
		require.Equal(t, http.StatusOK, resp.StatusCode)

		return &FTPServer{options: h.options}, h, id, secret
	}

	t.Run("download attributed to the owning session", func(t *testing.T) {
		ftp, h, id, _ := newFTP(t)

		hosted := "/" + uploadsDirName + "/" + id + "/evil.dtd"
		ftp.recordInteractionForPath("198.51.100.4:3333", "RETR "+hosted+"\ndownloaded file", hosted)

		item, err := h.options.Storage.GetCacheItem(id)
		require.NoError(t, err)
		require.Len(t, item.Data, 1, "the owning session should see its own file being fetched")

		record := &Interaction{}
		require.NoError(t, json.Unmarshal([]byte(item.Data[0]), record))
		require.Equal(t, "ftp", record.Protocol)
		require.Equal(t, id, record.UniqueID)

		// And it must not also land in the shared bucket, or every client sees it.
		shared, err := h.options.Storage.GetCacheItem(h.options.Token)
		require.NoError(t, err)
		require.Empty(t, shared.Data, "an attributed download must not be duplicated to the token bucket")
	})

	t.Run("unattributable interactions still use the token bucket", func(t *testing.T) {
		ftp, h, _, _ := newFTP(t)

		// A login has no path, and a path outside any session cannot be attributed.
		ftp.recordInteraction("198.51.100.4:3333", "USER anonymous\nlogging in")
		ftp.recordInteractionForPath("198.51.100.4:3333", "RETR /nope\ndownloaded file", "/nope")

		shared, err := h.options.Storage.GetCacheItem(h.options.Token)
		require.NoError(t, err)
		require.Len(t, shared.Data, 2, "unattributable FTP noise keeps its existing behaviour")
	})

	t.Run("path for an unknown session is not attributed", func(t *testing.T) {
		ftp, h, _, _ := newFTP(t)
		unknown := "c6rj61aciaeutn2ae681"

		require.Equal(t, "", ftp.correlationIDFromPath("/"+uploadsDirName+"/"+unknown+"/evil.dtd"),
			"only live sessions should be attributed")

		shared, err := h.options.Storage.GetCacheItem(h.options.Token)
		require.NoError(t, err)
		require.Empty(t, shared.Data)
	})

	// Paths are cleaned before the leading segment is taken, so traversal can
	// only ever resolve to the session it actually points at -- never to a
	// different one, and never outside the hosted-files root.
	t.Run("traversal resolves before attribution", func(t *testing.T) {
		ftp, _, id, _ := newFTP(t)

		// Leading ".." is dropped at the root, so this still names id.
		require.Equal(t, id, ftp.correlationIDFromPath("/../"+uploadsDirName+"/"+id+"/evil.dtd"))
		require.Equal(t, id, ftp.correlationIDFromPath("//"+uploadsDirName+"/"+id+"/evil.dtd"))

		// Climbing out of a session directory stops attributing to it.
		require.Equal(t, "", ftp.correlationIDFromPath("/"+uploadsDirName+"/"+id+"/../other/evil.dtd"))
		require.Equal(t, "", ftp.correlationIDFromPath("/"+uploadsDirName+"/"+id+"/.."))

		// A path outside the uploads directory is not ours, however much it looks
		// like a session: an operator directory at the FTP root shares that shape.
		require.Equal(t, "", ftp.correlationIDFromPath("/"+id+"/evil.dtd"),
			"only paths under the uploads directory may be attributed")
	})
}
