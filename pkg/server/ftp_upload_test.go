package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestIsFTPRoot(t *testing.T) {
	for _, p := range []string{"/", "", ".", "//", "/.", "/../.."} {
		require.True(t, isFTPRoot(p), "expected %q to be treated as root", p)
	}
	for _, p := range []string{"/c6rj61aciaeutn2ae680", "/a/b", "/evil.dtd", "/dir/"} {
		require.False(t, isFTPRoot(p), "expected %q not to be treated as root", p)
	}
}

func TestIsUploadsDir(t *testing.T) {
	for _, p := range []string{
		"/" + uploadsDirName,
		"/" + uploadsDirName + "/",
		"//" + uploadsDirName,
		"/./" + uploadsDirName,
		"/other/../" + uploadsDirName,
		"/" + uploadsDirName + "/.",
		// Backslashes on Windows, where the file system splits on them too.
		filepath.FromSlash("/other/../") + uploadsDirName,
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

// AuthUser accepts any credentials, so an unauthenticated client must not be
// able to enumerate the correlation ids that currently have hosted files.
func TestFTPSessionHidesUploadsDir(t *testing.T) {
	const id = "c6rj61aciaeutn2ae680"
	fs := afero.NewMemMapFs()
	for _, p := range []string{
		"/index.html",
		"/assets/app.js",
		"/" + uploadsDirName + "/" + id + "/evil.dtd",
		"/" + uploadsDirName + "/c6rj61aciaeutn2ae681/evil.dtd",
	} {
		require.NoError(t, afero.WriteFile(fs, p, nil, 0o600))
	}
	session := &ftpSession{Fs: fs}

	list := func(t *testing.T, p string) []string {
		t.Helper()
		entries, err := session.ReadDir(p)
		require.NoError(t, err)
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		return names
	}

	t.Run("the uploads directory never enumerates", func(t *testing.T) {
		for _, p := range []string{
			"/" + uploadsDirName,
			"/" + uploadsDirName + "/",
			"//" + uploadsDirName,
			"/./" + uploadsDirName,
			"/pub/../" + uploadsDirName,
			filepath.FromSlash("/pub/../") + uploadsDirName,
		} {
			require.Empty(t, list(t, p), "%q must not enumerate correlation ids", p)
		}
	})

	t.Run("the root lists operator content without the uploads directory", func(t *testing.T) {
		require.Equal(t, []string{"assets", "index.html"}, list(t, "/"),
			"-ftp-dir is documented as serving the operator's directory, minus our own")
	})

	t.Run("a session directory still lists for a client that knows its id", func(t *testing.T) {
		require.Equal(t, []string{"evil.dtd"}, list(t, "/"+uploadsDirName+"/"+id))
	})
}

// ftpserverlib quotes driver errors in its replies, so errors from a file that
// opened fine must not give the on-disk path either.
func TestFTPFileErrorsGiveClientPath(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.Mkdir("/pub", 0o700))
	session := &ftpSession{Fs: brokenFs{fs}}

	_, err := session.ReadDir("/pub")
	require.ErrorIs(t, err, syscall.EIO)
	require.NotContains(t, err.Error(), "/srv/ftp")

	f, err := session.Open("/pub")
	require.NoError(t, err)
	_, err = downloadFile{File: f, name: "/pub"}.Read(make([]byte, 1))
	require.ErrorIs(t, err, syscall.EIO)
	require.NotContains(t, err.Error(), "/srv/ftp")
}

// brokenFs opens files that fail every read with an error that names an
// on-disk path.
type brokenFs struct{ afero.Fs }

func (fs brokenFs) Open(name string) (afero.File, error) {
	f, err := fs.Fs.Open(name)
	if err != nil {
		return nil, err
	}
	return brokenFile{f}, nil
}

type brokenFile struct{ afero.File }

func (brokenFile) Read([]byte) (int, error)           { return 0, errOnDisk("read") }
func (brokenFile) Readdir(int) ([]os.FileInfo, error) { return nil, errOnDisk("readdirent") }

func errOnDisk(op string) error {
	return &os.PathError{Op: op, Path: "/srv/ftp/pub", Err: syscall.EIO}
}

// TestFTPServerSession drives a real client session, because ftpserverlib
// picks up the driver's hooks by type assertion and only a session shows that
// each one is reached.
func TestFTPServerSession(t *testing.T) {
	h, id, secret := uploadTestServer(t, true)
	options := h.options
	options.Token = "shared-token"
	require.NoError(t, options.Storage.SetID(options.Token))
	// Line breaks show whether a download is converted to CRLF.
	payload := "<!ENTITY % a \"b\">\n<!ENTITY % c \"d\">\n"
	resp := doUpload(t, h, uploadBody(t, id, secret, map[string][]byte{"evil.dtd": []byte(payload)}))
	require.Equal(t, http.StatusOK, resp.StatusCode)

	root := options.UploadStore.Root()
	index := filepath.Join(root, "index.html")
	require.NoError(t, os.WriteFile(index, []byte("operator"), 0o600))
	options.FTPDirectory = root

	ftp, err := NewFTPServer(options)
	require.NoError(t, err)
	require.NoError(t, ftp.ftpServer.Listen())
	go func() { _ = ftp.ftpServer.Serve() }()
	t.Cleanup(ftp.Close)

	_, port, err := net.SplitHostPort(ftp.ftpServer.Addr())
	require.NoError(t, err)
	c, err := textproto.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	send := func(code int, format string, args ...any) string {
		t.Helper()
		require.NoError(t, c.PrintfLine(format, args...))
		_, msg, err := c.ReadResponse(code)
		require.NoError(t, err, format)
		return msg
	}
	// dial opens a data connection over EPSV.
	dial := func() net.Conn {
		t.Helper()
		msg := send(229, "EPSV")
		_, rest, ok := strings.Cut(msg, "|||")
		require.True(t, ok, msg)
		dataPort, _, _ := strings.Cut(rest, "|")
		data, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", dataPort))
		require.NoError(t, err)
		return data
	}
	// transfer runs a data command, sending upload if it is not nil, and
	// returns what the server sent.
	transfer := func(upload []byte, format string, args ...any) []byte {
		t.Helper()
		data := dial()
		send(150, format, args...)
		var got []byte
		if upload != nil {
			_, err = data.Write(upload)
		} else {
			got, err = io.ReadAll(data)
		}
		require.NoError(t, err)
		require.NoError(t, data.Close())
		_, _, err = c.ReadResponse(226)
		require.NoError(t, err, format)
		return got
	}
	names := func(listing []byte) []string {
		return strings.Fields(string(listing))
	}

	_, _, err = c.ReadResponse(220)
	require.NoError(t, err)
	send(331, "USER anonymous")
	send(230, "PASS hunter2")

	require.Equal(t, []string{"index.html"}, names(transfer(nil, "NLST /")),
		"the uploads directory must not be discoverable")
	require.Empty(t, names(transfer(nil, "NLST /%s", uploadsDirName)),
		"the uploads directory must not enumerate correlation ids")

	hosted := "/" + uploadsDirName + "/" + id + "/evil.dtd"
	require.Equal(t, payload, string(transfer(nil, "RETR %s", hosted)),
		"a hosted file must arrive byte for byte, even without TYPE I")

	// Writes succeed for the client and change nothing on disk.
	transfer([]byte("overwritten"), "STOR /index.html")
	transfer([]byte("appended"), "APPE /index.html")
	send(257, "MKD /made")
	send(257, "XMKD /made")
	send(250, "RMD /made")
	send(250, "DELE /index.html")
	send(350, "RNFR /index.html")
	send(250, "RNTO /renamed.html")
	// Writes the driver does not fake are refused.
	before, err := os.Stat(index)
	require.NoError(t, err)
	send(550, "SITE CHMOD 755 /index.html")
	after, err := os.Stat(index)
	require.NoError(t, err)
	require.Equal(t, before.Mode(), after.Mode())
	content, err := os.ReadFile(index)
	require.NoError(t, err)
	require.Equal(t, "operator", string(content))
	require.NoDirExists(t, filepath.Join(root, "made"))
	require.NoFileExists(t, filepath.Join(root, "renamed.html"))

	// Error replies give the client's path, never where the root is on disk.
	for _, cmd := range []string{"SIZE /nope", "MDTM /nope", "MLST /nope", "RNFR /nope"} {
		require.NotContains(t, send(550, "%s", cmd), root, cmd)
	}
	require.NotContains(t, send(450, "STAT /nope"), root)
	send(229, "EPSV")
	require.NotContains(t, send(450, "NLST /nope"), root)
	send(229, "EPSV")
	require.NotContains(t, send(550, "RETR /nope"), root)
	send(350, "REST -1")
	send(229, "EPSV")
	require.NotContains(t, send(550, "RETR /index.html"), root, "a seek that fails")
	// The data connection is ready, so a transfer would start at once with a
	// 150 instead of the refusal.
	data := dial()
	require.NotContains(t, send(550, "RETR /"), root, "a directory is refused before any read")
	require.NoError(t, data.Close())

	// ftpserverlib has no hook for these: Stat records them.
	send(250, "CWD /%s", uploadsDirName)
	send(250, "CDUP")
	send(250, "XCWD /%s", uploadsDirName)

	requests := func(token string) []string {
		t.Helper()
		item, err := options.Storage.GetCacheItem(token)
		require.NoError(t, err)
		var raw []string
		for _, data := range item.Data {
			interaction := &Interaction{}
			require.NoError(t, json.Unmarshal([]byte(data), interaction))
			require.Equal(t, "ftp", interaction.Protocol)
			raw = append(raw, interaction.RawRequest)
		}
		return raw
	}
	require.Equal(t, []string{
		"USER anonymous\nanonymous logging in",
		"PASS hunter2\nuser anonymous logged in with password hunter2",
		"STOR /index.html\nuploading /index.html",
		"APPE /index.html\nuploading /index.html",
		"MKD /made\ncreating directory /made",
		"MKD /made\ncreating directory /made",
		"RMD /made\ndeleting directory /made",
		"DELE /index.html\ndeleting /index.html",
		"RETR /nope\ndownloading file /nope",
		"RETR /index.html\ndownloading file /index.html",
		"RETR /\ndownloading file /",
		"CWD /" + uploadsDirName + "\nchanging directory from / to /" + uploadsDirName,
		"CWD ..\nchanging directory from /" + uploadsDirName + " to /",
		"CWD /" + uploadsDirName + "\nchanging directory from / to /" + uploadsDirName,
	}, requests(options.Token))
	require.Equal(t, []string{"RETR " + hosted + "\ndownloading file " + hosted}, requests(id),
		"a hosted file's download belongs to its session")
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
