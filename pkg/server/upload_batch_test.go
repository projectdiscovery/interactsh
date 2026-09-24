package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

// orderedUploadBody is uploadBody with a defined file order, which the map-based
// helper cannot give: these tests need to know which file fails.
func orderedUploadBody(t *testing.T, correlationID, secret string, names []string, data [][]byte) string {
	t.Helper()
	require.Len(t, data, len(names))

	req := UploadRequest{CorrelationID: correlationID, SecretKey: secret}
	for i, name := range names {
		req.Files = append(req.Files, UploadFileRequest{
			Name: name,
			Data: base64.StdEncoding.EncodeToString(data[i]),
		})
	}
	encoded, err := json.Marshal(req)
	require.NoError(t, err)
	return string(encoded)
}

// sessionFiles lists the file names on disk for a session, temp files included,
// so that a leaked staging file is visible to these assertions.
func sessionFiles(t *testing.T, store *UploadStore, correlationID string) []string {
	t.Helper()
	entries, err := os.ReadDir(store.sessionDir(correlationID))
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// newSession registers an additional session on an existing server, for the
// cross-session assertions.
func newSession(t *testing.T, h *HTTPServer) (correlationID, secret string) {
	t.Helper()
	correlationID = xid.New().String()
	secret = uuid.New().String()
	require.NoError(t, h.options.Storage.SetIDPublicKey(correlationID, secret, testPublicKey(t)))
	return correlationID, secret
}

// A multi-file upload is all-or-nothing. Committing each file as it is written
// left the earlier ones on disk holding quota while the metadata that made them
// reachable was discarded: unusable, uncollectable until the session ended, and
// counted against every other session's uploads.
func TestUploadBatchIsAtomic(t *testing.T) {
	t.Run("quota exhausted part-way leaves nothing behind", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		store := h.options.UploadStore
		store.maxTotal = 1500 // fits one 1000-byte file, not two

		body := orderedUploadBody(t, id, secret,
			[]string{"a.bin", "b.bin"},
			[][]byte{make([]byte, 1000), make([]byte, 1000)})
		resp := doUpload(t, h, body)
		require.Equal(t, http.StatusInsufficientStorage, resp.StatusCode)

		files, _ := h.options.UploadStorage().ListUploads(id)
		require.Empty(t, files, "metadata must be unchanged")
		require.Empty(t, sessionFiles(t, store, id), "no file, and no staging temp file, may survive")
		require.Zero(t, store.totalBytes.Load(), "the reservation must be released")
	})

	t.Run("and the same upload then succeeds on retry", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		store := h.options.UploadStore
		store.maxTotal = 1500

		require.Equal(t, http.StatusInsufficientStorage, doUpload(t, h, orderedUploadBody(t, id, secret,
			[]string{"a.bin", "b.bin"},
			[][]byte{make([]byte, 1000), make([]byte, 1000)})).StatusCode)

		// Previously wedged: the orphan still held 1000 of the 1500 bytes while
		// metadata reported nothing, so this retry was refused indefinitely.
		resp := doUpload(t, h, orderedUploadBody(t, id, secret,
			[]string{"a.bin"}, [][]byte{make([]byte, 1000)}))
		require.Equal(t, http.StatusOK, resp.StatusCode, "a retry of the file that fitted must succeed")

		files, _ := h.options.UploadStorage().ListUploads(id)
		require.Len(t, files, 1)
		require.EqualValues(t, 1000, store.totalBytes.Load(), "charged once, not twice")
	})

	t.Run("per-session file cap reached part-way leaves nothing behind", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true) // UploadMaxFiles is 3
		store := h.options.UploadStore

		for _, name := range []string{"f0.dtd", "f1.dtd"} {
			require.Equal(t, http.StatusOK,
				doUpload(t, h, orderedUploadBody(t, id, secret, []string{name}, [][]byte{[]byte("x")})).StatusCode)
		}
		before := store.totalBytes.Load()

		// Two more against a limit of three: the first fits, the second does not.
		resp := doUpload(t, h, orderedUploadBody(t, id, secret,
			[]string{"f2.dtd", "f3.dtd"}, [][]byte{[]byte("yy"), []byte("zz")}))
		require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)

		files, _ := h.options.UploadStorage().ListUploads(id)
		require.Len(t, files, 2, "metadata must be unchanged")
		require.ElementsMatch(t, []string{"f0.dtd", "f1.dtd"}, sessionFiles(t, store, id),
			"the file that fitted must not be left on disk")
		require.Equal(t, before, store.totalBytes.Load())
	})

	// The reason staging beats deleting what was already written: for a name that
	// already existed, the previous content is gone the moment it is overwritten,
	// so a compensating delete would turn a leaked file into lost data.
	t.Run("a failed batch does not disturb the file it would have replaced", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		store := h.options.UploadStore

		original := []byte("original payload")
		require.Equal(t, http.StatusOK,
			doUpload(t, h, orderedUploadBody(t, id, secret, []string{"a.dtd"}, [][]byte{original})).StatusCode)
		before, _ := h.options.UploadStorage().ListUploads(id)
		require.Len(t, before, 1)
		charged := store.totalBytes.Load()

		// Replace a.dtd and add a file that cannot fit: the batch must fail whole.
		store.maxTotal = int64(len(original)) + 10
		resp := doUpload(t, h, orderedUploadBody(t, id, secret,
			[]string{"a.dtd", "b.dtd"},
			[][]byte{[]byte("replacement payload"), make([]byte, 1000)}))
		require.NotEqual(t, http.StatusOK, resp.StatusCode)

		onDisk, err := os.ReadFile(filepath.Join(store.sessionDir(id), "a.dtd"))
		require.NoError(t, err)
		require.Equal(t, original, onDisk, "the previously hosted file must be untouched")

		after, _ := h.options.UploadStorage().ListUploads(id)
		require.Equal(t, before, after, "metadata must still describe the file that is on disk")
		require.Equal(t, charged, store.totalBytes.Load())
		require.ElementsMatch(t, []string{"a.dtd"}, sessionFiles(t, store, id))
	})

	// Unwinding resolves every path through sessionDir plus a validated name, so
	// it cannot reach outside the session it belongs to.
	t.Run("unwinding one session does not touch another", func(t *testing.T) {
		h, mine, mySecret := uploadTestServer(t, true)
		store := h.options.UploadStore

		theirs, theirSecret := newSession(t, h)
		require.Equal(t, http.StatusOK, doUpload(t, h,
			orderedUploadBody(t, theirs, theirSecret, []string{"a.bin"}, [][]byte{[]byte("their payload")})).StatusCode)

		store.maxTotal = store.totalBytes.Load() + 1200
		resp := doUpload(t, h, orderedUploadBody(t, mine, mySecret,
			[]string{"a.bin", "b.bin"},
			[][]byte{make([]byte, 1000), make([]byte, 1000)}))
		require.Equal(t, http.StatusInsufficientStorage, resp.StatusCode)

		theirFile, err := os.ReadFile(filepath.Join(store.sessionDir(theirs), "a.bin"))
		require.NoError(t, err)
		require.Equal(t, []byte("their payload"), theirFile,
			"another session's identically named file must be untouched")
		theirMeta, ok := h.options.UploadStorage().ListUploads(theirs)
		require.True(t, ok)
		require.Len(t, theirMeta, 1)
		require.Empty(t, sessionFiles(t, store, mine))
	})

	t.Run("no staging temp files survive a successful batch either", func(t *testing.T) {
		h, id, secret := uploadTestServer(t, true)
		require.Equal(t, http.StatusOK, doUpload(t, h, orderedUploadBody(t, id, secret,
			[]string{"a.dtd", "b.dtd"}, [][]byte{[]byte("one"), []byte("two")})).StatusCode)

		for _, name := range sessionFiles(t, h.options.UploadStore, id) {
			require.False(t, strings.HasPrefix(name, ".upload-"), "temp file %q left behind", name)
		}
	})
}
