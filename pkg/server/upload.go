package server

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/rs/xid"
)

const (
	uploadSessionDirPerm = 0o700
	uploadFilePerm       = 0o600

	// uploadsDirName is the single directory, directly under the upload root,
	// that holds every session's uploaded files.
	//
	// Sessions live one level down rather than at the root so that the root can
	// be a shared -ftp-dir full of the operator's own files: the janitor and the
	// startup purge only ever read, and delete, inside this directory, so no
	// amount of coincidence between an operator's directory name and a
	// correlation id can put their content at risk. The leading dot keeps it out
	// of the way of an operator listing their own FTP root; it is not a security
	// measure, since NopDriver is what actually hides it (see ftp_server.go).
	uploadsDirName = ".interactsh-user-uploads"

	// deleteQueueSize bounds the backlog of session directories awaiting
	// removal. Sends are non-blocking, so a full queue drops the request and
	// leaves the directory for the janitor.
	deleteQueueSize = 1024

	// maxSweepInterval caps how long the janitor sleeps regardless of TTL.
	maxSweepInterval = 10 * time.Minute
	minSweepInterval = 1 * time.Minute
)

// uploadNameRe is a strict allowlist for uploaded file names. It is applied
// identically on upload and on serve.
//
// This is deliberately an allowlist rather than a sanitiser: the user needs the
// exact byte-for-byte name to reference the file from a DTD or XSLT payload, so
// silently mangling a name is worse than rejecting it. It also means the name
// never needs escaping when it is placed in a Content-Disposition header.
//
// Rejects: path separators, "..", NUL and control characters, leading dots,
// absolute paths, and over-long names.
var uploadNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// isSafeUploadName reports whether name is acceptable as an uploaded file name.
func isSafeUploadName(name string) bool {
	if !uploadNameRe.MatchString(name) {
		return false
	}
	// Belt and braces: the regexp already excludes "/" and "\", so no traversal
	// sequence can survive, but a bare ".." must never slip through either.
	return name != "." && name != ".."
}

// UploadErrorKind classifies upload failures so the HTTP layer can map them to
// status codes without matching on error strings.
type UploadErrorKind int

const (
	UploadErrOther UploadErrorKind = iota
	UploadErrBadName
	UploadErrTooLarge
	UploadErrTooManyFiles
	UploadErrOutOfSpace
)

// UploadError is a failure attributable to the uploaded content or to server
// capacity, as opposed to an internal error.
type UploadError struct {
	Kind UploadErrorKind
	Err  error
}

func (e *UploadError) Error() string { return e.Err.Error() }
func (e *UploadError) Unwrap() error { return e.Err }

func uploadErr(kind UploadErrorKind, format string, args ...interface{}) *UploadError {
	return &UploadError{Kind: kind, Err: errors.Errorf(format, args...)}
}

// UploadStore owns the on-disk lifecycle of client-uploaded files.
//
// Layout is <root>/<uploadsDirName>/<correlationID>/<filename>. The session
// directory is named by correlation ID because FTP has no Host header, so the
// identifier has to be carried in the path for the FTP view to work. The
// uploadsDirName level exists so that the root may be shared with -ftp-dir
// without this store ever touching an operator's files.
type UploadStore struct {
	root string
	// sessionsRoot is <root>/<uploadsDirName>: everything this store creates,
	// enumerates and deletes lives under it, and nothing above it is ours.
	sessionsRoot string
	// rootFS is an openat-rooted handle used for the serving path. Names there
	// come from a URL, and os.Root refuses any resolution that escapes the root
	// or traverses a symlink out of it, on every platform we build for.
	rootFS      *os.Root
	maxFileSize int64
	maxFiles    int
	maxTotal    int64
	ttl         time.Duration

	// correlationIDLength is used to recognise session directories inside
	// sessionsRoot, and to reject implausible identifiers before they reach a
	// filepath.Join.
	correlationIDLength int

	totalBytes atomic.Int64

	deleteCh chan string
	closeCh  chan struct{}
	closeWG  sync.WaitGroup
	closeAt  sync.Once
}

// NewUploadStore prepares the upload root and returns a store. It does not
// start the background goroutines; call Start for that.
func NewUploadStore(options *Options) (*UploadStore, error) {
	root := options.UploadDirectory
	switch {
	case root != "":
	case options.FTPDirectory != "":
		// Share the FTP root so that -ftp serves uploads with no extra config.
		root = options.FTPDirectory
	default:
		var err error
		if root, err = os.MkdirTemp("", "interactsh-uploads-"); err != nil {
			return nil, errors.Wrap(err, "could not create temporary upload directory")
		}
	}

	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.Wrap(err, "could not resolve upload directory")
	}

	// Creating the sessions directory creates the root along with it, so every
	// branch above ends up with both present before os.OpenRoot needs them --
	// including a -ftp-dir that does not exist yet, which the FTP server itself
	// never required.
	sessionsRoot := filepath.Join(abs, uploadsDirName)
	if err := os.MkdirAll(sessionsRoot, uploadSessionDirPerm); err != nil {
		return nil, errors.Wrap(err, "could not create upload directory")
	}

	// MkdirAll succeeds on a directory that already exists but cannot be written
	// to -- a read-only mount, or one owned by another user -- and the failure
	// would otherwise surface only when a client's first upload 500s, long after
	// startup. Probe it now so the server refuses to start with a clear reason.
	if err := checkUploadDirWritable(sessionsRoot); err != nil {
		return nil, err
	}

	rootFS, err := os.OpenRoot(abs)
	if err != nil {
		return nil, errors.Wrap(err, "could not open upload directory")
	}

	s := &UploadStore{
		root:                abs,
		sessionsRoot:        sessionsRoot,
		rootFS:              rootFS,
		maxFileSize:         options.UploadMaxFileSize,
		maxFiles:            options.UploadMaxFiles,
		maxTotal:            options.UploadMaxTotalSize,
		ttl:                 options.UploadTTL,
		correlationIDLength: options.CorrelationIdLength,
		deleteCh:            make(chan string, deleteQueueSize),
		closeCh:             make(chan struct{}),
	}

	// Upload metadata lives only in the cache, so no session survives a
	// restart; anything already here is by definition an orphan.
	s.purge()
	return s, nil
}

// checkUploadDirWritable verifies that files can actually be created in dir, by
// doing it. Permission bits are not consulted directly: they answer the question
// for the wrong subject on a setuid binary, and they do not answer it at all for
// a read-only mount, an exhausted filesystem or a restrictive ACL.
func checkUploadDirWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".writable-*")
	if err != nil {
		return errors.Wrapf(err, "upload directory %s is not writable", dir)
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()

	// Written to as well as created, so that a filesystem which allows the
	// create but refuses the write is caught here rather than mid-upload.
	if _, err := f.Write([]byte("interactsh")); err != nil {
		_ = f.Close()
		return errors.Wrapf(err, "upload directory %s is not writable", dir)
	}
	if err := f.Close(); err != nil {
		return errors.Wrapf(err, "upload directory %s is not writable", dir)
	}
	return nil
}

// Root returns the directory uploaded files are stored under.
func (s *UploadStore) Root() string { return s.root }

// MaxFileSize returns the per-file byte limit.
func (s *UploadStore) MaxFileSize() int64 { return s.maxFileSize }

// MaxFiles returns the per-session file count limit.
func (s *UploadStore) MaxFiles() int { return s.maxFiles }

// Start launches the deleter and janitor goroutines.
func (s *UploadStore) Start() {
	s.closeWG.Add(2)
	go s.runDeleter()
	go s.runJanitor()
}

// Close stops the background goroutines and releases the rooted handle.
func (s *UploadStore) Close() error {
	s.closeAt.Do(func() { close(s.closeCh) })
	s.closeWG.Wait()
	return s.rootFS.Close()
}

// looksLikeSessionDir reports whether a directory entry name could be one of
// our session directories.
//
// Operator files are kept safe structurally, by everything of ours living under
// uploadsDirName; this check is the second line of defence, so that anything
// unexpected inside that directory is left alone rather than deleted.
func (s *UploadStore) looksLikeSessionDir(name string) bool {
	return len(name) == s.correlationIDLength && govalidator.IsAlphanumeric(name)
}

// sessionDir returns the directory for a correlation ID, or "" if the ID is not
// a plausible correlation ID. Validating before any filepath.Join is what keeps
// a hostile identifier from escaping the root.
func (s *UploadStore) sessionDir(correlationID string) string {
	if !s.looksLikeSessionDir(correlationID) {
		return ""
	}
	return filepath.Join(s.sessionsRoot, correlationID)
}

// Save writes one file for a correlation ID and returns its size and digest.
//
// It is called from inside Storage.UpdateUploads, i.e. under the correlation
// ID's lock, so the caller's quota check and this write are atomic with respect
// to other uploads for the same session.
func (s *UploadStore) Save(correlationID, name string, data []byte, existingSize int64) (int64, string, error) {
	if !isSafeUploadName(name) {
		return 0, "", uploadErr(UploadErrBadName, "invalid file name %q", name)
	}
	size := int64(len(data))
	if size == 0 {
		return 0, "", uploadErr(UploadErrBadName, "file %q is empty", name)
	}
	if size > s.maxFileSize {
		return 0, "", uploadErr(UploadErrTooLarge, "file %q is %d bytes, limit is %d", name, size, s.maxFileSize)
	}

	dir := s.sessionDir(correlationID)
	if dir == "" {
		return 0, "", uploadErr(UploadErrOther, "invalid correlation-id")
	}

	// Reserve space before writing. existingSize is what this name already
	// occupies, since overwriting replaces rather than adds.
	if delta := size - existingSize; delta > 0 {
		if s.totalBytes.Add(delta) > s.maxTotal {
			s.totalBytes.Add(-delta)
			return 0, "", uploadErr(UploadErrOutOfSpace, "server upload capacity exhausted")
		}
	} else {
		s.totalBytes.Add(delta)
	}

	if err := os.MkdirAll(dir, uploadSessionDirPerm); err != nil {
		s.totalBytes.Add(existingSize - size)
		return 0, "", errors.Wrap(err, "could not create session directory")
	}

	// Plain os rather than the rooted handle: os.Root has no Rename before Go
	// 1.25, and both components are already constrained -- the correlation ID
	// is alphanumeric and length-checked, the name passed the allowlist, so
	// neither can contain a separator or traversal sequence.
	//
	// Write to a temp name and rename into place, so a reader (HTTP or the FTP
	// file driver) never observes a partially written file.
	tmp := filepath.Join(dir, ".upload-"+xid.New().String())
	if err := os.WriteFile(tmp, data, uploadFilePerm); err != nil {
		s.totalBytes.Add(existingSize - size)
		return 0, "", errors.Wrap(err, "could not write uploaded file")
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp)
		s.totalBytes.Add(existingSize - size)
		return 0, "", errors.Wrap(err, "could not commit uploaded file")
	}

	sum := sha256.Sum256(data)
	return size, hex.EncodeToString(sum[:]), nil
}

// Open returns a readable handle to an uploaded file. The name is re-validated
// here rather than trusted from the caller.
func (s *UploadStore) Open(correlationID, name string) (*os.File, os.FileInfo, error) {
	if !isSafeUploadName(name) {
		return nil, nil, errors.New("invalid file name")
	}
	if !s.looksLikeSessionDir(correlationID) {
		return nil, nil, errors.New("invalid correlation-id")
	}

	// Resolved through the rooted handle, so neither component can escape the
	// upload directory even if the root is operator-supplied and contains a
	// planted symlink.
	f, err := s.rootFS.Open(filepath.Join(uploadsDirName, correlationID, name))
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, errors.New("not a regular file")
	}
	return f, fi, nil
}

// RemoveSession queues a session's directory for deletion. It is safe to call
// from the storage cache's event goroutine: the send is non-blocking, so
// filesystem latency can never back-pressure cache maintenance. A dropped
// request is collected by the janitor instead.
func (s *UploadStore) RemoveSession(correlationID string) {
	if s.sessionDir(correlationID) == "" {
		return
	}
	select {
	case s.deleteCh <- correlationID:
	default:
		gologger.Debug().Msgf("Upload delete queue full, leaving %s to the janitor\n", correlationID)
	}
}

// removeSessionNow deletes a session directory synchronously.
func (s *UploadStore) removeSessionNow(correlationID string) {
	dir := s.sessionDir(correlationID)
	if dir == "" {
		return
	}
	freed := dirSize(dir)
	if err := os.RemoveAll(dir); err != nil {
		gologger.Warning().Msgf("Could not remove upload directory for %s: %s\n", correlationID, err)
		return
	}
	if freed > 0 {
		s.totalBytes.Add(-freed)
	}
}

func (s *UploadStore) runDeleter() {
	defer s.closeWG.Done()
	for {
		select {
		case id := <-s.deleteCh:
			s.removeSessionNow(id)
		case <-s.closeCh:
			// Drain whatever is already queued, then stop.
			for {
				select {
				case id := <-s.deleteCh:
					s.removeSessionNow(id)
				default:
					return
				}
			}
		}
	}
}

// runJanitor is the authoritative garbage collector for uploaded files.
//
// It cannot be left to cache eviction: goburrow/cache has no background
// janitor, so expiry is only processed on cache activity. An idle server would
// never evict, and would therefore leak every uploaded file indefinitely.
func (s *UploadStore) runJanitor() {
	defer s.closeWG.Done()

	interval := s.ttl / 10
	if interval > maxSweepInterval {
		interval = maxSweepInterval
	}
	if interval < minSweepInterval {
		interval = minSweepInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.sweep()
		case <-s.closeCh:
			return
		}
	}
}

// sweep removes session directories older than the TTL and recomputes the
// global byte total.
//
// Liveness is judged by directory mtime, never by asking the cache. A cache
// lookup would refresh the entry's access time, so under the default sliding
// eviction strategy probing every swept session would make exactly those
// sessions immortal.
func (s *UploadStore) sweep() {
	entries, err := os.ReadDir(s.sessionsRoot)
	if err != nil {
		gologger.Warning().Msgf("Could not read upload directory: %s\n", err)
		return
	}

	var total int64
	for _, entry := range entries {
		if !entry.IsDir() || !s.looksLikeSessionDir(entry.Name()) {
			continue
		}
		dir := filepath.Join(s.sessionsRoot, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		// Directory mtime advances when a file is added or removed, so this is
		// effectively "time since the last upload". Reads do not touch it.
		if time.Since(info.ModTime()) > s.ttl {
			if err := os.RemoveAll(dir); err != nil {
				gologger.Warning().Msgf("Could not sweep upload directory %s: %s\n", dir, err)
				total += dirSize(dir)
			}
			continue
		}
		total += dirSize(dir)
	}
	s.totalBytes.Store(total)
}

// purge removes every session directory in the root, leaving anything that does
// not look like one untouched.
func (s *UploadStore) purge() {
	entries, err := os.ReadDir(s.sessionsRoot)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() && s.looksLikeSessionDir(entry.Name()) {
			_ = os.RemoveAll(filepath.Join(s.sessionsRoot, entry.Name()))
		}
	}
	s.totalBytes.Store(0)
}

// dirSize sums the regular files directly inside dir.
func dirSize(dir string) int64 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var total int64
	for _, entry := range entries {
		if info, err := entry.Info(); err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	return total
}
