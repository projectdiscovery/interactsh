package storage

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

func newUploadTestDB(t *testing.T, opts *Options) (*StorageDB, string, string) {
	t.Helper()

	db, err := New(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	secret := uuid.New().String()
	correlationID := xid.New().String()
	_, pubKey := generateRSAKeyPair(t)
	require.NoError(t, db.SetIDPublicKey(correlationID, secret, pubKey))

	return db, correlationID, secret
}

func TestUpdateUploads(t *testing.T) {
	t.Run("stores metadata", func(t *testing.T) {
		db, id, secret := newUploadTestDB(t, &Options{EvictionTTL: time.Hour})

		err := db.UpdateUploads(id, secret, func(existing []UploadedFile) ([]UploadedFile, error) {
			require.Empty(t, existing, "new session should start with no uploads")
			return append(existing, UploadedFile{Name: "evil.dtd", Size: 42}), nil
		})
		require.NoError(t, err)

		files, ok := db.ListUploads(id)
		require.True(t, ok)
		require.Len(t, files, 1)
		require.Equal(t, "evil.dtd", files[0].Name)
	})

	t.Run("rejects wrong secret", func(t *testing.T) {
		db, id, _ := newUploadTestDB(t, &Options{EvictionTTL: time.Hour})

		called := false
		err := db.UpdateUploads(id, uuid.New().String(), func(f []UploadedFile) ([]UploadedFile, error) {
			called = true
			return f, nil
		})
		require.ErrorIs(t, err, ErrInvalidSecretKey)
		require.False(t, called, "callback must not run for an unauthorised caller")
	})

	t.Run("rejects unknown correlation id", func(t *testing.T) {
		db, _, secret := newUploadTestDB(t, &Options{EvictionTTL: time.Hour})

		err := db.UpdateUploads(xid.New().String(), secret, func(f []UploadedFile) ([]UploadedFile, error) {
			return f, nil
		})
		require.ErrorIs(t, err, ErrCorrelationIdNotFound)
	})

	t.Run("callback error leaves metadata untouched", func(t *testing.T) {
		db, id, secret := newUploadTestDB(t, &Options{EvictionTTL: time.Hour})

		require.NoError(t, db.UpdateUploads(id, secret, func(f []UploadedFile) ([]UploadedFile, error) {
			return append(f, UploadedFile{Name: "keep.dtd"}), nil
		}))

		err := db.UpdateUploads(id, secret, func(f []UploadedFile) ([]UploadedFile, error) {
			return append(f, UploadedFile{Name: "discard.dtd"}), os.ErrInvalid
		})
		require.ErrorIs(t, err, os.ErrInvalid)

		files, ok := db.ListUploads(id)
		require.True(t, ok)
		require.Len(t, files, 1, "failed update must not commit")
		require.Equal(t, "keep.dtd", files[0].Name)
	})

	// The quota check and the commit both run inside the callback under the
	// correlation-id lock, so concurrent uploads to one session cannot both
	// observe the same "slots remaining" and overshoot.
	t.Run("concurrent updates respect a quota", func(t *testing.T) {
		db, id, secret := newUploadTestDB(t, &Options{EvictionTTL: time.Hour})

		const maxFiles = 5
		var wg sync.WaitGroup
		for i := 0; i < 25; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_ = db.UpdateUploads(id, secret, func(f []UploadedFile) ([]UploadedFile, error) {
					if len(f) >= maxFiles {
						return nil, os.ErrPermission
					}
					return append(f, UploadedFile{Name: xid.New().String()}), nil
				})
			}(i)
		}
		wg.Wait()

		files, ok := db.ListUploads(id)
		require.True(t, ok)
		require.Len(t, files, maxFiles, "quota must hold under concurrency")
	})
}

func TestListUploads(t *testing.T) {
	db, id, _ := newUploadTestDB(t, &Options{EvictionTTL: time.Hour})

	t.Run("known id with no uploads", func(t *testing.T) {
		files, ok := db.ListUploads(id)
		require.True(t, ok, "session exists")
		require.Empty(t, files)
	})

	t.Run("unknown id", func(t *testing.T) {
		files, ok := db.ListUploads(xid.New().String())
		require.False(t, ok)
		require.Nil(t, files)
	})

	t.Run("returns a copy", func(t *testing.T) {
		db, id, secret := newUploadTestDB(t, &Options{EvictionTTL: time.Hour})
		require.NoError(t, db.UpdateUploads(id, secret, func(f []UploadedFile) ([]UploadedFile, error) {
			return append(f, UploadedFile{Name: "orig.dtd"}), nil
		}))

		files, _ := db.ListUploads(id)
		files[0].Name = "mutated.dtd"

		again, _ := db.ListUploads(id)
		require.Equal(t, "orig.dtd", again[0].Name, "caller must not be able to mutate stored metadata")
	})
}

// TestOnEvictionMemoryMode covers OnEviction firing in memory mode, which is
// the default and the mode upload cleanup most depends on: with no leveldb
// handle in play, the hook is the only signal that a session's files may go.
func TestOnEvictionMemoryMode(t *testing.T) {
	t.Run("fires on RemoveID", func(t *testing.T) {
		var mu sync.Mutex
		var evicted []string

		db, id, secret := newUploadTestDB(t, &Options{
			EvictionTTL: time.Hour,
			OnEviction: func(correlationID string, _ *CorrelationData) {
				mu.Lock()
				defer mu.Unlock()
				evicted = append(evicted, correlationID)
			},
		})

		require.NoError(t, db.RemoveID(id, secret))
		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(evicted) == 1 && evicted[0] == id
		}, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("fires on ttl expiry", func(t *testing.T) {
		var mu sync.Mutex
		var evicted []string

		db, id, _ := newUploadTestDB(t, &Options{
			EvictionTTL: 100 * time.Millisecond,
			OnEviction: func(correlationID string, _ *CorrelationData) {
				mu.Lock()
				defer mu.Unlock()
				evicted = append(evicted, correlationID)
			},
		})

		time.Sleep(200 * time.Millisecond)
		// goburrow/cache has no janitor; expiry is only processed on cache
		// activity, so poke it.
		db.cache.GetIfPresent(id)

		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(evicted) == 1 && evicted[0] == id
		}, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("fires on close", func(t *testing.T) {
		var mu sync.Mutex
		var evicted []string

		db, err := New(&Options{
			EvictionTTL: time.Hour,
			OnEviction: func(correlationID string, _ *CorrelationData) {
				mu.Lock()
				defer mu.Unlock()
				evicted = append(evicted, correlationID)
			},
		})
		require.NoError(t, err)

		secret := uuid.New().String()
		id := xid.New().String()
		_, pubKey := generateRSAKeyPair(t)
		require.NoError(t, db.SetIDPublicKey(id, secret, pubKey))

		require.NoError(t, db.Close())
		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(evicted) == 1 && evicted[0] == id
		}, 2*time.Second, 10*time.Millisecond)
	})

	// Without the s.db nil guard this panics on the cache's event goroutine,
	// which then deadlocks every subsequent cache operation.
	t.Run("memory mode eviction does not panic", func(t *testing.T) {
		db, id, secret := newUploadTestDB(t, &Options{EvictionTTL: time.Hour})

		require.NoError(t, db.RemoveID(id, secret))
		time.Sleep(100 * time.Millisecond)

		// If the event goroutine had died, this would block forever.
		done := make(chan struct{})
		go func() {
			defer close(done)
			newID := xid.New().String()
			_, pubKey := generateRSAKeyPair(t)
			_ = db.SetIDPublicKey(newID, uuid.New().String(), pubKey)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("cache is deadlocked: the removal listener killed the event goroutine")
		}
	})
}
