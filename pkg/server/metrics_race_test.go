package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/storage"
	"github.com/stretchr/testify/require"
)

func newMetricsTestServer(t *testing.T) *HTTPServer {
	t.Helper()

	store, err := storage.New(&storage.Options{EvictionTTL: 1 * time.Hour})
	require.NoError(t, err, "could not create storage")
	t.Cleanup(func() { _ = store.Close() })

	return &HTTPServer{options: &Options{Storage: store, Stats: &Metrics{}, EnableMetrics: true}}
}

func TestMetricsSnapshotNil(t *testing.T) {
	var m *Metrics
	require.Equal(t, Metrics{}, m.snapshot())
}

func TestMetricsHandlerDoesNotMutateSharedStats(t *testing.T) {
	h := newMetricsTestServer(t)

	w := httptest.NewRecorder()
	h.metricsHandler(w, httptest.NewRequest(http.MethodGet, "http://example.com/metrics", nil))
	require.Equal(t, http.StatusOK, w.Result().StatusCode)

	require.Nil(t, h.options.Stats.Cache, "handler must not write Cache into the shared stats")
	require.Nil(t, h.options.Stats.Cpu, "handler must not write Cpu into the shared stats")
	require.Nil(t, h.options.Stats.Memory, "handler must not write Memory into the shared stats")
	require.Nil(t, h.options.Stats.Network, "handler must not write Network into the shared stats")
}

func TestMetricsHandlerSnapshotsCounters(t *testing.T) {
	h := newMetricsTestServer(t)
	atomic.StoreUint64(&h.options.Stats.Dns, 3)
	atomic.StoreUint64(&h.options.Stats.Http, 7)
	atomic.StoreInt64(&h.options.Stats.Sessions, 2)
	atomic.StoreInt64(&h.options.Stats.SessionsTotal, 11)

	w := httptest.NewRecorder()
	h.metricsHandler(w, httptest.NewRequest(http.MethodGet, "http://example.com/metrics", nil))
	require.Equal(t, http.StatusOK, w.Result().StatusCode)

	var got Metrics
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Equal(t, uint64(3), got.Dns)
	require.Equal(t, uint64(7), got.Http)
	require.Equal(t, int64(2), got.Sessions)
	require.Equal(t, int64(11), got.SessionsTotal)
	require.NotNil(t, got.Cache)
	require.Nil(t, h.options.Stats.Cache)
}

func TestMetricsHandlerConcurrent(t *testing.T) {
	h := newMetricsTestServer(t)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				atomic.AddUint64(&h.options.Stats.Http, 1)
				atomic.AddUint64(&h.options.Stats.Dns, 1)
				atomic.AddInt64(&h.options.Stats.Sessions, 1)
				atomic.AddInt64(&h.options.Stats.SessionsTotal, 1)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				w := httptest.NewRecorder()
				h.metricsHandler(w, httptest.NewRequest(http.MethodGet, "http://example.com/metrics", nil))
				require.Equal(t, http.StatusOK, w.Result().StatusCode)
			}
		}()
	}
	wg.Wait()
}
