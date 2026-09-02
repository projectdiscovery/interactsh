package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/storage"
	"github.com/stretchr/testify/require"
)

// newMetricsTestServer returns an HTTPServer backed by in-memory storage and a
// zeroed metrics struct, suitable for driving metricsHandler directly.
func newMetricsTestServer(t *testing.T) *HTTPServer {
	t.Helper()

	store, err := storage.New(&storage.Options{EvictionTTL: 1 * time.Hour})
	require.NoError(t, err, "could not create storage")
	t.Cleanup(func() { _ = store.Close() })

	return &HTTPServer{options: &Options{Storage: store, Stats: &Metrics{}, EnableMetrics: true}}
}

// TestMetricsHandlerDoesNotMutateSharedStats is a regression test for the
// /metrics handler aliasing options.Stats. It used to assign the *Metrics to a
// local variable, which copied the pointer rather than the struct, so every
// request wrote Cache/Cpu/Memory/Network into the one struct shared by all the
// protocol servers. The handler must leave that struct untouched.
func TestMetricsHandlerDoesNotMutateSharedStats(t *testing.T) {
	h := newMetricsTestServer(t)

	w := httptest.NewRecorder()
	h.metricsHandler(w, httptest.NewRequest("GET", "http://example.com/metrics", nil))
	require.Equal(t, http.StatusOK, w.Result().StatusCode)

	require.Nil(t, h.options.Stats.Cache, "handler must not write Cache into the shared stats")
	require.Nil(t, h.options.Stats.Cpu, "handler must not write Cpu into the shared stats")
	require.Nil(t, h.options.Stats.Memory, "handler must not write Memory into the shared stats")
	require.Nil(t, h.options.Stats.Network, "handler must not write Network into the shared stats")
}

// TestMetricsHandlerConcurrent exercises the /metrics snapshot against
// concurrent counter writers. Run with -race to catch regressions.
func TestMetricsHandlerConcurrent(t *testing.T) {
	h := newMetricsTestServer(t)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers mimic the protocol servers updating shared counters.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					atomic.AddUint64(&h.options.Stats.Http, 1)
					atomic.AddUint64(&h.options.Stats.Dns, 1)
					atomic.AddInt64(&h.options.Stats.Sessions, 1)
					atomic.AddInt64(&h.options.Stats.SessionsTotal, 1)
				}
			}
		}()
	}

	// Concurrent readers hitting the metrics endpoint.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				w := httptest.NewRecorder()
				h.metricsHandler(w, httptest.NewRequest("GET", "http://example.com/metrics", nil))
				require.Equal(t, http.StatusOK, w.Result().StatusCode)
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}
