package client

import (
	"bytes"
	"sync"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/require"
)

type captureWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *captureWriter) Write(data []byte, _ levels.Level) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = w.b.Write(data)
}

func (w *captureWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

func testLogger(w *captureWriter) *gologger.Logger {
	logger := &gologger.Logger{}
	logger.SetMaxLevel(levels.LevelVerbose)
	logger.SetFormatter(formatter.NewCLI(false))
	logger.SetWriter(w)
	return logger
}

func TestNewReportsRegistrationFailureOnSuppliedLogger(t *testing.T) {
	supplied := &captureWriter{}
	fallback := &captureWriter{}
	previous := gologger.DefaultLogger
	gologger.DefaultLogger = testLogger(fallback)
	t.Cleanup(func() { gologger.DefaultLogger = previous })

	_, err := New(&Options{
		ServerURL:           "http://127.0.0.1:1",
		Logger:              testLogger(supplied),
		DisableHTTPFallback: true,
	})
	require.Error(t, err)
	require.Contains(t, supplied.String(), "Could not register")
	require.NotContains(t, fallback.String(), "Could not register")
}
