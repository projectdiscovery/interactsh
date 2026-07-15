package client

import (
	"regexp"
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

// xidAlphabet matches the server-side validator (see pkg/server/util.go).
var xidAlphabet = regexp.MustCompile(`^[0-9a-v]{20}$`)

func TestAnonymousCorrelationIDFormat(t *testing.T) {
	id, err := newAnonymousCorrelationID()
	require.NoError(t, err)
	require.Len(t, id, 20)
	require.Regexp(t, xidAlphabet, id, "must match server xid alphabet validator")

	parsed, err := xid.FromString(id)
	require.NoError(t, err, "must remain parseable as xid")
	require.WithinDuration(t, time.Now(), parsed.Time(), 5*time.Second,
		"timestamp prefix must encode the current time")
}

// TestAnonymousCorrelationIDNotFingerprinted asserts that the machine and pid
// bytes are randomised: xid.New() returns the same machine+pid for every call
// in the same process; newAnonymousCorrelationID() must not.
func TestAnonymousCorrelationIDNotFingerprinted(t *testing.T) {
	const samples = 64

	machineSet := make(map[string]struct{}, samples)
	pidSet := make(map[uint16]struct{}, samples)

	for range samples {
		raw, err := newAnonymousCorrelationID()
		require.NoError(t, err)
		id, err := xid.FromString(raw)
		require.NoError(t, err)
		machineSet[string(id.Machine())] = struct{}{}
		pidSet[id.Pid()] = struct{}{}
	}

	// With 64 samples and full randomness, the probability of getting a
	// single repeated 3-byte machine value is ~64^2 / 2^25 ≈ 1.2e-4. A
	// fingerprinted id would collapse to a single value, so even a weak
	// lower bound here catches the regression.
	require.Greater(t, len(machineSet), samples/2,
		"machine bytes must be randomised across calls")
	require.Greater(t, len(pidSet), samples/2,
		"pid bytes must be randomised across calls")
}

func TestAnonymousCorrelationIDDistinctFromXidNew(t *testing.T) {
	// xid.New() inherits a stable machine fingerprint per process; the
	// anonymous helper must not.
	stable := xid.New().Machine()
	collisions := 0
	const samples = 32
	for range samples {
		raw, err := newAnonymousCorrelationID()
		require.NoError(t, err)
		id, err := xid.FromString(raw)
		require.NoError(t, err)
		if string(id.Machine()) == string(stable) {
			collisions++
		}
	}
	// A truly fingerprinted helper would collide on every sample. Allow a
	// generous threshold so the test stays stable against random chance
	// (expected collisions ≈ samples / 2^24, i.e. effectively zero).
	require.Less(t, collisions, samples/4,
		"anonymous helper must not reuse xid.New()'s machine fingerprint")
}
