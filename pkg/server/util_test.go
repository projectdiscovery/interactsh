package server

import (
	"testing"

	"github.com/projectdiscovery/interactsh/pkg/settings"
	"github.com/stretchr/testify/require"
)

func TestIsCorrelationID_DefaultLengths(t *testing.T) {
	opts := &Options{
		CorrelationIdLength:      settings.CorrelationIdLengthDefault,
		CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault,
	}

	require.True(t, opts.isCorrelationID("c6rj61aciaeutn2ae680cg5ugboyyyyyn"))
	require.False(t, opts.isCorrelationID("too-short"))
	require.False(t, opts.isCorrelationID("c6rj61aciaeutn2ae680cg5ugboyyyy!!"))
}

func TestIsCorrelationID_ShortLengthsRejectDomainLabelFalsePositives(t *testing.T) {
	opts := &Options{CorrelationIdLength: 3, CorrelationIdNonceLength: 3}

	const exampleLabel = "example"
	candidates := []string{exampleLabel[:6], exampleLabel[1:7], "google"}
	for _, candidate := range candidates {
		require.False(t, opts.isCorrelationID(candidate), "%q must not be treated as a correlation id", candidate)
	}

	require.True(t, opts.isCorrelationID("d82yyy"), "valid xid+zbase32 preamble must still match")
}

func TestIsCorrelationID_AlphabetBoundaries(t *testing.T) {
	opts := &Options{CorrelationIdLength: 3, CorrelationIdNonceLength: 3}

	require.False(t, opts.isCorrelationID("xyzbnd"), "xid prefix must reject chars outside 0-9a-v")
	require.False(t, opts.isCorrelationID("abclmv"), "zbase32 suffix must reject chars outside its alphabet")
}

func TestIsValidCorrelationID(t *testing.T) {
	opts := &Options{
		CorrelationIdLength: settings.CorrelationIdLengthDefault,
	}

	// Valid xid lowercase string of default length (20)
	require.True(t, opts.isValidCorrelationID("c6rj61aciaeutn2ae680"))

	// Reject uppercase characters
	require.False(t, opts.isValidCorrelationID("C6RJ61ACIAEUTN2AE680"))
	require.False(t, opts.isValidCorrelationID("c6rj61aciaeutn2ae68A"))

	// Reject characters outside xid alphabet (w, x, y, z)
	require.False(t, opts.isValidCorrelationID("c6rj61aciaeutn2ae68w"))
	require.False(t, opts.isValidCorrelationID("c6rj61aciaeutn2ae68x"))
	require.False(t, opts.isValidCorrelationID("c6rj61aciaeutn2ae68y"))
	require.False(t, opts.isValidCorrelationID("c6rj61aciaeutn2ae68z"))

	// Reject invalid lengths
	require.False(t, opts.isValidCorrelationID("c6rj61aciaeutn2ae68"))
	require.False(t, opts.isValidCorrelationID("c6rj61aciaeutn2ae6800"))
	require.False(t, opts.isValidCorrelationID(""))

	// Reject non-alphanumeric characters
	require.False(t, opts.isValidCorrelationID("c6rj61aciaeutn2ae68-"))
	require.False(t, opts.isValidCorrelationID("c6rj61aciaeutn2ae68."))

	// Custom CorrelationIdLength
	customOpts := &Options{
		CorrelationIdLength: 5,
	}
	require.True(t, customOpts.isValidCorrelationID("c6rj6"))
	require.False(t, customOpts.isValidCorrelationID("c6rj61"))
	require.False(t, customOpts.isValidCorrelationID("c6rjW"))
}
