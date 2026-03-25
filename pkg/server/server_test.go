package server

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/interactsh/pkg/settings"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

func TestGetURLIDComponent(t *testing.T) {
	options := Options{CorrelationIdLength: settings.CorrelationIdLengthDefault, CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault}
	random := options.getURLIDComponent("c6rj61aciaeutn2ae680cg5ugboyyyyyn.interactsh.com")
	require.Equal(t, "c6rj61aciaeutn2ae680cg5ugboyyyyyn", random, "could not get correct component")
}

func TestIsCorrelationID(t *testing.T) {
	options := Options{CorrelationIdLength: settings.CorrelationIdLengthDefault, CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault}

	t.Run("exact length match", func(t *testing.T) {
		id := strings.Repeat("a", options.CorrelationIdLength) + strings.Repeat("b", options.CorrelationIdNonceLength)
		require.True(t, options.isCorrelationID(id))
	})

	t.Run("shorter than expected", func(t *testing.T) {
		require.False(t, options.isCorrelationID("tooshort"))
	})

	t.Run("sliding window finds embedded ID", func(t *testing.T) {
		shortNonce := Options{CorrelationIdLength: settings.CorrelationIdLengthDefault, CorrelationIdNonceLength: 4}
		validID := xid.New().String() + "abcd"
		longer := ".." + validID + ".." // non-alphanumeric padding prevents spurious matches
		found := false
		for chunk := range stringsutil.SlideWithLength(longer, shortNonce.GetIdLength()) {
			if shortNonce.isCorrelationID(chunk) {
				found = true
				break
			}
		}
		require.True(t, found, "sliding window should find embedded correlation ID")
	})
}
