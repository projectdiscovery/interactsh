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

	t.Run("bare correlation ID (20 chars, valid xid)", func(t *testing.T) {
		id := xid.New().String()
		require.Len(t, id, 20)
		require.True(t, options.isCorrelationID(id))
	})

	t.Run("corrID + 1 char nonce", func(t *testing.T) {
		id := xid.New().String() + "a"
		require.True(t, options.isCorrelationID(id))
	})

	t.Run("corrID + 2 char nonce", func(t *testing.T) {
		id := xid.New().String() + "ab"
		require.True(t, options.isCorrelationID(id))
	})

	t.Run("corrID + 3 char nonce (minimum)", func(t *testing.T) {
		id := xid.New().String() + "abc"
		require.True(t, options.isCorrelationID(id))
	})

	t.Run("corrID + 4 char nonce", func(t *testing.T) {
		id := xid.New().String() + "abcd"
		require.True(t, options.isCorrelationID(id))
	})

	t.Run("corrID + 8 char nonce", func(t *testing.T) {
		id := xid.New().String() + "abcdefgh"
		require.True(t, options.isCorrelationID(id))
	})

	t.Run("corrID + 13 char nonce (default)", func(t *testing.T) {
		id := xid.New().String() + strings.Repeat("a", 13)
		require.True(t, options.isCorrelationID(id))
	})

	t.Run("too short string", func(t *testing.T) {
		require.False(t, options.isCorrelationID("tooshort"))
	})

	t.Run("non-xid prefix (contains wxyz)", func(t *testing.T) {
		// xid only uses [0-9a-v], so 'w', 'x', 'y', 'z' are invalid
		id := "wxyzwxyzwxyzwxyzwxyz" + strings.Repeat("a", 13)
		require.False(t, options.isCorrelationID(id))
	})

	t.Run("non-alphanumeric", func(t *testing.T) {
		id := xid.New().String() + "abc-def-ghijk"
		require.False(t, options.isCorrelationID(id))
	})

	t.Run("sliding window finds embedded ID with minIdLength", func(t *testing.T) {
		validID := xid.New().String() + "abc" // 23 chars (corrID + 3 char nonce)
		longer := ".." + validID + ".."        // non-alphanumeric padding prevents spurious matches
		found := false
		for chunk := range stringsutil.SlideWithLength(longer, options.getMinIdLength()) {
			if options.isCorrelationID(chunk) {
				found = true
				break
			}
		}
		require.True(t, found, "sliding window should find embedded correlation ID")
	})
}

func TestTwoTierMatching(t *testing.T) {
	options := Options{CorrelationIdLength: settings.CorrelationIdLengthDefault, CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault}

	t.Run("tier 1: corrID+nonce in same label", func(t *testing.T) {
		corrID := xid.New().String()
		nonce := strings.Repeat("a", 13)
		domain := corrID + nonce + ".interactsh.com."

		parts := strings.Split(domain, ".")
		var matches []string
		for _, part := range parts {
			for partChunk := range stringsutil.SlideWithLength(part, options.getMinIdLength()) {
				normalizedPartChunk := strings.ToLower(partChunk)
				if options.isCorrelationID(normalizedPartChunk) {
					matches = append(matches, normalizedPartChunk)
				}
			}
		}
		require.NotEmpty(t, matches, "tier 1 should find corrID+nonce")
		// Verify correlation ID extraction
		require.Equal(t, corrID, matches[0][:options.CorrelationIdLength])
	})

	t.Run("tier 2: bare corrID label (no nonce)", func(t *testing.T) {
		corrID := xid.New().String()
		domain := corrID + ".interactsh.com."

		parts := strings.Split(domain, ".")
		// Tier 1: no matches expected (no label >= minIdLength with valid corrID+nonce)
		tier1Matched := false
		for _, part := range parts {
			for partChunk := range stringsutil.SlideWithLength(part, options.getMinIdLength()) {
				normalizedPartChunk := strings.ToLower(partChunk)
				if options.isCorrelationID(normalizedPartChunk) {
					tier1Matched = true
				}
			}
		}
		// SlideWithLength emits the full string for short labels, so tier 1 may match bare corrID
		// Tier 2 is a fallback — test that bare corrID labels are matchable
		tier2Matched := false
		for _, part := range parts {
			normalizedPart := strings.ToLower(part)
			if len(normalizedPart) == options.CorrelationIdLength && options.isCorrelationID(normalizedPart) {
				tier2Matched = true
			}
		}
		require.True(t, tier1Matched || tier2Matched, "bare corrID should be matched by at least one tier")
	})

	t.Run("preference: corrID+nonce matched by tier 1", func(t *testing.T) {
		corrID := xid.New().String()
		nonce := strings.Repeat("a", 13)
		domain := corrID + nonce + ".interactsh.com."

		parts := strings.Split(domain, ".")
		tier1Matched := false
		for _, part := range parts {
			for partChunk := range stringsutil.SlideWithLength(part, options.getMinIdLength()) {
				normalizedPartChunk := strings.ToLower(partChunk)
				if options.isCorrelationID(normalizedPartChunk) {
					tier1Matched = true
				}
			}
		}
		require.True(t, tier1Matched, "corrID+nonce should be matched by tier 1")
	})

	t.Run("any nonce length works with default config", func(t *testing.T) {
		corrID := xid.New().String()
		for _, nonceLen := range []int{3, 4, 8, 13, 20} {
			nonce := strings.Repeat("a", nonceLen)
			domain := corrID + nonce + ".interactsh.com."
			parts := strings.Split(domain, ".")
			matched := false
			for _, part := range parts {
				for partChunk := range stringsutil.SlideWithLength(part, options.getMinIdLength()) {
					normalizedPartChunk := strings.ToLower(partChunk)
					if options.isCorrelationID(normalizedPartChunk) {
						// Verify the correlation ID is extractable
						require.Equal(t, corrID, normalizedPartChunk[:options.CorrelationIdLength])
						matched = true
					}
				}
			}
			require.True(t, matched, "should match corrID with nonce length %d", nonceLen)
		}
	})
}

func TestSubdomainOf(t *testing.T) {
	options := Options{
		CorrelationIdLength:      settings.CorrelationIdLengthDefault,
		CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault,
		Domains:                  []string{"interactsh.com"},
	}

	t.Run("corrID+nonce same label (FQDN)", func(t *testing.T) {
		result := options.subdomainOf("corrIDnonce.interactsh.com.", true)
		require.Equal(t, "corrIDnonce", result)
	})

	t.Run("corrID and nonce dot-separated (FQDN)", func(t *testing.T) {
		result := options.subdomainOf("corrID.nonce.interactsh.com.", true)
		require.Equal(t, "corrID.nonce", result)
	})

	t.Run("nonce before corrID (FQDN)", func(t *testing.T) {
		result := options.subdomainOf("nonce.corrID.interactsh.com.", true)
		require.Equal(t, "nonce.corrID", result)
	})

	t.Run("corrID+nonce same label (HTTP)", func(t *testing.T) {
		result := options.subdomainOf("corrIDnonce.interactsh.com", false)
		require.Equal(t, "corrIDnonce", result)
	})

	t.Run("corrID and nonce dot-separated (HTTP)", func(t *testing.T) {
		result := options.subdomainOf("corrID.nonce.interactsh.com", false)
		require.Equal(t, "corrID.nonce", result)
	})

	t.Run("subdomain server domain", func(t *testing.T) {
		opts := Options{
			CorrelationIdLength:      settings.CorrelationIdLengthDefault,
			CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault,
			Domains:                  []string{"s.interactsh.com"},
		}
		result := opts.subdomainOf("corrID.nonce.s.interactsh.com.", true)
		require.Equal(t, "corrID.nonce", result)
	})

	t.Run("no matching domain returns hostname", func(t *testing.T) {
		result := options.subdomainOf("corrID.nonce.unknown.com", false)
		require.Equal(t, "corrID.nonce.unknown.com", result)
	})
}

func TestURLReflection(t *testing.T) {
	options := Options{CorrelationIdLength: settings.CorrelationIdLengthDefault, CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault}
	reflection := options.URLReflection("c6rj61aciaeutn2ae680cg5ugboyyyyyn.interactsh.com")
	require.NotEmpty(t, reflection)
}
