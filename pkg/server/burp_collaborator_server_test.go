package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBurpCollaborator(t *testing.T) {
	t.Run("id generate", func(t *testing.T) {
		ID, err := biidGenBurpID("vb/Vo8BaJ81e9dlYWuoa3FlGt+sJSN6QREfpOrA8mBQ=")
		require.Nil(t, err)
		require.Equal(t, "idbvyew82qjwc34muug1dq", ID)
	})
}
