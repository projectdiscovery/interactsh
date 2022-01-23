package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetURLIDComponent(t *testing.T) {
	random := getURLIDComponent("c6rj61aciaeutn2ae680cg5ugboyyyyyn.interactsh.com")
	require.Equal(t, "c6rj61aciaeutn2ae680cg5ugboyyyyyn", random, "could not get correct component")
}
