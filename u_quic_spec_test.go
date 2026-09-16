package quic

// [SIGHTGLASS U-LAYER] Tests for the spec plumbing (u_quic_spec.go).

import (
	"testing"

	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/protocol"
	"github.com/stretchr/testify/require"
)

// TestUSpecTokenLengthInstallsATokenStore: a profile that declares a client token length gets Initial
// packets carrying a token of that length. The token cannot be VALID (only the server that issued a
// NEW_TOKEN can make one), but the length is on the wire in clear text in every Initial header, so
// the shape is what is reproduced.
func TestUSpecTokenLengthInstallsATokenStore(t *testing.T) {
	ps := InitialPacketSpec{ClientTokenLength: 7}
	conf := &Config{}
	ps.UpdateConfig(conf)
	require.NotNil(t, conf.TokenStore, "a spec declaring a client token length installed no token store")

	tok := conf.TokenStore.Pop("example.invalid")
	require.NotNil(t, tok)
	require.Len(t, tok.data, 7, "the dummy token store handed out a %d byte token for a declared length of 7", len(tok.data))
	other := conf.TokenStore.Pop("example.invalid")
	require.NotNil(t, other)
	require.NotEqual(t, tok.data, other.data, "the dummy token store returns a constant token, which is itself a fingerprint")
	conf.TokenStore.Put("example.invalid", tok) // must not panic
}

// TestUSpecWithoutATokenLengthLeavesTheConfigAlone: absence means absence (HR-6). A profile that
// declares no client token must not get an invented one, and must not have a Config.TokenStore the
// caller never asked for.
func TestUSpecWithoutATokenLengthLeavesTheConfigAlone(t *testing.T) {
	conf := &Config{}
	(&QUICSpec{}).UpdateConfig(conf)
	require.Nil(t, conf.TokenStore, "a spec declaring no client token installed a token store anyway")
}

// TestUSpecExplicitTokenStoreWins: an explicit store overrides the length-derived dummy, which is
// what carries a REAL NEW_TOKEN from a previous connection to the same origin.
func TestUSpecExplicitTokenStoreWins(t *testing.T) {
	real := NewLRUTokenStore(1, 1)
	ps := InitialPacketSpec{ClientTokenLength: 7, TokenStore: real}
	conf := &Config{}
	ps.UpdateConfig(conf)
	require.Same(t, real, conf.TokenStore)
}

// TestUSpecDestConnIDLengthZeroKeepsTheUpstreamRandomLength: 0 means "the profile declares none", so
// the upstream behaviour stands rather than a length this package invented.
func TestUSpecDestConnIDLengthZeroKeepsTheUpstreamRandomLength(t *testing.T) {
	tr := &UTransport{Transport: &Transport{}, QUICSpec: &QUICSpec{}}
	id, err := tr.uGenerateDestConnID()
	require.NoError(t, err)
	require.GreaterOrEqual(t, id.Len(), int(protocol.MinConnectionIDLenInitial))
	require.LessOrEqual(t, id.Len(), protocol.MaxConnIDLen)
}

// TestUSpecDestConnIDLengthIsHonoured: any length the profile declares is the length generated.
func TestUSpecDestConnIDLengthIsHonoured(t *testing.T) {
	for l := int(protocol.MinConnectionIDLenInitial); l <= protocol.MaxConnIDLen; l++ {
		tr := &UTransport{Transport: &Transport{}, QUICSpec: &QUICSpec{InitialPacketSpec: InitialPacketSpec{DestConnIDLength: l}}}
		id, err := tr.uGenerateDestConnID()
		require.NoError(t, err)
		require.Equalf(t, l, id.Len(), "spec asked for a %d byte destination connection ID and got %d", l, id.Len())
	}
}
