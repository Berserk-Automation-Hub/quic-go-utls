package wire

// [SIGHTGLASS U-LAYER] Tests for TransportParameters.PopulateFromUQUIC (u_transport_parameters.go).
//
// When the ClientHello comes from a utls preset, the quic_transport_parameters extension body on the
// wire is marshaled by utls — not by TransportParameters.Marshal. quic-go's LOCAL flow control must
// be derived from the same values or the connection polices limits it never advertised: it would
// grant the peer a window the peer never saw, or tear the connection down for exceeding one the peer
// was never told about. These tests pin that mapping, including the two cases that are easy to get
// silently wrong (millisecond durations, and the write-back of an empty source connection ID).

import (
	"testing"
	"time"

	tls "github.com/Berserk-Automation-Hub/utls"

	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestPopulateFromUQUICMapsEveryParameterQuicGoPolices(t *testing.T) {
	p := &TransportParameters{}
	p.PopulateFromUQUIC(tls.TransportParameters{
		tls.MaxIdleTimeout(30000),
		tls.MaxUDPPayloadSize(1472),
		tls.InitialMaxData(15728640),
		tls.InitialMaxStreamDataBidiLocal(6291456),
		tls.InitialMaxStreamDataBidiRemote(6291457),
		tls.InitialMaxStreamDataUni(6291458),
		tls.InitialMaxStreamsBidi(100),
		tls.InitialMaxStreamsUni(103),
		tls.MaxAckDelay(25),
		tls.ActiveConnectionIDLimit(4),
		tls.MaxDatagramFrameSize(65536),
		&tls.DisableActiveMigration{},
	})

	require.Equal(t, 30*time.Second, p.MaxIdleTimeout, "max_idle_timeout is in MILLISECONDS on the wire")
	require.Equal(t, protocol.ByteCount(1472), p.MaxUDPPayloadSize)
	require.Equal(t, protocol.ByteCount(15728640), p.InitialMaxData)
	require.Equal(t, protocol.ByteCount(6291456), p.InitialMaxStreamDataBidiLocal)
	require.Equal(t, protocol.ByteCount(6291457), p.InitialMaxStreamDataBidiRemote)
	require.Equal(t, protocol.ByteCount(6291458), p.InitialMaxStreamDataUni)
	require.Equal(t, protocol.StreamNum(100), p.MaxBidiStreamNum)
	require.Equal(t, protocol.StreamNum(103), p.MaxUniStreamNum)
	require.Equal(t, 25*time.Millisecond, p.MaxAckDelay, "max_ack_delay is in MILLISECONDS on the wire")
	require.Equal(t, uint64(4), p.ActiveConnectionIDLimit)
	require.Equal(t, protocol.ByteCount(65536), p.MaxDatagramFrameSize)
	require.True(t, p.DisableActiveMigration)
}

// TestPopulateFromUQUICLeavesUnsentParametersAlone: parameters the browser does not send keep the
// caller's defaults, which govern purely local behaviour. Zeroing them would silently change the
// connection's own policy to something the profile never asked for.
func TestPopulateFromUQUICLeavesUnsentParametersAlone(t *testing.T) {
	p := &TransportParameters{
		MaxIdleTimeout:          42 * time.Second,
		AckDelayExponent:        3,
		ActiveConnectionIDLimit: 7,
		MaxDatagramFrameSize:    protocol.InvalidByteCount,
	}
	p.PopulateFromUQUIC(tls.TransportParameters{tls.InitialMaxData(1234)})
	require.Equal(t, protocol.ByteCount(1234), p.InitialMaxData)
	require.Equal(t, 42*time.Second, p.MaxIdleTimeout, "a parameter the spec does not carry was overwritten")
	require.Equal(t, uint8(3), p.AckDelayExponent)
	require.Equal(t, uint64(7), p.ActiveConnectionIDLimit)
	require.Equal(t, protocol.InvalidByteCount, p.MaxDatagramFrameSize)
}

// TestPopulateFromUQUICWritesBackAnEmptySourceConnectionID: RFC 9000 §7.3 requires
// initial_source_connection_id to equal the Source Connection ID the client actually put in its
// Initial header, and the peer VERIFIES it. A spec cannot know that value (it is generated per
// connection), so an empty one in the spec means "fill in the real one" — and the write-back has to
// reach the caller's slice, because that slice is what utls marshals onto the wire.
func TestPopulateFromUQUICWritesBackAnEmptySourceConnectionID(t *testing.T) {
	scid := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	p := &TransportParameters{InitialSourceConnectionID: scid}
	params := tls.TransportParameters{tls.InitialSourceConnectionID{}}
	p.PopulateFromUQUIC(params)

	require.Equal(t, scid, p.InitialSourceConnectionID, "the real source connection ID was overwritten by the spec's empty one")
	written, ok := params[0].(tls.InitialSourceConnectionID)
	require.True(t, ok)
	require.Equal(t, []byte{1, 2, 3, 4}, []byte(written),
		"the spec's empty initial_source_connection_id was not replaced with the connection's real one, so the peer would reject the handshake")
}

// TestPopulateFromUQUICKeepsAnExplicitSourceConnectionID: a spec that names one wins, and the local
// view follows it, so the two never disagree.
func TestPopulateFromUQUICKeepsAnExplicitSourceConnectionID(t *testing.T) {
	p := &TransportParameters{InitialSourceConnectionID: protocol.ParseConnectionID([]byte{9, 9})}
	params := tls.TransportParameters{tls.InitialSourceConnectionID{7, 7, 7}}
	p.PopulateFromUQUIC(params)
	require.Equal(t, protocol.ParseConnectionID([]byte{7, 7, 7}), p.InitialSourceConnectionID)
	require.Equal(t, []byte{7, 7, 7}, []byte(params[0].(tls.InitialSourceConnectionID)))
}

// TestPopulateFromUQUICIgnoresWireOnlyParameters: Google's connection options (0x3128), the RFC 9368
// version_information and GREASE parameters have no quic-go-side representation. They must travel
// verbatim through utls and change nothing locally — not be mistaken for a parameter that does.
func TestPopulateFromUQUICIgnoresWireOnlyParameters(t *testing.T) {
	before := TransportParameters{InitialMaxData: 5, MaxIdleTimeout: time.Second}
	p := before
	p.PopulateFromUQUIC(tls.TransportParameters{
		&tls.GREASEQUICBit{},
		tls.InitialMaxStreamsBidi(10),
	})
	require.Equal(t, protocol.StreamNum(10), p.MaxBidiStreamNum)
	p.MaxBidiStreamNum = before.MaxBidiStreamNum
	require.Equal(t, before, p, "an unrecognised wire-only parameter changed quic-go's local view")
}
