package wire

// [SIGHTGLASS U-LAYER] Populate quic-go's local TransportParameters from the utls
// quic_transport_parameters extension carried in a browser ClientHello spec.
//
// When the ClientHello is emitted from a utls preset, the extension body on the wire is marshaled by
// utls from tls.TransportParameters — NOT by TransportParameters.Marshal below. quic-go's local flow
// control must therefore be derived from the SAME values, or the connection would police limits it
// never advertised. Parameters the browser does not send are left at the caller's defaults.

import (
	"time"

	tls "github.com/Berserk-Automation-Hub/utls"

	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/protocol"
)

func (p *TransportParameters) PopulateFromUQUIC(params tls.TransportParameters) {
	for i, param := range params {
		switch param.ID() {
		case uint64(maxIdleTimeoutParameterID):
			if v, ok := param.(tls.MaxIdleTimeout); ok {
				p.MaxIdleTimeout = time.Duration(v) * time.Millisecond
			}
		case uint64(maxUDPPayloadSizeParameterID):
			if v, ok := param.(tls.MaxUDPPayloadSize); ok {
				p.MaxUDPPayloadSize = protocol.ByteCount(v)
			}
		case uint64(initialMaxDataParameterID):
			if v, ok := param.(tls.InitialMaxData); ok {
				p.InitialMaxData = protocol.ByteCount(v)
			}
		case uint64(initialMaxStreamDataBidiLocalParameterID):
			if v, ok := param.(tls.InitialMaxStreamDataBidiLocal); ok {
				p.InitialMaxStreamDataBidiLocal = protocol.ByteCount(v)
			}
		case uint64(initialMaxStreamDataBidiRemoteParameterID):
			if v, ok := param.(tls.InitialMaxStreamDataBidiRemote); ok {
				p.InitialMaxStreamDataBidiRemote = protocol.ByteCount(v)
			}
		case uint64(initialMaxStreamDataUniParameterID):
			if v, ok := param.(tls.InitialMaxStreamDataUni); ok {
				p.InitialMaxStreamDataUni = protocol.ByteCount(v)
			}
		case uint64(initialMaxStreamsBidiParameterID):
			if v, ok := param.(tls.InitialMaxStreamsBidi); ok {
				p.MaxBidiStreamNum = protocol.StreamNum(v)
			}
		case uint64(initialMaxStreamsUniParameterID):
			if v, ok := param.(tls.InitialMaxStreamsUni); ok {
				p.MaxUniStreamNum = protocol.StreamNum(v)
			}
		case uint64(maxAckDelayParameterID):
			if v, ok := param.(tls.MaxAckDelay); ok {
				p.MaxAckDelay = time.Duration(v) * time.Millisecond
			}
		case uint64(disableActiveMigrationParameterID):
			p.DisableActiveMigration = true
		case uint64(activeConnectionIDLimitParameterID):
			if v, ok := param.(tls.ActiveConnectionIDLimit); ok {
				p.ActiveConnectionIDLimit = uint64(v)
			}
		case uint64(initialSourceConnectionIDParameterID):
			v, ok := param.(tls.InitialSourceConnectionID)
			if !ok {
				continue
			}
			if len(v) > 0 {
				p.InitialSourceConnectionID = protocol.ParseConnectionID(v)
				continue
			}
			// An empty InitialSourceConnectionID in the spec means "whatever this connection's real
			// source connection ID is" — write it back so utls puts the true value on the wire.
			// (Chrome uses a zero-length source connection ID, so this is normally still empty.)
			params[i] = tls.InitialSourceConnectionID(p.InitialSourceConnectionID.Bytes())
		case uint64(maxDatagramFrameSizeParameterID):
			if v, ok := param.(tls.MaxDatagramFrameSize); ok {
				p.MaxDatagramFrameSize = protocol.ByteCount(v)
			}
		default:
			// Unknown / vendor / GREASE parameters (e.g. Google's 0x3128 connection options and the
			// RFC 9368 version_information) are wire-only: they go out verbatim via utls and have no
			// quic-go-side representation.
		}
	}
}
