package quic

// [SIGHTGLASS U-LAYER] Browser-parroting QUIC spec.
//
// This file (and the other u_*.go files in this package, plus internal/handshake/u_crypto_setup.go
// and internal/wire/u_transport_parameters.go) are the ONLY additions this vendored fork makes to
// upstream github.com/bogdanfinn/quic-go-utls v1.0.9-utls. They let a caller pin every
// passively-observable property of the QUIC Initial flight to a captured browser:
//
//   - the TLS ClientHello bytes            (utls ClientHelloSpec, via UQUICClient+ApplyPreset)
//   - the quic_transport_parameters body   (the spec's *tls.QUICTransportParametersExtension)
//   - Destination/Source Connection ID lengths
//   - the first Initial packet number + its on-wire length
//   - the Initial frame layout (CRYPTO split/order + PING/PADDING interleave) and the exact
//     UDP datagram size
//
// Everything else is upstream quic-go. See third_party/quic-go-utls/UQUIC_LAYER_PATCH.md.

import (
	"crypto/rand"

	tls "github.com/bogdanfinn/utls"
)

// DefaultUDPDatagramMinSize is the RFC 9000 §14.1 minimum for a datagram carrying an Initial.
const DefaultUDPDatagramMinSize = 1200

// QUICSpec is a full client-side QUIC parrot: the Initial-packet shape plus the TLS ClientHello.
type QUICSpec struct {
	// InitialPacketSpec pins the QUIC Initial packet (header fields + frame layout).
	InitialPacketSpec InitialPacketSpec

	// ClientHelloSpec is the utls ClientHello to send in the Initial CRYPTO stream. It MUST contain
	// a *tls.QUICTransportParametersExtension: those transport parameters are both what goes on the
	// wire AND what this connection's local flow control is configured from (see
	// wire.TransportParameters.PopulateFromUQUIC).
	ClientHelloSpec *tls.ClientHelloSpec

	// UDPDatagramMinSize is the minimum UDP payload size of a datagram carrying an Initial packet.
	// Initial datagrams built through the spec's FrameBuilder are padded to EXACTLY the connection's
	// max packet size (Config.InitialPacketSize), so this is only the floor used when no
	// FrameBuilder is set. 0 means DefaultUDPDatagramMinSize.
	UDPDatagramMinSize int
}

// InitialPacketSpec pins the observable fields of the client's Initial packets.
type InitialPacketSpec struct {
	// SrcConnIDLength is the length in bytes of the client's Source Connection ID. 0 means a
	// zero-length SCID (what Chrome sends).
	SrcConnIDLength int

	// DestConnIDLength is the length in bytes of the randomly generated Destination Connection ID
	// of the first flight. 0 means "use the upstream default" (a random length in [8,20]).
	DestConnIDLength int

	// InitPacketNumberLength is the on-wire length in bytes of the first Initial packet's packet
	// number (1..4). 0 means "let quic-go choose" (which never picks 1).
	InitPacketNumberLength int

	// InitPacketNumber is the packet number of the first Initial packet.
	InitPacketNumber uint64

	// TokenStore overrides Config.TokenStore for this connection.
	TokenStore TokenStore

	// ClientTokenLength, when > 0 and TokenStore is nil, installs a dummy token store that returns
	// random tokens of that length (they will not be valid; only the wire shape is reproduced).
	ClientTokenLength int

	// FrameBuilder lays out the frames of every Initial packet that carries CRYPTO data. If nil, the
	// upstream layout (one CRYPTO frame + trailing PADDING) is used.
	FrameBuilder QUICFrameBuilder
}

func (ps *InitialPacketSpec) UpdateConfig(conf *Config) {
	if ts := ps.getTokenStore(); ts != nil {
		conf.TokenStore = ts
	}
}

func (ps *InitialPacketSpec) getTokenStore() TokenStore {
	if ps.TokenStore != nil {
		return ps.TokenStore
	}
	if ps.ClientTokenLength > 0 {
		return &dummyTokenStore{tokenLength: ps.ClientTokenLength}
	}
	return nil
}

func (s *QUICSpec) UpdateConfig(config *Config) { s.InitialPacketSpec.UpdateConfig(config) }

type dummyTokenStore struct{ tokenLength int }

func (d *dummyTokenStore) Pop(string) *ClientToken {
	data := make([]byte, d.tokenLength)
	if _, err := rand.Read(data); err != nil {
		return nil
	}
	return &ClientToken{data: data}
}

func (d *dummyTokenStore) Put(string, *ClientToken) {}
