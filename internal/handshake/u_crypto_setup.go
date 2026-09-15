package handshake

// [SIGHTGLASS U-LAYER] Client crypto setup that emits a browser-shaped ClientHello.
//
// Upstream NewCryptoSetupClient builds the ClientHello from tls.Config, which cannot reproduce a
// specific browser's extension set/order. This variant drives utls' UQUICClient + ApplyPreset with a
// captured *tls.ClientHelloSpec instead. Everything after the ClientHello — the QUIC event loop, key
// installation, transport-parameter handling — is the SAME cryptoSetup code path as upstream; only
// the tls connection object differs (see the tlsQUICConn interface).

import (
	"context"

	tls "github.com/bogdanfinn/utls"

	"github.com/bogdanfinn/quic-go-utls/internal/protocol"
	"github.com/bogdanfinn/quic-go-utls/internal/utils"
	"github.com/bogdanfinn/quic-go-utls/internal/wire"
	"github.com/bogdanfinn/quic-go-utls/qlogwriter"
)

// tlsQUICConn is the subset of *tls.QUICConn that cryptoSetup uses. *tls.UQUICConn now implements
// all of it, including StoreSession (see the vendored utls patch 2/4, third_party/utls/u_quic.go).
type tlsQUICConn interface {
	Start(context.Context) error
	NextEvent() tls.QUICEvent
	Close() error
	HandleData(tls.QUICEncryptionLevel, []byte) error
	SetTransportParameters([]byte)
	SendSessionTicket(tls.QUICSessionTicketOptions) error
	StoreSession(*tls.SessionState) error
	ConnectionState() tls.ConnectionState
}

var _ tlsQUICConn = (*tls.QUICConn)(nil)

// uQUICConn adapts *tls.UQUICConn to tlsQUICConn.
//
// PARITY A-5 (round 3). This used to be a loud-fail stub: `StoreSession` was unreachable because
// UQUICClient dropped tls.QUICConfig.EnableSessionEvents, so no QUICStoreSession event could ever
// fire and a spec-driven QUIC client could never persist a resumption ticket — it dialled COLD
// forever, emitting Chrome's cold q-JA4 on every connection while genuine Chrome emits the
// resumption one (q13d0314h3_55b375c5d22e_79cc91d6b50c) as soon as it has a ticket for the origin.
// Both halves are now vendored patches in third_party/utls (1/4 and 2/4), so the adapter simply
// forwards and the whole upstream 0-RTT path in crypto_setup.go (QUICStoreSession ->
// marshalDataForSessionState, QUICResumeSession -> handleDataFromSessionState) becomes reachable.
type uQUICConn struct{ *tls.UQUICConn }

// NewUCryptoSetupClient creates a client crypto setup whose ClientHello is built from chs.
func NewUCryptoSetupClient(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	tlsConf *tls.Config,
	enable0RTT bool,
	rttStats *utils.RTTStats,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
	version protocol.Version,
	chs *tls.ClientHelloSpec,
) (CryptoSetup, error) {
	cs := newCryptoSetup(connID, tp, rttStats, qlogger, logger, protocol.PerspectiveClient, version)

	tlsConf = tlsConf.Clone()
	tlsConf.MinVersion = tls.VersionTLS13
	cs.tlsConf = tlsConf
	cs.allow0RTT = enable0RTT

	// EnableSessionEvents mirrors what upstream's own NewCryptoSetupClient passes
	// (crypto_setup.go:102 `EnableSessionEvents: true`). It is what makes QUICStoreSession /
	// QUICResumeSession fire, which is what carries the peer transport parameters into and out of the
	// session ticket — the precondition for 0-RTT (PARITY A-5).
	uc := tls.UQUICClient(&tls.QUICConfig{TLSConfig: tlsConf, EnableSessionEvents: true}, tls.HelloCustom)
	if err := uc.ApplyPreset(chs); err != nil {
		return nil, err
	}
	cs.conn = uQUICConn{uc}
	// NOTE: no SetTransportParameters here. The spec's *tls.QUICTransportParametersExtension already
	// carries the exact bytes utls will write into extension 0x39; if utls asks anyway (the
	// QUICTransportParametersRequired event) the shared handleEvent path answers with tp.Marshal.
	return cs, nil
}
