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

	tls "github.com/Berserk-Automation-Hub/utls"

	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/protocol"
	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/utils"
	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/wire"
	"github.com/Berserk-Automation-Hub/quic-go-utls/qlogwriter"
)

// tlsQUICConn is the subset of *tls.QUICConn that cryptoSetup uses. *tls.UQUICConn now implements
// all of it, including StoreSession (see patch 2/4 in the utls fork, u_quic.go —
// github.com/Berserk-Automation-Hub/utls on the "sightglass" branch).
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
// Both halves are now patches in the utls fork (1/4 and 2/4), so the adapter simply
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

	// The caller's Config is never mutated: the u-layer writes a TLS-version floor onto it below, and
	// so does utls' ApplyPreset.
	tlsConf = tlsConf.Clone()
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
	// RFC 9001 §4.2: QUIC uses TLS 1.3 and nothing else, whatever the ClientHello spec's
	// supported_versions list happens to contain. This has to be set AFTER ApplyPreset, not before:
	// ApplyPreset -> UConn.SetTLSVers writes a MinVersion DERIVED FROM THE SPEC onto the very Config
	// installed above (utls u_conn.go), so a spec that also lists TLS 1.2 — a perfectly ordinary thing
	// for a browser profile to carry — silently lowers the LOCAL policy and UQUICConn.Start then
	// refuses the connection with "tls: Config MinVersion must be at least TLS 1.13" before a single
	// byte reaches the wire. Setting it first, as this did, is a no-op that ApplyPreset overwrites.
	//
	// Nothing observable changes: the ClientHello bytes, supported_versions included, come from the
	// spec either way. Only the local floor moves, and QUIC has no other legal value for it.
	tlsConf.MinVersion = tls.VersionTLS13
	cs.conn = uQUICConn{uc}
	// NOTE: no SetTransportParameters here. The spec's *tls.QUICTransportParametersExtension already
	// carries the exact bytes utls will write into extension 0x39; if utls asks anyway (the
	// QUICTransportParametersRequired event) the shared handleEvent path answers with tp.Marshal.
	return cs, nil
}
