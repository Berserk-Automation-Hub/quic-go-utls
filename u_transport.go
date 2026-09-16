package quic

// [SIGHTGLASS U-LAYER] Spec-driven dial. Mirrors Transport.dial/doDial, differing only where the
// QUICSpec pins something observable: the connection-ID lengths, the first Initial packet number,
// and the use of the spec-driven connection (u_connection.go).

import (
	"context"
	"errors"
	"fmt"
	"net"

	tls "github.com/Berserk-Automation-Hub/utls"

	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/protocol"
	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/utils"
	"github.com/Berserk-Automation-Hub/quic-go-utls/qlogwriter"
)

// UTransport is a Transport that dials with a QUICSpec.
type UTransport struct {
	*Transport

	QUICSpec *QUICSpec
}

// uDialsEarly is whether a spec-driven dial attempts 0-RTT. It is always true, and it is a named
// constant rather than a parameter for two reasons.
//
// There is no non-early entry point. Upstream quic-go exposes Transport.Dial and Transport.DialEarly;
// this file used to mirror both, but nothing ever called UTransport.Dial except this package's own
// tests — the shipped caller is quich3.h3client -> UTransport.DialEarly, and a browser is never
// "cold by policy": Chrome attempts 0-RTT whenever it holds a ticket for the origin. An exported
// second entry point that only tests reach is dead code on the shipped path, so it is gone and the
// use0RTT parameter it existed to vary went with it.
//
// It stays NAMED so the single-factor ablation is a one-token edit: flip it to false and the warm
// half of Sightglass's TestQUICResumptionHelloMatchesChromeQJA4 must fail, because a client that
// does not allow 0-RTT sends no early_data extension and emits the COLD q-JA4 on a warm origin.
const uDialsEarly = true

// DialEarly dials a new connection, attempting to use 0-RTT if possible. It is the u-layer's only
// dial entry point; see uDialsEarly.
func (t *UTransport) DialEarly(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *Config) (*Conn, error) {
	return t.dialSpec(ctx, addr, "", tlsConf, conf)
}

func (t *UTransport) dialSpec(ctx context.Context, addr net.Addr, host string, tlsConf *tls.Config, conf *Config) (*Conn, error) {
	if t.QUICSpec == nil {
		return nil, errors.New("quic u-layer: UTransport.QUICSpec is nil")
	}
	if t.QUICSpec.ClientHelloSpec == nil {
		return nil, errors.New("quic u-layer: QUICSpec.ClientHelloSpec is nil")
	}
	// RFC 9000 §17.2 gives the connection-ID length field 8 bits but caps the value at 20, and
	// protocol.GenerateConnectionID slices a fixed 20-byte array, so anything larger panics deep
	// inside the dial with "slice bounds out of range" instead of naming the profile field that is
	// wrong. Both lengths are profile data, so both are bounded here and reported by name.
	if l := t.QUICSpec.InitialPacketSpec.SrcConnIDLength; l < 0 || l > protocol.MaxConnIDLen {
		return nil, fmt.Errorf("quic u-layer: SrcConnIDLength %d is outside the RFC 9000 §17.2 range 0..%d", l, protocol.MaxConnIDLen)
	}
	// The Source Connection ID length is a spec property, so it must be pinned before Transport.init
	// caches its generator. Both halves below are load-bearing and neither can stand without the
	// other: the length itself, and the permission to use a ZERO length — which is what a browser
	// sends and what upstream refuses to pick, substituting protocol.DefaultConnectionIDLength (4)
	// unless allowZeroLengthConnIDs says otherwise. A spec-driven client owns its socket outright,
	// so it does not need a non-empty connection ID to demultiplex on.
	//
	// The assignment is skipped when the caller made its own connection-ID decision, because
	// overwriting it here would be silent either way; what happens instead is the check AFTER init,
	// which refuses the dial rather than sending a length the spec never asked for.
	if t.ConnectionIDGenerator == nil && t.ConnectionIDLength == 0 {
		t.ConnectionIDLength = t.QUICSpec.InitialPacketSpec.SrcConnIDLength
	}
	if err := t.init(true); err != nil {
		return nil, err
	}
	// Transport.init caches ONE connection-ID generator for the life of the Transport (it runs under
	// a sync.Once), so whatever it settled on above is the Source Connection ID length every dial on
	// this Transport will put in its long header — including dials whose spec pins something else.
	// Two ways to arrive here with a mismatch, neither of which can be honoured after the fact:
	//
	//   - the caller set Transport.ConnectionIDLength or Transport.ConnectionIDGenerator itself, so
	//     the `if` above deliberately left it alone; or
	//   - an EARLIER dial on this same Transport pinned a different spec's length, and init is a
	//     no-op the second time.
	//
	// Silently sending the other length is the failure this fork exists to prevent: the SCID length
	// is in clear text in every long header, so a dial that quietly used 4 bytes where the profile
	// declares 0 wears a fingerprint the document never declared. HR-6 — loud-fail, never substitute.
	if got := t.connIDGenerator.ConnectionIDLen(); got != t.QUICSpec.InitialPacketSpec.SrcConnIDLength {
		return nil, fmt.Errorf(
			"quic u-layer: this Transport issues %d-byte source connection IDs and this dial's spec pins SrcConnIDLength %d; a Transport's connection-ID generator is fixed at its first dial, so one Transport cannot send both",
			got, t.QUICSpec.InitialPacketSpec.SrcConnIDLength)
	}
	if err := validateConfig(conf); err != nil {
		return nil, err
	}
	conf = populateConfig(conf)
	t.QUICSpec.UpdateConfig(conf)
	tlsConf = tlsConf.Clone()
	setTLSConfigServerName(tlsConf, addr, host)
	return t.uDoDial(ctx,
		newSendConn(t.conn, addr, packetInfo{}, utils.DefaultLogger),
		tlsConf,
		conf,
		protocol.PacketNumber(t.QUICSpec.InitialPacketSpec.InitPacketNumber),
		false,
		conf.Versions[0],
	)
}

func (t *UTransport) uDoDial(
	ctx context.Context,
	sendConn sendConn,
	tlsConf *tls.Config,
	config *Config,
	initialPacketNumber protocol.PacketNumber,
	hasNegotiatedVersion bool,
	version protocol.Version,
) (*Conn, error) {
	srcConnID, err := t.connIDGenerator.GenerateConnectionID()
	if err != nil {
		return nil, err
	}
	destConnID, err := t.uGenerateDestConnID()
	if err != nil {
		return nil, err
	}

	tracingID := nextConnTracingID()
	ctx = context.WithValue(ctx, ConnectionTracingKey, tracingID)

	t.mutex.Lock()
	if t.closeErr != nil {
		t.mutex.Unlock()
		return nil, t.closeErr
	}

	var qlogTrace qlogwriter.Trace
	if config.Tracer != nil {
		qlogTrace = config.Tracer(ctx, true, destConnID)
	}

	logger := utils.DefaultLogger.WithPrefix("client")
	logger.Infof("Starting new uQUIC connection to %s (%s -> %s), source connection ID %s, destination connection ID %s, version %s", tlsConf.ServerName, sendConn.LocalAddr(), sendConn.RemoteAddr(), srcConnID, destConnID, version)

	conn := newUClientConnection(
		context.WithoutCancel(ctx),
		sendConn,
		(*packetHandlerMap)(t.Transport),
		destConnID,
		srcConnID,
		t.connIDGenerator,
		t.statelessResetter,
		config,
		tlsConf,
		initialPacketNumber,
		uDialsEarly,
		hasNegotiatedVersion,
		qlogTrace,
		logger,
		version,
		t.QUICSpec,
	)
	t.handlers[srcConnID] = conn
	t.mutex.Unlock()

	errChan := make(chan error, 1)
	recreateChan := make(chan errCloseForRecreating, 1)
	go func() {
		err := conn.run()
		var recreateErr *errCloseForRecreating
		if errors.As(err, &recreateErr) {
			recreateChan <- *recreateErr
			return
		}
		if t.isSingleUse {
			t.Close()
		}
		errChan <- err
	}()

	var earlyConnChan <-chan struct{}
	if uDialsEarly {
		earlyConnChan = conn.earlyConnReady()
	}

	select {
	case <-ctx.Done():
		conn.destroy(nil)
		select {
		case <-errChan:
		case <-recreateChan:
		}
		return nil, context.Cause(ctx)
	case params := <-recreateChan:
		return t.uDoDial(ctx, sendConn, tlsConf, config, params.nextPacketNumber, true, params.nextVersion)
	case err := <-errChan:
		return nil, err
	case <-earlyConnChan:
		return conn.Conn, nil
	case <-conn.HandshakeComplete():
		return conn.Conn, nil
	}
}

// uGenerateDestConnID generates the first-flight Destination Connection ID at the spec's length
// (Chrome: 8 bytes). Upstream picks a random length in [8,20], which is itself a fingerprint.
func (t *UTransport) uGenerateDestConnID() (protocol.ConnectionID, error) {
	l := t.QUICSpec.InitialPacketSpec.DestConnIDLength
	if l == 0 {
		return generateConnectionIDForInitial()
	}
	if l < protocol.MinConnectionIDLenInitial {
		return protocol.ConnectionID{}, errors.New("quic u-layer: DestConnIDLength below the RFC 9000 minimum of 8")
	}
	if l > protocol.MaxConnIDLen {
		return protocol.ConnectionID{}, fmt.Errorf("quic u-layer: DestConnIDLength %d above the RFC 9000 §17.2 maximum of %d", l, protocol.MaxConnIDLen)
	}
	return protocol.GenerateConnectionID(l)
}
