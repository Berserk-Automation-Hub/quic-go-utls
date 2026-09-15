package quic

// [SIGHTGLASS U-LAYER] Spec-driven dial. Mirrors Transport.dial/doDial, differing only where the
// QUICSpec pins something observable: the connection-ID lengths, the first Initial packet number,
// and the use of the spec-driven connection (u_connection.go).

import (
	"context"
	"errors"
	"net"

	tls "github.com/bogdanfinn/utls"

	"github.com/bogdanfinn/quic-go-utls/internal/protocol"
	"github.com/bogdanfinn/quic-go-utls/internal/utils"
	"github.com/bogdanfinn/quic-go-utls/qlogwriter"
)

// UTransport is a Transport that dials with a QUICSpec.
type UTransport struct {
	*Transport

	QUICSpec *QUICSpec
}

// Dial dials a new connection to a remote host (not using 0-RTT).
func (t *UTransport) Dial(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *Config) (*Conn, error) {
	return t.dialSpec(ctx, addr, "", tlsConf, conf, false)
}

// DialEarly dials a new connection, attempting to use 0-RTT if possible.
func (t *UTransport) DialEarly(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *Config) (*Conn, error) {
	return t.dialSpec(ctx, addr, "", tlsConf, conf, true)
}

func (t *UTransport) dialSpec(ctx context.Context, addr net.Addr, host string, tlsConf *tls.Config, conf *Config, use0RTT bool) (*Conn, error) {
	if t.QUICSpec == nil {
		return nil, errors.New("quic u-layer: UTransport.QUICSpec is nil")
	}
	if t.QUICSpec.ClientHelloSpec == nil {
		return nil, errors.New("quic u-layer: QUICSpec.ClientHelloSpec is nil")
	}
	// The Source Connection ID length is a spec property, so it must be pinned before Transport.init
	// caches a generator (Chrome sends a zero-length SCID, which upstream never picks by default).
	if t.ConnectionIDGenerator == nil {
		t.ConnectionIDGenerator = &protocol.DefaultConnectionIDGenerator{ConnLen: t.QUICSpec.InitialPacketSpec.SrcConnIDLength}
	}
	if err := t.init(true); err != nil { // allowZeroLengthConnIDs: a spec'd client owns its socket
		return nil, err
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
		use0RTT,
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
	use0RTT bool,
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
		use0RTT,
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
	if use0RTT {
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
		return t.uDoDial(ctx, sendConn, tlsConf, config, params.nextPacketNumber, true, use0RTT, params.nextVersion)
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
	return protocol.GenerateConnectionID(l)
}
