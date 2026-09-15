package quic

// [SIGHTGLASS U-LAYER] Spec-driven client connection. Mirrors newClientConnection, differing in
// exactly three places:
//   - the local transport parameters are taken FROM the ClientHello spec (so what quic-go's flow
//     control believes it advertised is byte-identical to what utls actually put on the wire),
//   - the crypto setup and the packet packer are the spec-driven variants, and
//   - ECN MARKING of outgoing packets is off, because Chrome never marks (see uSendsECNMarks).
//
// PARITY ROUND-5 — ECN CODEPOINT ON THE IP HEADER (a real, remotely-observable divergence).
//
// Rounds 1-4 audited what QUIC puts INSIDE the datagram and what setsockopt puts on the socket, but
// never what the kernel stamps into the IP header of each datagram we emit. quic-go performs RFC-9000
// §13.4.2 ECN validation on every connection: sentPacketHandler.ECNMode() returns ECT(0) for the
// first 10 one-RTT packets (ecnStateTesting) and keeps returning it forever if the path validates
// (ecnStateCapable) — internal/ackhandler/ecn.go:122-139 — and oobConn.WritePacket then attaches an
// IP_TOS control message carrying those bits (sys_conn_oob.go:255-266 / appendIPv4ECNMsg:311). So
// every one-RTT datagram we sent left the host with IP TOS byte 0x02.
//
// Chrome 152 marks NOTHING. Both halves are proven:
//
//	CAPTURE. In the genuine-Chrome oracle pcap (fingerprints/_login/quic_login.pcap) all 444
//	outgoing QUIC datagrams across all 13 Chrome->Google connections carry IP TOS byte 0x00
//	(DF=1, TTL=64, first datagram 1250 B on 13/13). The only ECN-marked datagrams in that capture
//	(11x ECT(1), 10x ECT(0)) belong to macOS's own 17.x/172.224.x Apple flows, which are
//	distinguishable at a glance: they use 1350-byte datagrams, not Chrome's 1250.
//
//	SOURCE. quiche's QuicPacketWriterParams::ecn_codepoint defaults to ECN_NOT_ECT
//	(quic_packet_writer.h:45) and QuicConnection::SetFromConfig only overrides it when the
//	congestion controller opts in: `if (sent_packet_manager_.EnableECT1()) set_ecn_codepoint(ECN_ECT1);
//	else if (sent_packet_manager_.EnableECT0()) set_ecn_codepoint(ECN_ECT0);` (quic_connection.cc:473-477).
//	EVERY sender Chrome ships by default hard-returns false from both: bbr2_sender.h:101-102,
//	bbr_sender.h:142-143, bbr3_sender.h:97-98, tcp_cubic_sender_bytes.h:79-80. Only prague_sender
//	(L4S, not the default) ever returns true. Chrome's QUIC socket setup calls SetRecvTos() and
//	nothing else ECN-related (quic_session_pool.cc:1228).
//
// So the fix is to disable ECN MARKING while leaving ECN RECEPTION intact — which is exactly
// Chrome's asymmetry (SetRecvTos yes, ecn_codepoint NOT_ECT). Passing enableECN=false to
// NewSentPacketHandler does precisely that: ECNMode() returns ECNUnsupported, WritePacket attaches no
// IP_TOS cmsg, and the receive path is untouched (receivedPacketTracker counts ECT0/ECT1/CE off the
// wire independently, received_packet_tracker.go:30-42, so our ACKs still report ECN counts if a
// server ever marks — as Chrome's do).
//
// This is the u-layer's file, so no upstream quic-go file is modified. Guarded on real wire bytes by
// quich3.TestNoECNMarksOnAnyDatagram, which records the actual oob control messages handed to
// WriteMsgUDP over a full loopback QUIC handshake.

import (
	"context"
	"fmt"
	"net"

	tls "github.com/bogdanfinn/utls"

	"github.com/bogdanfinn/quic-go-utls/internal/ackhandler"
	"github.com/bogdanfinn/quic-go-utls/internal/handshake"
	"github.com/bogdanfinn/quic-go-utls/internal/protocol"
	"github.com/bogdanfinn/quic-go-utls/internal/utils"
	"github.com/bogdanfinn/quic-go-utls/internal/wire"
	"github.com/bogdanfinn/quic-go-utls/qlogwriter"
)

// uSendsECNMarks is whether this connection ECN-marks the packets it SENDS. Chrome does not, ever
// (444/444 captured datagrams Not-ECT; every default Chrome congestion controller returns false from
// EnableECT0/EnableECT1) — see the ROUND-5 note at the top of this file. It is a named constant so
// that the single-factor ablation is a one-token edit: flip it to `s.conn.capabilities().ECN` (the
// value rounds 1-4 passed) and quich3.TestNoECNMarksOnAnyDatagram must fail.
const uSendsECNMarks = false

var newUClientConnection = func(
	ctx context.Context,
	conn sendConn,
	runner connRunner,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	connIDGenerator ConnectionIDGenerator,
	statelessResetter *statelessResetter,
	conf *Config,
	tlsConf *tls.Config,
	initialPacketNumber protocol.PacketNumber,
	enable0RTT bool,
	hasNegotiatedVersion bool,
	qlogTrace qlogwriter.Trace,
	logger utils.Logger,
	v protocol.Version,
	uSpec *QUICSpec,
) *wrappedConn {
	s := &Conn{
		conn:                conn,
		config:              conf,
		origDestConnID:      destConnID,
		handshakeDestConnID: destConnID,
		srcConnIDLen:        srcConnID.Len(),
		perspective:         protocol.PerspectiveClient,
		logID:               destConnID.String(),
		logger:              logger,
		qlogTrace:           qlogTrace,
		versionNegotiated:   hasNegotiatedVersion,
		version:             v,
	}
	if qlogTrace != nil {
		s.qlogger = qlogTrace.AddProducer()
	}
	if s.qlogger != nil {
		var srcAddr, destAddr *net.UDPAddr
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			srcAddr = addr
		}
		if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			destAddr = addr
		}
		s.qlogger.RecordEvent(startedConnectionEvent(srcAddr, destAddr))
	}
	s.connIDManager = newConnIDManager(
		destConnID,
		func(token protocol.StatelessResetToken) { runner.AddResetToken(token, s) },
		runner.RemoveResetToken,
		s.queueControlFrame,
	)
	s.connIDGenerator = newConnIDGenerator(
		runner,
		srcConnID,
		nil,
		statelessResetter,
		connRunnerCallbacks{
			AddConnectionID:    func(connID protocol.ConnectionID) { runner.Add(connID, s) },
			RemoveConnectionID: runner.Remove,
			ReplaceWithClosed:  runner.ReplaceWithClosed,
		},
		s.queueControlFrame,
		connIDGenerator,
	)
	s.ctx, s.ctxCancel = context.WithCancelCause(ctx)
	s.preSetup()
	s.sentPacketHandler = ackhandler.NewSentPacketHandler(
		initialPacketNumber,
		protocol.ByteCount(s.config.InitialPacketSize),
		s.rttStats,
		&s.connStats,
		false,          // has no effect
		uSendsECNMarks, // [U-LAYER] false: Chrome never ECN-marks (see the ROUND-5 note above)
		s.receivedPacketHandler.IgnorePacketsBelow,
		s.perspective,
		s.qlogger,
		s.logger,
	)
	s.currentMTUEstimate.Store(uint32(estimateMaxPayloadSize(protocol.ByteCount(s.config.InitialPacketSize))))
	oneRTTStream := newCryptoStream()

	// [U-LAYER] The transport parameters we advertise are the ones inside the ClientHello spec: utls
	// writes those exact bytes into extension 0x39, so quic-go's local view MUST be derived from them.
	// Start from the same defaults newClientConnection uses (they govern purely local behaviour, e.g.
	// the ACK delay exponent, for parameters the browser does not send), then let the spec win.
	params := &wire.TransportParameters{
		InitialMaxStreamDataBidiRemote: protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataBidiLocal:  protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataUni:        protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxData:                 protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
		MaxIdleTimeout:                 s.config.MaxIdleTimeout,
		MaxBidiStreamNum:               protocol.StreamNum(s.config.MaxIncomingStreams),
		MaxUniStreamNum:                protocol.StreamNum(s.config.MaxIncomingUniStreams),
		MaxAckDelay:                    protocol.MaxAckDelayInclGranularity,
		MaxUDPPayloadSize:              protocol.MaxPacketBufferSize,
		AckDelayExponent:               protocol.AckDelayExponent,
		ActiveConnectionIDLimit:        protocol.MaxActiveConnectionIDs,
		InitialSourceConnectionID:      srcConnID,
		EnableResetStreamAt:            conf.EnableStreamResetPartialDelivery,
		MaxDatagramFrameSize:           protocol.InvalidByteCount,
	}
	if s.config.EnableDatagrams {
		params.MaxDatagramFrameSize = wire.MaxDatagramSize
	}
	qtp, err := uQUICTransportParameters(uSpec.ClientHelloSpec)
	if err != nil {
		panic(fmt.Sprintf("quic u-layer: %v", err))
	}
	params.PopulateFromUQUIC(qtp.TransportParameters)
	if s.qlogger != nil {
		s.qlogTransportParameters(params, protocol.PerspectiveClient, false)
	}

	cs, err := handshake.NewUCryptoSetupClient(
		destConnID,
		params,
		tlsConf,
		enable0RTT,
		s.rttStats,
		s.qlogger,
		logger,
		s.version,
		uSpec.ClientHelloSpec,
	)
	if err != nil {
		panic(fmt.Sprintf("quic u-layer: apply ClientHelloSpec: %v", err))
	}
	s.cryptoStreamHandler = cs
	s.cryptoStreamManager = newCryptoStreamManager(s.initialStream, s.handshakeStream, oneRTTStream)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen)
	s.packer = newUPacketPacker(
		newPacketPacker(srcConnID, s.connIDManager.Get, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, &s.receivedPacketHandler, s.datagramQueue, s.perspective),
		uSpec,
	)
	if len(tlsConf.ServerName) > 0 {
		s.tokenStoreKey = tlsConf.ServerName
	} else {
		s.tokenStoreKey = conn.RemoteAddr().String()
	}
	if s.config.TokenStore != nil {
		if token := s.config.TokenStore.Pop(s.tokenStoreKey); token != nil {
			s.packer.SetToken(token.data)
			s.rttStats.SetInitialRTT(token.rtt)
		}
	}
	return &wrappedConn{Conn: s}
}

// uQUICTransportParameters finds the quic_transport_parameters extension in a ClientHello spec.
// Loud-fails (HR-6) if it is absent: without it the ClientHello would carry no transport parameters
// and the peer would reject the connection.
func uQUICTransportParameters(chs *tls.ClientHelloSpec) (*tls.QUICTransportParametersExtension, error) {
	for _, ext := range chs.Extensions {
		if qtp, ok := ext.(*tls.QUICTransportParametersExtension); ok {
			return qtp, nil
		}
	}
	return nil, fmt.Errorf("ClientHelloSpec has no *tls.QUICTransportParametersExtension (extension 0x0039)")
}
