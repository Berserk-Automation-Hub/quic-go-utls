package quic

// [SIGHTGLASS U-LAYER] Tests for the spec-driven dial (u_transport.go, u_connection.go,
// u_packet_packer.go, internal/handshake/u_crypto_setup.go, internal/wire/u_transport_parameters.go).
//
// The u-layer exists to pin the passively observable properties of the client's Initial flight, so
// its tests assert those properties ON THE WIRE: the datagrams are captured off a UDP socket and
// decrypted with the RFC 9001 §5.2 Initial keys anybody who sees the Destination Connection ID can
// derive. Nothing here reads back our own configuration.
//
// THE SPEC IN THIS FILE IS SYNTHETIC AND IS NOT A BROWSER (HR-1). No value below is a captured
// fingerprint, and none is claimed to be one: the browser's values live in a Sightglass profile
// document, and this fork must never contain an engine identity (HR-5). What these tests assert is
// the MECHANISM — that whatever a spec pins is what leaves the socket — which is precisely the thing
// a profile-level test cannot prove on its own.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	tls "github.com/Berserk-Automation-Hub/utls"

	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/handshake"
	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/protocol"
	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/testdata"
	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/wire"
	"github.com/Berserk-Automation-Hub/quic-go-utls/qlog"
	"github.com/Berserk-Automation-Hub/quic-go-utls/qlogwriter"
	"github.com/Berserk-Automation-Hub/quic-go-utls/quicvarint"
	"github.com/Berserk-Automation-Hub/quic-go-utls/testutils/events"
	"github.com/stretchr/testify/require"
)

// uTestSpecValues are the synthetic pins this file drives through the u-layer and then looks for on
// the wire. They are deliberately values upstream quic-go would never pick by itself, so finding
// them in a datagram proves the spec drove the packet rather than the library's own defaults:
// upstream picks a random DCID length in [8,20], a 4-byte SCID, packet number 0, and a
// packet-number field of 2 or 4 bytes — never 1.
const (
	uTestDCIDLen      = 8
	uTestSCIDLen      = 0
	uTestFirstPN      = 1
	uTestFirstPNLen   = 1
	uTestDatagramSize = 1250
)

func uTestClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []byte{0},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519}},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
			}},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519}}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.ALPNExtension{AlpnProtocols: []string{uTestALPN}},
			&tls.QUICTransportParametersExtension{TransportParameters: tls.TransportParameters{
				tls.MaxIdleTimeout(30000),
				tls.MaxUDPPayloadSize(1472),
				tls.InitialMaxData(15728640),
				tls.InitialMaxStreamDataBidiLocal(6291456),
				tls.InitialMaxStreamDataBidiRemote(6291456),
				tls.InitialMaxStreamDataUni(6291456),
				tls.InitialMaxStreamsBidi(100),
				tls.InitialMaxStreamsUni(103),
				tls.InitialSourceConnectionID{},
			}},
		},
	}
}

func uTestSpec() *QUICSpec {
	return &QUICSpec{
		ClientHelloSpec: uTestClientHelloSpec(),
		InitialPacketSpec: InitialPacketSpec{
			SrcConnIDLength:        uTestSCIDLen,
			DestConnIDLength:       uTestDCIDLen,
			InitPacketNumber:       uTestFirstPN,
			InitPacketNumberLength: uTestFirstPNLen,
			FrameBuilder:           &QUICRandomFrames{MinPING: 1, MaxPING: 3, MinCRYPTO: 3, MaxCRYPTO: 8, MinPADDING: 2, MaxPADDING: 6},
		},
	}
}

const uTestALPN = "u-layer-test"

func uTestTLSConfig() *tls.Config {
	return &tls.Config{ServerName: "u-layer.invalid", NextProtos: []string{uTestALPN}, InsecureSkipVerify: true}
}

func uTestQUICConfig() *Config {
	return &Config{
		InitialPacketSize:    uTestDatagramSize,
		HandshakeIdleTimeout: 300 * time.Millisecond,
		MaxIdleTimeout:       300 * time.Millisecond,
	}
}

// uDialIntoTheVoid dials a UDP address nobody answers on and returns every datagram the dial put on
// the wire. The handshake can never complete, which is exactly what is wanted: the client's Initial
// flight is the whole subject.
func uDialIntoTheVoid(t *testing.T, spec *QUICSpec, conf *Config) [][]byte {
	t.Helper()
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer sink.Close()
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer cli.Close()

	tr := &UTransport{Transport: &Transport{Conn: cli}, QUICSpec: spec}
	defer tr.Close()

	dialErr := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		_, err := tr.DialEarly(ctx, sink.LocalAddr(), uTestTLSConfig(), conf)
		dialErr <- err
	}()

	var datagrams [][]byte
	require.NoError(t, sink.SetReadDeadline(time.Now().Add(1100*time.Millisecond)))
	for {
		buf := make([]byte, 2048)
		n, _, err := sink.ReadFrom(buf)
		if err != nil {
			break
		}
		datagrams = append(datagrams, buf[:n])
		if len(datagrams) >= 4 {
			break
		}
	}
	<-done
	// A dial that emits nothing has usually loud-failed inside the packer, and that error is the
	// interesting one — reporting only "no datagrams" would hide it.
	require.NotEmptyf(t, datagrams, "the dial put nothing on the wire; it failed with: %v", <-dialErr)
	return datagrams
}

// uDecryptInitial removes header protection and decrypts one client Initial packet with the keys
// RFC 9001 §5.2 derives from the Destination Connection ID — i.e. exactly what any on-path observer
// can do, which is why the Initial's frame layout is a fingerprint at all.
func uDecryptInitial(t *testing.T, datagram []byte) (*wire.ExtendedHeader, []byte) {
	t.Helper()
	hdr, pdata, _, err := wire.ParsePacket(datagram)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketTypeInitial, hdr.Type, "the first packet in the datagram is not an Initial")
	_, opener := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveServer, hdr.Version)
	data := append([]byte(nil), pdata...)
	extHdr, err := unpackLongHeader(opener, hdr, data)
	require.NoError(t, err)
	extHdrLen := extHdr.ParsedLen()
	payload, err := opener.Open(data[extHdrLen:extHdrLen], data[extHdrLen:], extHdr.PacketNumber, data[:extHdrLen])
	require.NoError(t, err)
	return extHdr, payload
}

// TestUTransportPinsTheInitialPacketShapeOnTheWire is the u-layer's end-to-end guard: every property
// the spec pins is read back out of the bytes that left the socket.
func TestUTransportPinsTheInitialPacketShapeOnTheWire(t *testing.T) {
	datagrams := uDialIntoTheVoid(t, uTestSpec(), uTestQUICConfig())

	for i, dg := range datagrams {
		require.Equalf(t, uTestDatagramSize, len(dg),
			"datagram %d is %d bytes, the spec pins every Initial datagram to %d", i, len(dg), uTestDatagramSize)
	}

	extHdr, payload := uDecryptInitial(t, datagrams[0])
	require.Equalf(t, uTestDCIDLen, extHdr.DestConnectionID.Len(),
		"Destination Connection ID is %d bytes, the spec pins %d (upstream picks a random length in [8,20])",
		extHdr.DestConnectionID.Len(), uTestDCIDLen)
	require.Equalf(t, uTestSCIDLen, extHdr.SrcConnectionID.Len(),
		"Source Connection ID is %d bytes, the spec pins %d (upstream defaults to 4)",
		extHdr.SrcConnectionID.Len(), uTestSCIDLen)
	require.Equalf(t, protocol.PacketNumber(uTestFirstPN), extHdr.PacketNumber,
		"first Initial packet number is %d, the spec pins %d (upstream always starts at 0)",
		extHdr.PacketNumber, uTestFirstPN)
	require.Equalf(t, protocol.PacketNumberLen(uTestFirstPNLen), extHdr.PacketNumberLen,
		"first Initial packet-number field is %d bytes, the spec pins %d (upstream emits only 2 or 4)",
		extHdr.PacketNumberLen, uTestFirstPNLen)
	require.Zerof(t, len(extHdr.Token), "the Initial carries a %d byte token; the spec asks for none", len(extHdr.Token))

	pf := parseInitialPayload(t, payload)
	// The CRYPTO bytes really are a ClientHello (handshake type 0x01), reassembled from offset 0.
	first := pf.crypto[0]
	for _, c := range pf.crypto {
		if c.Offset < first.Offset {
			first = c
		}
	}
	require.Zerof(t, first.Offset, "the lowest CRYPTO offset in the first Initial is %d, want 0", first.Offset)
	require.Equalf(t, byte(0x01), first.Data[0], "the CRYPTO stream does not start with a TLS ClientHello (handshake type 0x%02x)", first.Data[0])
}

// TestUTransportLaysTheInitialOutWithTheSpecsFrameBuilder is the guard for the frame LAYOUT, kept
// apart from the header pins above so that a packer that has fallen back to upstream framing is
// reported as such rather than as whichever header field happens to be asserted first.
//
// Upstream quic-go emits exactly ONE CRYPTO frame followed by a run of trailing PADDING. The
// browser this parrots interleaves several out-of-order CRYPTO fragments with PING and PADDING.
func TestUTransportLaysTheInitialOutWithTheSpecsFrameBuilder(t *testing.T) {
	datagrams := uDialIntoTheVoid(t, uTestSpec(), uTestQUICConfig())
	_, payload := uDecryptInitial(t, datagrams[0])
	pf := parseInitialPayload(t, payload)

	require.Greaterf(t, len(pf.crypto), 1,
		"the Initial carries %d CRYPTO frame(s): that is upstream quic-go's one-CRYPTO-plus-trailing-PADDING layout, not the spec's", len(pf.crypto))
	require.Positivef(t, pf.pings,
		"the Initial carries no PING frames: the spec's frame builder did not lay this packet out")
	require.Positive(t, pf.padding, "the Initial carries no PADDING")

	// The number of separate PADDING RUNS is deliberately NOT asserted here. It is a property of the
	// permutation, not of the layout: MinPADDING..MaxPADDING padding pieces are shuffled in among the
	// CRYPTO and PING frames, and a permutation that happens to put two of them side by side reads
	// back as one run. Asserting it on ONE connection therefore fails roughly one dial in twelve —
	// measured, 1 failure in 12 runs of this test before it was removed — which is a flaky guard, not
	// a guard. The multi-run property is real and IS guarded, statistically and where it is cheap to
	// repeat: TestUQUICRandomFramesEmitsTheChaosShape builds 50 payloads and requires more than one
	// PADDING run in at least one of them. What is deterministic on the wire, and what is asserted
	// above, is that a PING frame and several CRYPTO frames are there at all — upstream quic-go emits
	// neither in an Initial.
}

// TestUTransportKeepsTheSpecLayoutWhenTheClientHelloFillsThePacket: the browser this parrots sends a
// ClientHello that does not fit in one Initial — the oracle pcap shows a two-packet flight — and the
// packer must lay BOTH out with the spec's frame builder, not fall back to one CRYPTO frame when the
// packet is full.
//
// This is the guard for the `reserve` the packer subtracts before it asks upstream for a payload
// (`reserve := protocol.ByteCount(fb.MaxOverhead())`). Every other test in this file uses a small
// synthetic ClientHello that leaves hundreds of spare bytes, so the reserve is slack there and
// deleting it changes nothing: with `reserve = 0` the whole suite stayed green. Under saturation it
// is load-bearing — upstream fills the packet to the last byte, the builder then has no room for the
// extra frame headers a split costs or for a single PING, and the Initial silently reverts to
// upstream's one-CRYPTO-frame shape, which is exactly the tell the frame builder exists to remove.
func TestUTransportKeepsTheSpecLayoutWhenTheClientHelloFillsThePacket(t *testing.T) {
	spec := uTestSpec()
	chs := uTestClientHelloSpec()
	// One large extension, so the hello needs more than one Initial. The value is nothing but
	// filler: no browser is being reproduced here (HR-1), the size is the whole point.
	chs.Extensions = append(chs.Extensions, &tls.GenericExtension{Id: 0x4444, Data: make([]byte, 1400)})
	spec.ClientHelloSpec = chs

	datagrams := uDialIntoTheVoid(t, spec, uTestQUICConfig())
	require.GreaterOrEqualf(t, len(datagrams), 2,
		"a %d-byte ClientHello produced %d datagram(s); it was supposed to need at least two Initials", 1400, len(datagrams))
	for i, dg := range datagrams {
		require.Equalf(t, uTestDatagramSize, len(dg),
			"datagram %d is %d bytes, the spec pins every Initial datagram to %d even when the ClientHello fills it", i, len(dg), uTestDatagramSize)
	}
	// The FIRST Initial is the saturated one — upstream fills it to the last byte and the tail of the
	// hello goes in the next. Measured, with the reserve and without it:
	//
	//	reserve = fb.MaxOverhead()   crypto=5 pings=2 padding=65 runs=3
	//	reserve = 0                  crypto=2 pings=1 padding=0  runs=0
	//
	// so the frame COUNT alone does not separate them (the initial crypto stream splits the hello
	// itself, so two frames appear either way, which is why a count-only assertion let `reserve = 0`
	// through). PADDING does: with nothing reserved there is not one spare byte for it, and the
	// spec's declared MinPADDING..MaxPADDING runs silently become none.
	_, payload := uDecryptInitial(t, datagrams[0])
	pf := parseInitialPayload(t, payload)
	require.Positivef(t, pf.padding,
		"the saturated Initial carries no PADDING at all (%d CRYPTO frame(s), %d PING(s)): the packer reserved nothing for the frame builder, so the layout the spec declares — %d..%d PADDING runs — could not be applied and upstream's shape went out instead",
		len(pf.crypto), pf.pings, 2, 6)
	require.GreaterOrEqualf(t, len(pf.crypto), 3,
		"the saturated Initial carries %d CRYPTO frame(s); the spec's frame builder declares a minimum of 3, and there was no room to split", len(pf.crypto))
	require.Positivef(t, pf.pings, "the saturated Initial carries no PING frame: there was no room left for the spec's layout")
}

// TestUTransportPinsWhateverSourceConnectionIDLengthTheSpecAsks is the engine-agnostic half of the
// SCID guard (HR-9): the length is the PROFILE's, not a constant. Zero is the length Chrome happens
// to use, and it is also what upstream produces once zero-length connection IDs are allowed — so a
// test that only ever asks for zero cannot tell the pin from the permission. This one asks for a
// length upstream would never pick and looks for it in the long header.
func TestUTransportPinsWhateverSourceConnectionIDLengthTheSpecAsks(t *testing.T) {
	for _, l := range []int{3, 5, 12} {
		t.Run(fmt.Sprintf("%d-byte SCID", l), func(t *testing.T) {
			spec := uTestSpec()
			spec.InitialPacketSpec.SrcConnIDLength = l
			datagrams := uDialIntoTheVoid(t, spec, uTestQUICConfig())
			extHdr, _ := uDecryptInitial(t, datagrams[0])
			require.Equalf(t, l, extHdr.SrcConnectionID.Len(),
				"the spec asked for a %d byte source connection ID and the wire carries %d", l, extHdr.SrcConnectionID.Len())
		})
	}
}

// TestUTransportPinsWhateverFirstPacketNumberTheSpecAsks is the engine-agnostic half of the two
// packet-number pins (HR-5, HR-9), and it is here because the reverse attack worked without it.
//
// Every other test in this file drives the single pair (packet number 1, 1-byte field) — which is
// what the browser this fork was written for happens to send. A certifier therefore replaced
// `protocol.PacketNumber(t.QUICSpec.InitialPacketSpec.InitPacketNumber)` in dialSpec with
// `protocol.PacketNumber(1)`, and `hdr.PacketNumberLen = protocol.PacketNumberLen(n)` in
// u_packet_packer.go with `protocol.PacketNumberLen(1)`, and the suite stayed green in both cases:
// an engine's identity burned into library code, invisible — exactly the defect HR-5 exists to
// forbid, and the reason SCID and DCID lengths are already looped over (3/5/12 and 8..20).
//
// So this asks for numbers and field widths no browser profile here declares and reads both back out
// of the long header on the wire. Each case keeps the number inside the field it pins, because a
// truncated packet number is a different (and legitimate) QUIC behaviour, not this pin.
func TestUTransportPinsWhateverFirstPacketNumberTheSpecAsks(t *testing.T) {
	for _, tc := range []struct {
		pn    uint64
		pnLen int
	}{
		{pn: 7, pnLen: 1},
		{pn: 42, pnLen: 2},
		{pn: 3, pnLen: 3},
		{pn: 2, pnLen: 4},
	} {
		t.Run(fmt.Sprintf("packet number %d in a %d-byte field", tc.pn, tc.pnLen), func(t *testing.T) {
			spec := uTestSpec()
			spec.InitialPacketSpec.InitPacketNumber = tc.pn
			spec.InitialPacketSpec.InitPacketNumberLength = tc.pnLen
			datagrams := uDialIntoTheVoid(t, spec, uTestQUICConfig())
			extHdr, _ := uDecryptInitial(t, datagrams[0])
			require.Equalf(t, protocol.PacketNumber(tc.pn), extHdr.PacketNumber,
				"the spec asked for first Initial packet number %d and the wire carries %d", tc.pn, extHdr.PacketNumber)
			require.Equalf(t, protocol.PacketNumberLen(tc.pnLen), extHdr.PacketNumberLen,
				"the spec asked for a %d-byte packet-number field and the wire carries %d", tc.pnLen, extHdr.PacketNumberLen)
		})
	}
}

// uDialOneInitial dials into the void and returns ONLY the first datagram, cancelling the dial the
// moment that datagram is on the wire.
//
// uDialIntoTheVoid waits out a 1.1 s read deadline to collect the whole flight, which is right when
// the flight is the subject — but it costs 1.1 s per dial. The frame-bound guard below needs
// HUNDREDS of independent first Initials, because a per-connection random layout is only observable
// ACROSS connections, and at 1.1 s each that would be four minutes. One datagram and a cancel costs
// ~0.13 ms (measured: 200 dials in 25 ms), so the shipped-path guard can assert a distribution
// instead of a range.
func uDialOneInitial(t *testing.T, spec *QUICSpec, conf *Config) []byte {
	t.Helper()
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer sink.Close()
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer cli.Close()

	tr := &UTransport{Transport: &Transport{Conn: cli}, QUICSpec: spec}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	dialErr := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := tr.DialEarly(ctx, sink.LocalAddr(), uTestTLSConfig(), conf)
		dialErr <- err
	}()

	require.NoError(t, sink.SetReadDeadline(time.Now().Add(900*time.Millisecond)))
	buf := make([]byte, 2048)
	n, _, rerr := sink.ReadFrom(buf)
	cancel()
	<-done
	// A dial that emits nothing has usually loud-failed inside the packer, and that error is the
	// interesting one — reporting only the read deadline would hide it.
	require.NoErrorf(t, rerr, "the dial put nothing on the wire; it failed with: %v", <-dialErr)
	out := make([]byte, n)
	copy(out, buf[:n])
	return out
}

// TestUTransportInitialFrameCountsComeFromTheSpecsBounds is the SHIPPED-PATH half of the frame-bound
// guard (the builder-level half is TestUQUICRandomFramesHonoursTheDeclaredFrameBounds): the CRYPTO,
// PING and PADDING counts on Initials that really left a socket track the bounds THIS dial's spec
// declares, and not a constant compiled into the builder.
//
// It is here for the same reason TestUTransportPinsWhateverFirstPacketNumberTheSpecAsks is: with one
// bound set in play everywhere, replacing the builder's spec reads with constants inside that set's
// range left the entire package green. Two sets that share no value cannot both be satisfied by a
// constant, and reading the counts off the DECRYPTED datagram proves the spec reached the packer
// rather than only the builder's own unit test.
//
// WHAT THE RANGE ASSERTIONS MISSED, and why this dials 200 times. Until this round the varying set
// was dialled ONCE and only Min <= x <= Max was asserted, so every constant inside the declared
// range passed — including the two constants a HALF-read spec produces. Three single-factor
// mutations of the builder, each applied alone, left the whole package green (see the header of
// TestUQUICRandomFramesHonoursTheDeclaredFrameBounds for the exact edits). A single connection
// cannot distinguish "drawn from 2..8" from "pinned at 5": only the DISTRIBUTION over connections
// can, and a connection here costs 0.13 ms.
//
// Measured on this machine, 30 trials of 200 dials each, for the 2..8 / 4..7 / 9..12 set below:
//
//	                       PING seen      CRYPTO seen   max PADDING runs   dials with runs <= MinPADDING
//	real builder           4..7 always    9..12 always  >= 7 always        28..51
//	PADDING pinned at Min  4..7           9..12         2 always           200
//	PADDING pinned at Max  4..7           9..12         >= 8 always        0..2
//	PING pinned at Min     4..4           9..12         >= 7               32..54
//	PING pinned at Max     7..7           9..12         >= 7               28..55
//
// so each of the six declared fields has an assertion below that no other field can satisfy for it.
// PING frames and CRYPTO frames are counted EXACTLY off the wire (a PING is one 0x01 byte; a CRYPTO
// frame carries its own length), so for those the ends of the declared range must be REACHED. Two
// PADDING frames that the shuffle puts side by side read back as ONE run, so PADDING is bounded by
// its distribution instead: some dial must exceed MinPADDING runs (impossible when the count is
// pinned at Min) and at least minDialsAtOrBelowMinPADDING dials must be at or below MinPADDING
// (which pinning at Max produced at most twice in 6000 dials).
func TestUTransportInitialFrameCountsComeFromTheSpecsBounds(t *testing.T) {
	// See the table above: the real builder put 28 or more dials at or below MinPADDING in every one
	// of 30 trials, a builder pinned at MaxPADDING never more than 2.
	const minDialsAtOrBelowMinPADDING = 10

	// MinCRYPTO is >= 3 in both sets because quic-go's initial crypto stream hands the builder three
	// CRYPTO chunks for this ClientHello (measured, 5/5 dials) and the builder can only SPLIT them,
	// never merge — so a set asking for fewer would be unsatisfiable by construction rather than by
	// the spec. Neither set contains 3, which is the count the constant-mutation produces.
	for _, tc := range []struct {
		fb    QUICRandomFrames
		dials int
	}{
		// Every bound pinned: one dial decides it, and it shares no value with the set below.
		{QUICRandomFrames{MinPING: 1, MaxPING: 1, MinCRYPTO: 4, MaxCRYPTO: 5, MinPADDING: 1, MaxPADDING: 1}, 1},
		// Every bound a range: the distribution over dials decides it.
		{QUICRandomFrames{MinPING: 4, MaxPING: 7, MinCRYPTO: 9, MaxCRYPTO: 12, MinPADDING: 2, MaxPADDING: 8}, 200},
	} {
		fb := tc.fb
		t.Run(fmt.Sprintf("CRYPTO %d..%d PING %d..%d PADDING %d..%d in %d dial(s)", fb.MinCRYPTO, fb.MaxCRYPTO, fb.MinPING, fb.MaxPING, fb.MinPADDING, fb.MaxPADDING, tc.dials), func(t *testing.T) {
			spec := uTestSpec()
			spec.InitialPacketSpec.FrameBuilder = &fb

			cryptoCounts, pingCounts, runCounts := map[int]int{}, map[int]int{}, map[int]int{}
			minCrypto, maxCrypto := 1<<30, 0
			minPings, maxPings := 1<<30, 0
			maxRuns, atOrBelowMinPADDING := 0, 0
			for i := 0; i < tc.dials; i++ {
				_, payload := uDecryptInitial(t, uDialOneInitial(t, spec, uTestQUICConfig()))
				pf := parseInitialPayload(t, payload)

				require.GreaterOrEqualf(t, len(pf.crypto), int(fb.MinCRYPTO),
					"the Initial on the wire carries %d CRYPTO frame(s) and this dial's spec declares at least %d: the layout that left the socket is not the one the profile declared",
					len(pf.crypto), fb.MinCRYPTO)
				require.LessOrEqualf(t, len(pf.crypto), int(fb.MaxCRYPTO),
					"the Initial on the wire carries %d CRYPTO frame(s) and this dial's spec declares at most %d: the layout that left the socket is not the one the profile declared",
					len(pf.crypto), fb.MaxCRYPTO)
				require.GreaterOrEqualf(t, pf.pings, int(fb.MinPING),
					"the Initial on the wire carries %d PING frame(s), this dial's spec declares at least %d", pf.pings, fb.MinPING)
				require.LessOrEqualf(t, pf.pings, int(fb.MaxPING),
					"the Initial on the wire carries %d PING frame(s), this dial's spec declares at most %d", pf.pings, fb.MaxPING)
				require.Positivef(t, pf.runs, "the Initial on the wire carries no PADDING; this dial's spec declares %d..%d runs", fb.MinPADDING, fb.MaxPADDING)
				require.LessOrEqualf(t, pf.runs, int(fb.MaxPADDING),
					"the Initial on the wire carries %d PADDING run(s) and this dial's spec declares at most %d", pf.runs, fb.MaxPADDING)

				cryptoCounts[len(pf.crypto)]++
				pingCounts[pf.pings]++
				runCounts[pf.runs]++
				minCrypto, maxCrypto = min(minCrypto, len(pf.crypto)), max(maxCrypto, len(pf.crypto))
				minPings, maxPings = min(minPings, pf.pings), max(maxPings, pf.pings)
				maxRuns = max(maxRuns, pf.runs)
				if pf.runs <= int(fb.MinPADDING) {
					atOrBelowMinPADDING++
				}
			}

			// The margins, on the record on every run rather than inferred from a green tick.
			t.Logf("%d dial(s): CRYPTO frames %v, PING frames %v, PADDING runs %v (%d dial(s) at or below MinPADDING=%d); this dial's spec declares CRYPTO %d..%d, PING %d..%d, PADDING %d..%d",
				tc.dials, cryptoCounts, pingCounts, runCounts, atOrBelowMinPADDING, fb.MinPADDING,
				fb.MinCRYPTO, fb.MaxCRYPTO, fb.MinPING, fb.MaxPING, fb.MinPADDING, fb.MaxPADDING)

			if tc.dials == 1 {
				return // a single connection can only decide the per-dial bounds above
			}
			require.Equalf(t, int(fb.MinCRYPTO), minCrypto,
				"in %d dials the fewest CRYPTO frames any Initial carried was %d and this dial's spec declares a floor of %d: the split count is not being drawn from [MinCRYPTO,MaxCRYPTO], so MinCRYPTO never reaches the packer — %v",
				tc.dials, minCrypto, fb.MinCRYPTO, cryptoCounts)
			require.Equalf(t, int(fb.MaxCRYPTO), maxCrypto,
				"in %d dials the most CRYPTO frames any Initial carried was %d and this dial's spec declares a ceiling of %d: the split count is not being drawn from [MinCRYPTO,MaxCRYPTO], so MaxCRYPTO never reaches the packer — %v",
				tc.dials, maxCrypto, fb.MaxCRYPTO, cryptoCounts)
			require.Equalf(t, int(fb.MinPING), minPings,
				"in %d dials the fewest PING frames any Initial carried was %d and this dial's spec declares a floor of %d: PING frames never merge on the wire, so a floor that is never reached means MinPING is not what the packer drew from — %v",
				tc.dials, minPings, fb.MinPING, pingCounts)
			require.Equalf(t, int(fb.MaxPING), maxPings,
				"in %d dials the most PING frames any Initial carried was %d and this dial's spec declares a ceiling of %d: MaxPING has stopped reaching the packer, so every Initial this profile sends carries a PING count the document never declared — %v",
				tc.dials, maxPings, fb.MaxPING, pingCounts)
			require.Greaterf(t, maxRuns, int(fb.MinPADDING),
				"in %d dials no Initial carried MORE than %d PADDING run(s) although this dial's spec declares up to %d: an Initial can never carry more runs than the frames the builder emitted, so the count is pinned at MinPADDING and MaxPADDING never reaches the packer — %v",
				tc.dials, fb.MinPADDING, fb.MaxPADDING, runCounts)
			require.GreaterOrEqualf(t, atOrBelowMinPADDING, minDialsAtOrBelowMinPADDING,
				"in %d dials only %d Initial(s) carried as few as %d PADDING run(s) (at least %d expected; the real builder produced 28 or more in 30 measured trials, a builder pinned at MaxPADDING never more than 2) although this dial's spec declares a floor of %d: the count is pinned at MaxPADDING and MinPADDING never reaches the packer — %v",
				tc.dials, atOrBelowMinPADDING, fb.MinPADDING, minDialsAtOrBelowMinPADDING, fb.MinPADDING, runCounts)
		})
	}
}

// TestUTransportRejectsAPacketNumberLengthNoLongHeaderCanCarry: RFC 9000 §17.2 gives the
// packet-number length a two-bit field, so 1..4 are the only widths that exist. This is the analogue
// of E22/E23 for the OTHER header field the spec pins, and the two out-of-range directions fail
// differently, which is why both are here:
//
//   - n > 4 does reach the wire writer, and upstream stops it — but as
//     `INTERNAL_ERROR (local): invalid packet number length: 5`, a connection-level error raised
//     three frames below any code that knows the word "profile", after the dial has started and
//     with the field that is wrong named nowhere. A failure that merely differs is not a guard (C1).
//   - n < 0 is not caught at all. The packer's pin is `n > 0 && …`, so a negative width reads as
//     "absent", the dial goes ahead, and the client sends a packet-number width its document never
//     declared — HR-6's silent substitution, exactly.
//
// Both are now refused where the document enters the library, with the field named.
func TestUTransportRejectsAPacketNumberLengthNoLongHeaderCanCarry(t *testing.T) {
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer cli.Close()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}

	for _, n := range []int{5, 255, -1} {
		t.Run(fmt.Sprintf("InitPacketNumberLength %d", n), func(t *testing.T) {
			spec := uTestSpec()
			spec.InitialPacketSpec.InitPacketNumberLength = n
			tr := &UTransport{Transport: &Transport{Conn: cli}, QUICSpec: spec}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			_, err := tr.DialEarly(ctx, addr, uTestTLSConfig(), uTestQUICConfig())
			require.EqualErrorf(t, err,
				fmt.Sprintf("quic u-layer: InitPacketNumberLength %d is outside the RFC 9000 §17.2 range 1..4 (0 means \"let quic-go choose\")", n),
				"a profile declaring a %d-byte packet-number field was accepted; the long header has two bits for it, so whatever went on the wire is not what the document asked for", n)
		})
	}

	// Positive control: ZERO is not "wrong", it is the documented "let quic-go choose", and it must
	// still dial. Without this the three assertions above would also pass if dialSpec refused every
	// value.
	t.Run("zero still dials and lets quic-go choose the width", func(t *testing.T) {
		spec := uTestSpec()
		spec.InitialPacketSpec.InitPacketNumberLength = 0
		datagrams := uDialIntoTheVoid(t, spec, uTestQUICConfig())
		extHdr, _ := uDecryptInitial(t, datagrams[0])
		require.GreaterOrEqualf(t, int(extHdr.PacketNumberLen), 2,
			"a spec declaring no packet-number length produced a %d-byte field; upstream quic-go emits only 2 or 4, so the pin fired for a profile that never asked for one",
			extHdr.PacketNumberLen)
	})
}

// TestUTransportRefusesASpecThisTransportCannotHonour: Transport.init caches ONE connection-ID
// generator for the life of the Transport, so the Source Connection ID length is decided once and
// every later dial on that Transport inherits it. A dial whose spec pins a different length cannot
// be honoured — and must therefore be refused, not quietly served with the other length, which would
// put an SCID length on the wire that this dial's profile never declared (HR-6).
//
// Both ways in are covered: a caller that pinned the Transport's own connection-ID fields (the case
// the pre-init `if` in dialSpec deliberately does not overwrite), and two u-layer sessions sharing
// one Transport — the cross-session leak in its connection-ID form.
func TestUTransportRefusesASpecThisTransportCannotHonour(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}

	t.Run("the caller pinned the Transport's own connection-ID length", func(t *testing.T) {
		cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		defer cli.Close()
		tr := &UTransport{Transport: &Transport{Conn: cli, ConnectionIDLength: 4}, QUICSpec: uTestSpec()}
		defer tr.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, err = tr.DialEarly(ctx, addr, uTestTLSConfig(), uTestQUICConfig())
		require.EqualError(t, err, "quic u-layer: this Transport issues 4-byte source connection IDs and this dial's spec pins SrcConnIDLength 0; a Transport's connection-ID generator is fixed at its first dial, so one Transport cannot send both",
			"the dial went ahead although the Transport pins a 4-byte source connection ID and the spec pins 0: one of those two is silently not what left the socket")
	})

	t.Run("a second session on the same Transport pins a different length", func(t *testing.T) {
		// A real (unanswering) sink rather than a dead port: a datagram to a closed localhost port
		// draws an ICMP port-unreachable, which races the deadline and makes the first dial's error
		// unpredictable. What the first dial has to achieve here is only that Transport.init runs,
		// which is asserted directly below rather than inferred from which error came back.
		sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		defer sink.Close()
		cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		defer cli.Close()
		shared := &Transport{Conn: cli}
		defer shared.Close()

		specA := uTestSpec()
		specA.InitialPacketSpec.SrcConnIDLength = 3
		ctxA, cancelA := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancelA()
		_, err = (&UTransport{Transport: shared, QUICSpec: specA}).DialEarly(ctxA, sink.LocalAddr(), uTestTLSConfig(), uTestQUICConfig())
		require.Error(t, err, "the first dial was supposed to fail: nobody answers on the sink")
		require.Equal(t, 3, shared.connIDGenerator.ConnectionIDLen(),
			"the first dial did not leave this Transport issuing its own spec's 3-byte source connection IDs, so the second dial below would prove nothing")

		specB := uTestSpec()
		specB.InitialPacketSpec.SrcConnIDLength = 5
		ctxB, cancelB := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancelB()
		_, err = (&UTransport{Transport: shared, QUICSpec: specB}).DialEarly(ctxB, addr, uTestTLSConfig(), uTestQUICConfig())
		require.EqualError(t, err, "quic u-layer: this Transport issues 3-byte source connection IDs and this dial's spec pins SrcConnIDLength 5; a Transport's connection-ID generator is fixed at its first dial, so one Transport cannot send both",
			"the second session was served the first session's source connection ID length instead of its own")
	})
}

// TestUTransportSecondInitialKeepsUpstreamPacketNumberLength: the spec pins the FIRST Initial's
// packet-number length only. Pinning every Initial would be its own tell — the capture shows the
// second packet of the ClientHello flight using a 2-byte field.
func TestUTransportSecondInitialKeepsUpstreamPacketNumberLength(t *testing.T) {
	datagrams := uDialIntoTheVoid(t, uTestSpec(), uTestQUICConfig())
	if len(datagrams) < 2 {
		t.Skipf("the dial only produced %d datagram(s); this synthetic ClientHello fits in one Initial and the retransmission never arrived within the deadline", len(datagrams))
	}
	extHdr, _ := uDecryptInitial(t, datagrams[1])
	if extHdr.PacketNumber == uTestFirstPN {
		t.Skipf("datagram 2 is a retransmission of packet number %d, not a second packet", extHdr.PacketNumber)
	}
	require.NotEqualf(t, protocol.PacketNumberLen(uTestFirstPNLen), extHdr.PacketNumberLen,
		"the second Initial also uses a %d-byte packet-number field; the spec pins only the first", uTestFirstPNLen)
}

// TestUTransportLocalFlowControlComesFromTheSpec is the guard for
// wire.TransportParameters.PopulateFromUQUIC, wired in u_connection.go.
//
// utls marshals the quic_transport_parameters extension straight out of the ClientHello spec, so the
// values on the WIRE are the spec's no matter what quic-go believes. What PopulateFromUQUIC fixes is
// the other half: quic-go's OWN view of what it advertised, which is what its flow controllers
// police and what its idle timer uses. If the two disagree the connection grants the peer a window
// the peer never saw, or kills the connection for exceeding a limit the peer was never told about —
// and neither shows up in the ClientHello bytes.
//
// It reads that local view out of the qlog parameters_set event quic-go emits for its own
// parameters, which is the only place the library states it.
func TestUTransportLocalFlowControlComesFromTheSpec(t *testing.T) {
	var rec events.Recorder
	conf := uTestQUICConfig()
	conf.Tracer = func(context.Context, bool, ConnectionID) qlogwriter.Trace { return &events.Trace{Recorder: &rec} }
	// Config values deliberately DIFFERENT from the spec's, so a local view built from the Config
	// instead of from the spec is visible rather than coincidentally equal.
	conf.InitialStreamReceiveWindow = 1 << 17
	conf.InitialConnectionReceiveWindow = 1 << 18
	conf.MaxIdleTimeout = 7 * time.Second

	uDialIntoTheVoid(t, uTestSpec(), conf)

	var local *qlog.ParametersSet
	for _, ev := range rec.Events(qlog.ParametersSet{}) {
		ps, ok := ev.(qlog.ParametersSet)
		if ok && ps.Initiator == qlog.InitiatorLocal {
			local = &ps
			break
		}
	}
	require.NotNil(t, local, "the connection never recorded its own transport parameters")

	require.Equalf(t, protocol.ByteCount(15728640), local.InitialMaxData,
		"quic-go believes it advertised initial_max_data %d; the ClientHello spec says 15728640", local.InitialMaxData)
	require.Equalf(t, protocol.ByteCount(6291456), local.InitialMaxStreamDataBidiLocal,
		"quic-go believes it advertised initial_max_stream_data_bidi_local %d; the ClientHello spec says 6291456", local.InitialMaxStreamDataBidiLocal)
	require.Equal(t, protocol.ByteCount(6291456), local.InitialMaxStreamDataBidiRemote)
	require.Equal(t, protocol.ByteCount(6291456), local.InitialMaxStreamDataUni)
	require.Equal(t, int64(100), local.InitialMaxStreamsBidi)
	require.Equal(t, int64(103), local.InitialMaxStreamsUni)
	require.Equalf(t, 30*time.Second, local.MaxIdleTimeout,
		"quic-go believes it advertised max_idle_timeout %s; the ClientHello spec says 30s", local.MaxIdleTimeout)
	require.Equalf(t, protocol.ByteCount(1472), local.MaxUDPPayloadSize,
		"quic-go believes it advertised max_udp_payload_size %d; the ClientHello spec says 1472", local.MaxUDPPayloadSize)
}

// TestUTransportRejectsAnIncompleteSpec: HR-6. A dial without the pins that define the identity must
// fail loudly rather than fall through to upstream quic-go's shape, which would put a
// quic-go-shaped Initial on the wire under a browser's name.
func TestUTransportRejectsAnIncompleteSpec(t *testing.T) {
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer cli.Close()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}

	for _, tc := range []struct {
		name string
		spec *QUICSpec
		want string
	}{
		{"no spec at all", nil, "quic u-layer: UTransport.QUICSpec is nil"},
		{"no ClientHello spec", &QUICSpec{}, "quic u-layer: QUICSpec.ClientHelloSpec is nil"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &UTransport{Transport: &Transport{Conn: cli}, QUICSpec: tc.spec}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			_, err := tr.DialEarly(ctx, addr, uTestTLSConfig(), uTestQUICConfig())
			require.EqualError(t, err, tc.want)
		})
	}
}

// TestUTransportRejectsAnUndiallableDestConnIDLength: RFC 9000 §7.2 requires the client's first
// Destination Connection ID to be at least 8 bytes. A spec that asks for less must be refused, not
// silently rounded up to something the profile never declared.
func TestUTransportRejectsAnUndiallableDestConnIDLength(t *testing.T) {
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer cli.Close()

	spec := uTestSpec()
	spec.InitialPacketSpec.DestConnIDLength = int(protocol.MinConnectionIDLenInitial) - 1
	tr := &UTransport{Transport: &Transport{Conn: cli}, QUICSpec: spec}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = tr.DialEarly(ctx, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, uTestTLSConfig(), uTestQUICConfig())
	require.EqualError(t, err, "quic u-layer: DestConnIDLength below the RFC 9000 minimum of 8")
}

// TestUTransportRejectsAConnectionIDLengthAboveTheRFCMaximum: RFC 9000 §17.2 caps a connection ID at
// 20 bytes, and protocol.GenerateConnectionID slices a fixed 20-byte array — so a profile that
// declares 21 used to panic with "slice bounds out of range [:21] with length 20" from inside
// connection_id.go, several frames below any code that knows the word "profile". Both lengths come
// from the document, so both are bounded where the document enters the library and the error names
// the field (HR-6: loud-fail, and loudly enough to be actionable).
func TestUTransportRejectsAConnectionIDLengthAboveTheRFCMaximum(t *testing.T) {
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer cli.Close()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}

	t.Run("destination", func(t *testing.T) {
		spec := uTestSpec()
		spec.InitialPacketSpec.DestConnIDLength = protocol.MaxConnIDLen + 1
		tr := &UTransport{Transport: &Transport{Conn: cli}, QUICSpec: spec}
		defer tr.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, err := tr.DialEarly(ctx, addr, uTestTLSConfig(), uTestQUICConfig())
		require.EqualError(t, err, fmt.Sprintf("quic u-layer: DestConnIDLength 21 above the RFC 9000 §17.2 maximum of %d", protocol.MaxConnIDLen))
	})

	t.Run("source", func(t *testing.T) {
		for _, l := range []int{protocol.MaxConnIDLen + 1, -1} {
			spec := uTestSpec()
			spec.InitialPacketSpec.SrcConnIDLength = l
			tr := &UTransport{Transport: &Transport{Conn: cli}, QUICSpec: spec}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			_, err := tr.DialEarly(ctx, addr, uTestTLSConfig(), uTestQUICConfig())
			cancel()
			require.EqualError(t, err, fmt.Sprintf("quic u-layer: SrcConnIDLength %d is outside the RFC 9000 §17.2 range 0..%d", l, protocol.MaxConnIDLen))
		}
	})
}

// TestUTransportGeneratesAFreshDestConnIDEveryDial: the first-flight Destination Connection ID is
// the ONE field in the Initial header that must NOT be reproducible. Everything else the spec pins is
// a constant on purpose — but the DCID is a random nonce, it is the value RFC 9001 §5.2 derives the
// Initial keys from, and it travels in clear text in every client Initial. A client that reuses one
// links every connection it ever makes, to every observer on the path, forever.
//
// uGenerateDestConnID is u-layer code, so upstream's own randomness tests do not cover it, and the
// length assertions elsewhere in this file cannot tell `protocol.GenerateConnectionID(l)` from a
// hard-coded l-byte constant. This one can: it reads the DCID off the wire on three separate dials.
func TestUTransportGeneratesAFreshDestConnIDEveryDial(t *testing.T) {
	const dials = 3
	seen := make([]string, 0, dials)
	for range dials {
		datagrams := uDialIntoTheVoid(t, uTestSpec(), uTestQUICConfig())
		hdr, _, _, err := wire.ParsePacket(datagrams[0])
		require.NoError(t, err)
		require.Equal(t, uTestDCIDLen, hdr.DestConnectionID.Len())
		seen = append(seen, hdr.DestConnectionID.String())
	}
	uniq := map[string]int{}
	for _, id := range seen {
		uniq[id]++
	}
	require.Lenf(t, uniq, dials,
		"%d dials produced only %d distinct Destination Connection ID(s) (%v): the first-flight DCID is not freshly random, so every connection from this host is linkable by its Initial header",
		dials, len(uniq), seen)

	// A DCID that varies but is not random — a counter, a timestamp — would pass the test above, so
	// the three IDs are also required to share almost no byte position. The tolerance is ONE, not
	// five: three uniform 8-byte values share a given position with probability 2^-16, so "two or
	// more shared" has probability 28·2^-32 ≈ 6·10^-9 and cannot flake, while a big-endian nanosecond
	// timestamp shares its top FOUR positions between dials a second apart and a counter shares
	// seven. (An earlier revision required only `shared < 6` and a certifier walked a timestamp
	// straight through it.) Entropy itself is measured where it can be sampled four thousand times:
	// TestUTransportDestConnIDIsUniformlyRandom.
	shared := 0
	for i := range uTestDCIDLen {
		if seen[0][2*i:2*i+2] == seen[1][2*i:2*i+2] && seen[1][2*i:2*i+2] == seen[2][2*i:2*i+2] {
			shared++
		}
	}
	require.LessOrEqualf(t, shared, 1, "%d of %d byte positions are identical across all three Destination Connection IDs (%v): the DCID is structured, not random", shared, uTestDCIDLen, seen)
}

// TestUTransportDestConnIDIsUniformlyRandom is the entropy half of the DCID guard, and it exists
// because three dials cannot measure randomness — only change.
//
// The wire test above proves the DCID that leaves the socket is fresh on every dial. It cannot prove
// it is RANDOM, and an earlier revision that tried (by tolerating five of eight identical byte
// positions) was defeated exactly as the documentation claimed it could not be: a certifier replaced
// protocol.GenerateConnectionID(l) with a big-endian time.Now().UnixNano() — no crypto/rand anywhere
// — and the suite stayed green, because three dials a second apart differ in their low bytes. A
// timestamp DCID is as linkable as a constant one: monotone, predictable, and it puts the host clock
// in clear text in every Initial header.
//
// This drives the SAME function the dial drives — (*UTransport).uGenerateDestConnID, called by
// uDoDial <- dialSpec <- DialEarly, which is what go/quich3/h3client.go:646 calls — and asks of its
// output the two properties true of uniform bytes and false of every structured generator: every
// byte position takes nearly all 256 values, and every bit is set about half the time.
//
// What it CANNOT detect, stated rather than glossed over: a keyed PRF (AES of a counter, say) is
// uniform by construction and would pass, and no statistical test can tell one from randomness
// without the key. What it excludes is the family a real mistake produces — constants, counters,
// timestamps, host prefixes, truncated or biased randomness.
func TestUTransportDestConnIDIsUniformlyRandom(t *testing.T) {
	const samples = 4096
	tr := &UTransport{Transport: &Transport{}, QUICSpec: uTestSpec()}

	values := make([]map[byte]struct{}, uTestDCIDLen)
	for i := range values {
		values[i] = make(map[byte]struct{}, 256)
	}
	bitsSet := make([]int, 8*uTestDCIDLen)
	distinct := make(map[protocol.ConnectionID]struct{}, samples)
	for range samples {
		id, err := tr.uGenerateDestConnID()
		require.NoError(t, err)
		require.Equal(t, uTestDCIDLen, id.Len())
		distinct[id] = struct{}{}
		for i, b := range id.Bytes() {
			values[i][b] = struct{}{}
			for bit := range 8 {
				if b&(1<<bit) != 0 {
					bitsSet[8*i+bit]++
				}
			}
		}
	}
	// The per-position checks come first on purpose: they are the ones that NAME the defect. A
	// timestamp or a counter also repeats itself within 4096 calls, but "only 1 of 256 values at byte
	// 0" says what is wrong, where "3712 distinct instead of 4096" merely differs.
	//
	// A byte position misses a given value in 4096 uniform draws with probability (255/256)^4096 =
	// 1.1e-7, so all 256 are expected and requiring 250 is unflakeable slack. A constant position
	// scores 1; a big-endian nanosecond timestamp scores 1 in its top four positions; a counter
	// scores 1 in seven of eight.
	const minValues = 250
	for i, v := range values {
		require.GreaterOrEqualf(t, len(v), minValues,
			"byte %d of the Destination Connection ID took only %d of 256 possible values in %d generations: that position is not random, so every Initial this host sends carries a stable pattern any observer on the path can link",
			i, len(v), samples)
	}
	// A uniform bit is set samples/2 ± 32 (1σ). 40%..60% is twelve standard deviations out.
	for i, n := range bitsSet {
		require.Truef(t, n > samples*2/5 && n < samples*3/5,
			"bit %d of the Destination Connection ID was set in %d of %d generations (%.1f%%); a uniform bit is set half the time, so this one carries structure",
			i, n, samples, 100*float64(n)/float64(samples))
	}
	require.Equalf(t, samples, len(distinct),
		"%d generations produced only %d distinct Destination Connection IDs: the generator repeats itself", samples, len(distinct))
}

// uVarintAt is a small reader used by the transport-parameter assertions below.
func uVarintAt(t *testing.T, b []byte, i int) (uint64, int) {
	t.Helper()
	v, n, err := quicvarint.Parse(b[i:])
	require.NoError(t, err)
	return v, n
}

// TestUTransportAdvertisesTheSpecsTransportParameters: quic-go's local flow control must be derived
// from the SAME transport parameters utls puts on the wire, or the connection would police limits it
// never advertised. This drives the real dial and then re-reads the parameter block out of the
// ClientHello bytes that left the socket.
func TestUTransportAdvertisesTheSpecsTransportParameters(t *testing.T) {
	spec := uTestSpec()
	datagrams := uDialIntoTheVoid(t, spec, uTestQUICConfig())

	// Reassemble the CRYPTO stream across every Initial that was sent.
	stream := map[uint64]byte{}
	maxOff := uint64(0)
	for _, dg := range datagrams {
		_, payload := uDecryptInitial(t, dg)
		for _, c := range parseInitialPayload(t, payload).crypto {
			for i, b := range c.Data {
				stream[c.Offset+uint64(i)] = b
				if c.Offset+uint64(i)+1 > maxOff {
					maxOff = c.Offset + uint64(i) + 1
				}
			}
		}
	}
	ch := make([]byte, maxOff)
	for i := range ch {
		b, ok := stream[uint64(i)]
		if !ok {
			ch = ch[:i]
			break
		}
		ch[i] = b
	}

	// The quic_transport_parameters extension (0x0039) body, found by scanning the ClientHello for
	// the codepoint followed by a plausible length. The body is a sequence of (id, len, value)
	// varint triples (RFC 9000 §18).
	want := map[uint64]uint64{
		0x01: 30000,    // max_idle_timeout
		0x03: 1472,     // max_udp_payload_size
		0x04: 15728640, // initial_max_data
		0x05: 6291456,  // initial_max_stream_data_bidi_local
		0x06: 6291456,  // initial_max_stream_data_bidi_remote
		0x07: 6291456,  // initial_max_stream_data_uni
		0x08: 100,      // initial_max_streams_bidi
		0x09: 103,      // initial_max_streams_uni
	}
	found := map[uint64]uint64{}
	for i := 0; i+4 < len(ch); i++ {
		if ch[i] != 0x00 || ch[i+1] != 0x39 {
			continue
		}
		bodyLen := int(ch[i+2])<<8 | int(ch[i+3])
		if bodyLen == 0 || i+4+bodyLen > len(ch) {
			continue
		}
		body := ch[i+4 : i+4+bodyLen]
		ok := true
		for j := 0; j < len(body); {
			id, n := uVarintAt(t, body, j)
			j += n
			if j >= len(body) {
				ok = false
				break
			}
			l, n := uVarintAt(t, body, j)
			j += n
			if j+int(l) > len(body) {
				ok = false
				break
			}
			if _, interesting := want[id]; interesting && l > 0 {
				v, _ := uVarintAt(t, body, j)
				found[id] = v
			}
			j += int(l)
		}
		if ok && len(found) > 0 {
			break
		}
		found = map[uint64]uint64{}
	}
	require.Equal(t, want, found,
		"the quic_transport_parameters extension on the wire does not carry the spec's values")
}

// TestUTransportLoudFailsWithoutTransportParameters: a ClientHello spec with no
// quic_transport_parameters extension cannot produce a usable QUIC connection, so the u-layer must
// say so rather than dial something the peer will reject for reasons nobody can trace.
func TestUTransportLoudFailsWithoutTransportParameters(t *testing.T) {
	chs := uTestClientHelloSpec()
	var kept []tls.TLSExtension
	for _, e := range chs.Extensions {
		if _, isTP := e.(*tls.QUICTransportParametersExtension); !isTP {
			kept = append(kept, e)
		}
	}
	require.Less(t, len(kept), len(chs.Extensions), "the test spec had no transport parameters to remove")
	chs.Extensions = kept

	_, err := uQUICTransportParameters(chs)
	require.Error(t, err)
	require.EqualError(t, err, "ClientHelloSpec has no *tls.QUICTransportParametersExtension (extension 0x0039)")
	var nilErr *net.AddrError
	require.False(t, errors.As(err, &nilErr))
}

// TestUTransportCompletesARealHandshake is the u-layer's whole-path guard: a spec-driven dial has to
// produce a WORKING QUIC connection, not just a well-shaped first datagram. It exercises every
// element at once — the spec-driven crypto setup (the ClientHello utls built from the preset is the
// one the server accepts), the transport parameters taken from the spec (a mismatch between what we
// advertised and what we police shows up here and nowhere else), the u packer for the Initial flight
// and upstream's packer for everything after it, and the zero-length source connection ID, which
// upstream's Transport refuses unless the u-layer asks it to allow one.
func TestUTransportCompletesARealHandshake(t *testing.T) {
	serverConf := testdata.GetTLSConfig()
	serverConf.NextProtos = []string{uTestALPN}
	serverSock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer serverSock.Close()
	ln, err := Listen(serverSock, serverConf, &Config{})
	require.NoError(t, err)
	defer ln.Close()

	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer cli.Close()
	tr := &UTransport{Transport: &Transport{Conn: cli}, QUICSpec: uTestSpec()}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accepted := make(chan *Conn, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		accepted <- c
	}()

	clientConf := &tls.Config{ServerName: "localhost", RootCAs: testdata.GetRootCA(), NextProtos: []string{uTestALPN}}
	conf := uTestQUICConfig()
	conf.HandshakeIdleTimeout = 8 * time.Second
	conf.MaxIdleTimeout = 8 * time.Second
	conn, err := tr.DialEarly(ctx, serverSock.LocalAddr(), clientConf, conf)
	require.NoError(t, err, "a spec-driven dial could not complete a handshake against a stock quic-go server")
	defer conn.CloseWithError(0, "")

	require.Equalf(t, uTestALPN, conn.ConnectionState().TLS.NegotiatedProtocol,
		"the handshake completed but negotiated %q", conn.ConnectionState().TLS.NegotiatedProtocol)

	var srv *Conn
	select {
	case srv = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the server never accepted the connection")
	}
	defer srv.CloseWithError(0, "")

	// ECN: the u-layer connection must report ECNUnsupported for its own outgoing packets, because
	// Chrome never marks. This reads the wiring (the enableECN the sent-packet handler was built
	// with), not the constant that feeds it.
	require.Equalf(t, protocol.ECNUnsupported, conn.sentPacketHandler.ECNMode(true),
		"the connection ECN-marks its 1-RTT packets; every datagram would leave the host with IP TOS 0x02")
	require.Equal(t, protocol.ECNUnsupported, conn.sentPacketHandler.ECNMode(false))

	// Data really flows, and MORE of it than quic-go's own default stream window allows. This is the
	// flow-control half of the u-layer: utls writes the SPEC's transport parameters onto the wire, so
	// the server may send up to the spec's initial_max_stream_data (6291456) immediately. If quic-go's
	// local view were built from Config defaults (512 kB) instead of from the spec, the client would
	// police a limit it never advertised and kill the connection with a FLOW_CONTROL_ERROR.
	const payload = 1 << 20
	require.Greater(t, payload, protocol.DefaultInitialMaxStreamData,
		"the test payload fits in quic-go's default stream window, so it cannot detect a local/advertised mismatch")

	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	_, err = str.Write([]byte("u-layer"))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	srvDone := make(chan error, 1)
	go func() {
		srvStr, err := srv.AcceptStream(ctx)
		if err != nil {
			srvDone <- err
			return
		}
		got, err := io.ReadAll(srvStr)
		if err != nil {
			srvDone <- err
			return
		}
		if string(got) != "u-layer" {
			srvDone <- errors.New("the stream data did not survive the spec-driven connection")
			return
		}
		if _, err := srvStr.Write(make([]byte, payload)); err != nil {
			srvDone <- err
			return
		}
		srvDone <- srvStr.Close()
	}()

	back, err := io.ReadAll(str)
	require.NoError(t, err, "reading %d bytes back failed: quic-go policed a flow-control limit the ClientHello never advertised", payload)
	require.Len(t, back, payload)
	require.NoError(t, <-srvDone)
}
