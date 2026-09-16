package quic

// [SIGHTGLASS U-LAYER] Tests for the spec-driven packer's ENTRY CONDITION (u_packet_packer.go).
//
// The wire tests in u_transport_test.go drive a real dial, so they only ever reach the packer in the
// state a real dial produces: "there is Initial CRYPTO to send and the connection wants to send it".
// The condition this file guards is the other one — the connection asking for an ACK-ONLY packet
// while Initial CRYPTO is still pending, which happens when the congestion controller will not let
// anything ack-eliciting out. No black-box dial can be steered into that state on demand, so the
// packer is driven directly here, through upstream's own mock harness (newTestPacketPacker), and
// through the method the connection actually calls: uPacketPacker.PackCoalescedPacket.

import (
	"testing"

	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/monotime"
	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/protocol"
	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func uTestFrameBuilder() *QUICRandomFrames {
	return &QUICRandomFrames{MinPING: 1, MaxPING: 3, MinCRYPTO: 3, MaxCRYPTO: 8, MinPADDING: 2, MaxPADDING: 6}
}

// TestUPacketPackerLeavesAnAckOnlyInitialToUpstream: `useSpecInitial` refuses the spec path when the
// caller asked for an ACK-only packet, and that `!onlyAck` is load-bearing.
//
// Removing it does not merely re-frame a packet: it makes the packer send the ClientHello in a window
// where the connection decided to send nothing but an ACK — an ack-eliciting, full-size datagram that
// the congestion controller refused, at a moment the browser being parroted would have sent 30-odd
// bytes. The spec layout is applied to a packet upstream would never have filled.
func TestUPacketPackerLeavesAnAckOnlyInitialToUpstream(t *testing.T) {
	const maxPacketSize protocol.ByteCount = 1250
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	up := newUPacketPacker(tp.packer, &QUICSpec{InitialPacketSpec: InitialPacketSpec{FrameBuilder: uTestFrameBuilder()}})

	// There IS Initial CRYPTO waiting, which is what makes this the interesting case: the spec path
	// is one `!onlyAck` away from running. It has to be a real ClientHello — initialCryptoStream
	// reports no data until it has parsed one, because it splits the hello itself.
	clientHello := getClientHello(t, "u-layer.invalid")
	tp.initialStream.Write(clientHello)

	ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).AnyTimes()
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42)).AnyTimes()
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil).AnyTimes()
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), gomock.Any()).Return(ack).AnyTimes()

	p, err := up.PackCoalescedPacket(true, maxPacketSize, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, p, "the packer produced nothing for an ACK-only Initial although an ACK was available")
	require.Len(t, p.longHdrPackets, 1)
	require.Equal(t, ack, p.longHdrPackets[0].ack)
	require.Emptyf(t, p.longHdrPackets[0].frames,
		"the ACK-only Initial carries %d frame(s): the connection asked for an ACK and the spec layout sent the pending ClientHello instead, in a window the congestion controller had closed",
		len(p.longHdrPackets[0].frames))
}

// TestUPacketPackerUsesTheSpecWhenThereIsCryptoToSend is the positive control for the test above: the
// same packer, the same pending CRYPTO, onlyAck=false — the spec path DOES run, so the assertion
// above is about `onlyAck` and not about a packer that never lays anything out.
func TestUPacketPackerUsesTheSpecWhenThereIsCryptoToSend(t *testing.T) {
	const maxPacketSize protocol.ByteCount = 1250
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	up := newUPacketPacker(tp.packer, &QUICSpec{InitialPacketSpec: InitialPacketSpec{FrameBuilder: uTestFrameBuilder()}})

	tp.initialStream.Write(getClientHello(t, "u-layer.invalid"))
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).AnyTimes()
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42)).AnyTimes()
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil).AnyTimes()
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	p, err := up.PackCoalescedPacket(false, maxPacketSize, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Equalf(t, maxPacketSize, p.buffer.Len(),
		"the spec-laid-out Initial is %d bytes, not the %d the config pins", p.buffer.Len(), maxPacketSize)
	require.NotEmpty(t, p.longHdrPackets[0].frames, "no CRYPTO went out although a whole ClientHello was waiting on the initial stream")
}
