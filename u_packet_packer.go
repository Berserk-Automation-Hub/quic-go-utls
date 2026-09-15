package quic

// [SIGHTGLASS U-LAYER] Spec-driven Initial packet packing.
//
// uPacketPacker is the upstream packetPacker with ONE behavioural change: an Initial packet that
// carries CRYPTO data is emitted as a standalone, exactly-sized datagram whose frames are laid out by
// the spec's QUICFrameBuilder (out-of-order CRYPTO + PING + PADDING) and whose packet-number field is
// the spec's length. Every other packet — ACK-only Initials, Handshake, 0-RTT, 1-RTT, MTU probes,
// CONNECTION_CLOSE — is packed by upstream code, untouched.

import (
	"fmt"

	"github.com/bogdanfinn/quic-go-utls/internal/monotime"
	"github.com/bogdanfinn/quic-go-utls/internal/protocol"
	"github.com/bogdanfinn/quic-go-utls/internal/wire"
)

type uPacketPacker struct {
	*packetPacker

	uSpec *QUICSpec
}

func newUPacketPacker(p *packetPacker, uSpec *QUICSpec) *uPacketPacker {
	return &uPacketPacker{packetPacker: p, uSpec: uSpec}
}

// hasInitialCryptoToSend reports whether the next Initial packet would carry CRYPTO data.
func (p *uPacketPacker) hasInitialCryptoToSend() bool {
	if _, err := p.cryptoSetup.GetInitialSealer(); err != nil {
		return false
	}
	return p.initialStream.HasData() || p.retransmissionQueue.HasData(protocol.EncryptionInitial)
}

func (p *uPacketPacker) useSpecInitial(onlyAck bool) bool {
	return !onlyAck && p.uSpec != nil && p.uSpec.InitialPacketSpec.FrameBuilder != nil && p.hasInitialCryptoToSend()
}

func (p *uPacketPacker) PackCoalescedPacket(onlyAck bool, maxSize protocol.ByteCount, now monotime.Time, v protocol.Version) (*coalescedPacket, error) {
	if !p.useSpecInitial(onlyAck) {
		return p.packetPacker.PackCoalescedPacket(onlyAck, maxSize, now, v)
	}
	return p.packSpecInitialPacket(maxSize, now, false, v)
}

func (p *uPacketPacker) PackPTOProbePacket(encLevel protocol.EncryptionLevel, maxSize protocol.ByteCount, addPingIfEmpty bool, now monotime.Time, v protocol.Version) (*coalescedPacket, error) {
	if encLevel != protocol.EncryptionInitial || !p.useSpecInitial(false) {
		return p.packetPacker.PackPTOProbePacket(encLevel, maxSize, addPingIfEmpty, now, v)
	}
	return p.packSpecInitialPacket(maxSize, now, addPingIfEmpty, v)
}

// packSpecInitialPacket packs one Initial packet, alone in its datagram, of exactly maxSize bytes.
//
// The browser this parrots (Chrome/QUICHE) sends every client Initial as a standalone full-size
// datagram — command-proven from the oracle pcap: every client Initial datagram is 1250 bytes and
// contains a single Initial packet. Coalescing a Handshake packet behind the Initial (which upstream
// quic-go does when handshake keys already exist) cannot happen on this path anyway: the client only
// packs Initial CRYPTO before it has handshake keys.
func (p *uPacketPacker) packSpecInitialPacket(maxSize protocol.ByteCount, now monotime.Time, addPingIfEmpty bool, v protocol.Version) (*coalescedPacket, error) {
	sealer, err := p.cryptoSetup.GetInitialSealer()
	if err != nil {
		return nil, err
	}
	fb := p.uSpec.InitialPacketSpec.FrameBuilder
	reserve := protocol.ByteCount(fb.MaxOverhead())

	hdr, pl := p.maybeGetCryptoPacket(
		maxSize-protocol.ByteCount(sealer.Overhead())-reserve,
		protocol.EncryptionInitial,
		now,
		addPingIfEmpty,
		false,
		v,
	)
	if pl.length == 0 {
		return nil, nil
	}
	// Pin the FIRST Initial's packet-number length. Upstream quic-go never emits a 1-byte packet
	// number (PacketNumberLengthForHeader returns 2 or 4); the browser does. Ground truth from the
	// oracle pcap for the two-packet ClientHello flight: pn=1 pnLen=1 (payload 1215 B) then
	// pn=2 pnLen=2 (payload 1214 B) — so pinning only the first packet reproduces BOTH.
	if n := p.uSpec.InitialPacketSpec.InitPacketNumberLength; n > 0 && uint64(hdr.PacketNumber) == p.uSpec.InitialPacketSpec.InitPacketNumber {
		if n > 4 {
			return nil, fmt.Errorf("quic u-layer: InitPacketNumberLength %d out of range 1..4", n)
		}
		hdr.PacketNumberLen = protocol.PacketNumberLen(n)
	}

	// Split the payload into the CRYPTO stream chunks (laid out by the spec) and everything else
	// (an ACK and/or control frames, which are written verbatim ahead of the spec layout).
	var chunks []CryptoChunk
	var rest payload
	rest.ack = pl.ack
	for _, f := range pl.frames {
		if cf, ok := f.Frame.(*wire.CryptoFrame); ok {
			chunks = append(chunks, CryptoChunk{Offset: uint64(cf.Offset), Data: cf.Data})
			continue
		}
		rest.frames = append(rest.frames, f)
		rest.length += f.Frame.Length(v)
	}
	if rest.ack != nil {
		rest.length += rest.ack.Length(v)
	}
	if len(chunks) == 0 {
		// No CRYPTO after all (e.g. the retransmission queue only had a PING). The payload has
		// already been popped off the streams, so it MUST be packed here — re-entering the packer
		// would drop those frames. Use the upstream framing with upstream Initial padding.
		buffer := getPacketBuffer()
		padding := p.initialPaddingLen(pl.frames, p.longHeaderPacketLength(hdr, pl, v)+protocol.ByteCount(sealer.Overhead()), maxSize)
		cont, err := p.appendLongHeaderPacket(buffer, hdr, pl, padding, protocol.EncryptionInitial, sealer, v)
		if err != nil {
			return nil, err
		}
		return &coalescedPacket{buffer: buffer, longHdrPackets: []*longHeaderPacket{cont}}, nil
	}

	// The whole datagram is exactly maxSize: header + payload + AEAD tag.
	budget := maxSize - hdr.GetLength(v) - protocol.ByteCount(sealer.Overhead()) - rest.length
	if budget <= 0 {
		return nil, fmt.Errorf("quic u-layer: no room for CRYPTO frames in a %d B Initial packet", maxSize)
	}
	specFrames, err := fb.Build(chunks, int(budget))
	if err != nil {
		return nil, err
	}

	buffer := getPacketBuffer()
	packet := &coalescedPacket{buffer: buffer, longHdrPackets: make([]*longHeaderPacket, 0, 1)}
	hdr.Length = protocol.ByteCount(hdr.PacketNumberLen) + protocol.ByteCount(sealer.Overhead()) + rest.length + protocol.ByteCount(len(specFrames))

	startLen := len(buffer.Data)
	raw := buffer.Data[startLen:]
	raw, err = hdr.Append(raw, v)
	if err != nil {
		return nil, err
	}
	payloadOffset := protocol.ByteCount(len(raw))
	if rest.length > 0 {
		raw, err = p.appendPacketPayload(raw, rest, 0, v)
		if err != nil {
			return nil, err
		}
	}
	raw = append(raw, specFrames...)
	raw = p.encryptPacket(raw, sealer, hdr.PacketNumber, payloadOffset, protocol.ByteCount(hdr.PacketNumberLen))
	buffer.Data = buffer.Data[:len(buffer.Data)+len(raw)]

	if got, want := protocol.ByteCount(len(raw)), maxSize; got != want {
		return nil, fmt.Errorf("quic u-layer BUG: Initial packet is %d B, want exactly %d B", got, want)
	}
	if pn := p.pnManager.PopPacketNumber(protocol.EncryptionInitial); pn != hdr.PacketNumber {
		return nil, fmt.Errorf("quic u-layer BUG: peeked and popped packet numbers differ: %d != %d", pn, hdr.PacketNumber)
	}
	packet.longHdrPackets = append(packet.longHdrPackets, &longHeaderPacket{
		header:       hdr,
		ack:          pl.ack,
		frames:       pl.frames,
		streamFrames: pl.streamFrames,
		length:       protocol.ByteCount(len(raw)),
	})
	return packet, nil
}
