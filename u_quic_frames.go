package quic

// [SIGHTGLASS U-LAYER] Initial-packet frame layout.
//
// A QUICFrameBuilder decides how one Initial packet's slice(s) of the CRYPTO stream are laid out on
// the wire: into how many CRYPTO frames they are split, in what order, and how PING/PADDING frames
// are interleaved. That layout is passively observable — Initial packets are decryptable by anyone
// who sees the Destination Connection ID (RFC 9001 §5.2) — so it is part of the client fingerprint.
//
// GROUND TRUTH (command-proven, HR-7) — genuine Chrome 152.0.7977.83, decrypted from
// reversing/oracle_verify/fingerprints/_login/quic_login.pcap with the quicfp decoder:
//
//	QUICFP_FRAMES=1 go run . fingerprints/_login/quic_login.pcap
//	  [pkt] dcid=1c4ada467132bc26 scidlen=0 pn=1 pnLen=1 tokenLen=0 pktBytes=1250
//	  [frames] payload=1215B layout=CRYPTO(off=1418,len=168) PINGx1 PADDINGx1 CRYPTO(off=1161,len=46)
//	    CRYPTO(off=1109,len=36) PADDINGx115 CRYPTO(off=1586,len=372) CRYPTO(off=0,len=72) PADDINGx17
//	    CRYPTO(off=1958,len=7) ... PADDINGx3
//
// i.e. EVERY client Initial datagram is exactly 1250 bytes, with DCID 8 / SCID 0 / token 0 and a
// first packet number of 1 in a 1-byte packet-number field, and every Initial that carries crypto is
// "chaos protected" (QUICHE's QuicChaosProtector): out-of-order CRYPTO frames from several stream
// ranges, with PING and PADDING frames interleaved, filling the datagram exactly.
//
// QUICRandomFrames reproduces that OBSERVABLE SHAPE. RESIDUAL, NOT claimed as byte parity (HR-7):
// QUICHE's exact chaos sequencing (how it picks split points and which stream ranges land in which
// packet) is not reproduced. Both stacks randomize per connection, so only the shape is comparable.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand"

	"github.com/bogdanfinn/quic-go-utls/quicvarint"
)

// CryptoChunk is a contiguous run of CRYPTO-stream bytes destined for one Initial packet, at its
// absolute stream offset.
type CryptoChunk struct {
	Offset uint64
	Data   []byte
}

// QUICFrameBuilder lays out one Initial packet's frames.
type QUICFrameBuilder interface {
	// MaxOverhead is the largest number of bytes the builder may add on top of the raw CRYPTO stream
	// bytes it is given (CRYPTO frame headers + PING frames). The packer reserves this much when it
	// asks quic-go for crypto data, so the built payload always fits the packet.
	MaxOverhead() int

	// Build lays out chunks into EXACTLY budget bytes of QUIC frames, padding with PADDING frames.
	// It must loud-fail if the data plus its minimum framing cannot fit in budget.
	Build(chunks []CryptoChunk, budget int) ([]byte, error)
}

// maxCryptoFrameHeader bounds one CRYPTO frame header for the reserve calculation: type(1) +
// offset varint(<=4) + length varint(<=4). Four-byte varints cover offsets/lengths up to 2^30, i.e.
// a 1 GB crypto stream; a ClientHello is a few kilobytes. The builder itself accounts for every
// frame EXACTLY (cryptoFrameLen), so this is only the packer's safety margin.
const maxCryptoFrameHeader = 9

// appendCryptoFrame appends one CRYPTO frame (type 0x06) carrying data at an absolute stream offset.
func appendCryptoFrame(b []byte, offset uint64, data []byte) []byte {
	b = append(b, 0x06)
	b = quicvarint.Append(b, offset)
	b = quicvarint.Append(b, uint64(len(data)))
	return append(b, data...)
}

func cryptoFrameLen(offset uint64, dataLen int) int {
	return 1 + quicvarint.Len(offset) + quicvarint.Len(uint64(dataLen)) + dataLen
}

// randUint64 returns a crypto-random value in [min, max]. It loud-fails on a broken RNG.
func randUint64(min, max uint64) (uint64, error) {
	if max < min {
		return 0, fmt.Errorf("quic u-layer: bad random range [%d,%d]", min, max)
	}
	if max == min {
		return min, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return 0, fmt.Errorf("quic u-layer: crypto/rand: %w", err)
	}
	return min + n.Uint64(), nil
}

// QUICRandomFrames builds a randomized, browser-shaped Initial payload: the packet's CRYPTO stream
// slices are split into up to MaxCRYPTO frames, [MinPING,MaxPING] PING frames and
// [MinPADDING,MaxPADDING] PADDING runs are added, and the whole set is shuffled. The result is always
// exactly the budget the packer asks for, so the UDP datagram size is constant.
type QUICRandomFrames struct {
	MinPING    uint8
	MaxPING    uint8
	MinCRYPTO  uint8
	MaxCRYPTO  uint8
	MinPADDING uint8
	MaxPADDING uint8
}

func (q *QUICRandomFrames) MaxOverhead() int {
	return int(q.MaxCRYPTO)*maxCryptoFrameHeader + int(q.MaxPING)
}

func (q *QUICRandomFrames) validate() error {
	if q.MinCRYPTO < 1 {
		return errors.New("quic u-layer: MinCRYPTO must be >= 1")
	}
	if q.MinPADDING < 1 {
		return errors.New("quic u-layer: MinPADDING must be >= 1")
	}
	if q.MinCRYPTO > q.MaxCRYPTO || q.MinPING > q.MaxPING || q.MinPADDING > q.MaxPADDING {
		return errors.New("quic u-layer: QUICRandomFrames has a Min bound above its Max bound")
	}
	return nil
}

func (q *QUICRandomFrames) Build(chunks []CryptoChunk, budget int) ([]byte, error) {
	if err := q.validate(); err != nil {
		return nil, err
	}
	if len(chunks) == 0 {
		return nil, errors.New("quic u-layer: Build called with no CRYPTO chunks")
	}

	// (1) Seed one piece per chunk. This is the minimum framing; if it does not fit, the packer
	// reserved too little and we loud-fail (HR-6) rather than emit an off-size datagram.
	pieces := make([]CryptoChunk, 0, int(q.MaxCRYPTO)+len(chunks))
	used := 0
	for _, c := range chunks {
		if len(c.Data) == 0 {
			continue
		}
		pieces = append(pieces, c)
		used += cryptoFrameLen(c.Offset, len(c.Data))
	}
	if len(pieces) == 0 {
		return nil, errors.New("quic u-layer: Build called with only empty CRYPTO chunks")
	}
	if used > budget {
		return nil, fmt.Errorf("quic u-layer: %d CRYPTO frame(s) need %d B but the Initial packet budget is %d B",
			len(pieces), used, budget)
	}

	// (2) Split pieces further, up to MaxCRYPTO frames, while the extra frame headers still fit.
	target, err := randUint64(uint64(q.MinCRYPTO), uint64(q.MaxCRYPTO))
	if err != nil {
		return nil, err
	}
	for uint64(len(pieces)) < target {
		// Only pieces of >= 2 bytes can be split.
		var splittable []int
		for i, p := range pieces {
			if len(p.Data) >= 2 {
				splittable = append(splittable, i)
			}
		}
		if len(splittable) == 0 {
			break
		}
		sel, err := randUint64(0, uint64(len(splittable)-1))
		if err != nil {
			return nil, err
		}
		i := splittable[sel]
		at, err := randUint64(1, uint64(len(pieces[i].Data)-1))
		if err != nil {
			return nil, err
		}
		left := CryptoChunk{Offset: pieces[i].Offset, Data: pieces[i].Data[:at]}
		right := CryptoChunk{Offset: pieces[i].Offset + at, Data: pieces[i].Data[at:]}
		delta := cryptoFrameLen(left.Offset, len(left.Data)) + cryptoFrameLen(right.Offset, len(right.Data)) -
			cryptoFrameLen(pieces[i].Offset, len(pieces[i].Data))
		if used+delta > budget {
			break
		}
		used += delta
		pieces[i] = left
		pieces = append(pieces, right)
	}

	// (3) PING frames.
	frames := make([][]byte, 0, len(pieces)+int(q.MaxPING)+int(q.MaxPADDING))
	for _, p := range pieces {
		frames = append(frames, appendCryptoFrame(nil, p.Offset, p.Data))
	}
	numPING, err := randUint64(uint64(q.MinPING), uint64(q.MaxPING))
	if err != nil {
		return nil, err
	}
	if int(numPING) > budget-used {
		numPING = uint64(max(0, budget-used))
	}
	for i := uint64(0); i < numPING; i++ {
		frames = append(frames, []byte{0x01})
		used++
	}

	// (4) PADDING runs fill the packet to exactly the budget.
	if pad := budget - used; pad > 0 {
		numPADDING, err := randUint64(uint64(q.MinPADDING), uint64(q.MaxPADDING))
		if err != nil {
			return nil, err
		}
		if numPADDING > uint64(pad) {
			numPADDING = uint64(pad)
		}
		rem := pad
		for i := uint64(0); i+1 < numPADDING; i++ {
			maxLen := rem - int(numPADDING-i-1)
			if maxLen < 1 {
				break
			}
			n, err := randUint64(1, uint64(maxLen))
			if err != nil {
				return nil, err
			}
			frames = append(frames, make([]byte, n))
			rem -= int(n)
		}
		frames = append(frames, make([]byte, rem))
	}

	// (5) Shuffle and concatenate. CRYPTO frames carry absolute offsets, so any order is valid.
	mrand.Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })
	out := make([]byte, 0, budget)
	for _, f := range frames {
		out = append(out, f...)
	}
	if len(out) != budget {
		return nil, fmt.Errorf("quic u-layer BUG: built %d B, want exactly %d B", len(out), budget)
	}
	return out, nil
}
