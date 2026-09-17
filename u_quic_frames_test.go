package quic

// [SIGHTGLASS U-LAYER] Tests for the Initial-packet frame layout builder (u_quic_frames.go).
//
// These are the fork's OWN tests for code the fork adds. They assert the builder's contract, which
// is what the shipped path depends on: the payload is EXACTLY the budget the packer asked for (or
// the datagram size stops being constant and the size itself becomes the tell), the CRYPTO bytes
// survive the split/shuffle intact (or the handshake breaks), the layout actually varies between
// connections, and every failure is loud rather than silent (HR-6).

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Berserk-Automation-Hub/quic-go-utls/quicvarint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parsedFrames is what a built Initial payload decodes to.
type parsedFrames struct {
	crypto  []CryptoChunk
	pings   int
	padding int // total PADDING bytes
	runs    int // number of PADDING runs
}

// parseInitialPayload decodes the frame types the builder is allowed to emit. It rejects anything
// else, so a builder that started emitting some other frame type would be caught rather than
// counted as padding.
func parseInitialPayload(t *testing.T, b []byte) parsedFrames {
	t.Helper()
	var out parsedFrames
	inPadRun := false
	for i := 0; i < len(b); {
		switch b[i] {
		case 0x00: // PADDING
			if !inPadRun {
				out.runs++
				inPadRun = true
			}
			out.padding++
			i++
			continue
		case 0x01: // PING
			out.pings++
			i++
		case 0x06: // CRYPTO
			r := bytes.NewReader(b[i+1:])
			off, err := quicvarint.Read(r)
			require.NoError(t, err)
			l, err := quicvarint.Read(r)
			require.NoError(t, err)
			hdr := 1 + quicvarint.Len(off) + quicvarint.Len(l)
			require.LessOrEqual(t, i+hdr+int(l), len(b), "CRYPTO frame runs off the end of the payload")
			out.crypto = append(out.crypto, CryptoChunk{Offset: off, Data: b[i+hdr : i+hdr+int(l)]})
			i += hdr + int(l)
		default:
			t.Fatalf("unexpected frame type 0x%02x at offset %d in a builder payload", b[i], i)
		}
		inPadRun = false
	}
	return out
}

// requireCryptoStreamEquals reassembles the built CRYPTO frames into one stream and checks it is
// byte-for-byte the stream that was handed to Build - nothing lost, nothing invented, nothing
// duplicated with different bytes.
func requireCryptoStreamEquals(t *testing.T, got []CryptoChunk, want []CryptoChunk) {
	t.Helper()
	gotStream := map[uint64]byte{}
	for _, c := range got {
		for i, b := range c.Data {
			off := c.Offset + uint64(i)
			if prev, ok := gotStream[off]; ok {
				require.Equalf(t, prev, b, "crypto stream offset %d written twice with different bytes", off)
			}
			gotStream[off] = b
		}
	}
	wantStream := map[uint64]byte{}
	for _, c := range want {
		for i, b := range c.Data {
			wantStream[c.Offset+uint64(i)] = b
		}
	}
	require.Equal(t, wantStream, gotStream,
		"the CRYPTO stream the builder emitted is not the one it was given: the ClientHello would be corrupt on the wire")
}

func testChunks() []CryptoChunk {
	data := make([]byte, 600)
	for i := range data {
		data[i] = byte(i % 251)
	}
	return []CryptoChunk{{Offset: 0, Data: data[:400]}, {Offset: 1000, Data: data[400:]}}
}

func chromeShapedBuilder() *QUICRandomFrames {
	// NOT a captured browser value (HR-1): these bounds only have to produce a layout with several
	// CRYPTO frames, some PINGs and several PADDING runs so the builder's contract is exercised.
	return &QUICRandomFrames{MinPING: 1, MaxPING: 3, MinCRYPTO: 3, MaxCRYPTO: 8, MinPADDING: 2, MaxPADDING: 6}
}

// TestUQUICRandomFramesFillsTheBudgetExactly is the datagram-size guard: every Initial this fork
// builds is padded to EXACTLY the budget, because a browser's Initial datagram size is constant and
// a varying one is itself a fingerprint.
func TestUQUICRandomFramesFillsTheBudgetExactly(t *testing.T) {
	q := chromeShapedBuilder()
	chunks := testChunks()
	for _, budget := range []int{700, 900, 1215, 1400} {
		for i := 0; i < 20; i++ {
			out, err := q.Build(chunks, budget)
			require.NoError(t, err)
			require.Equalf(t, budget, len(out),
				"built %d B for a %d B budget: the UDP datagram size would vary between packets", len(out), budget)
		}
	}
}

// TestUQUICRandomFramesPreservesTheCryptoStream is the correctness guard: splitting and shuffling
// must not lose, duplicate or reorder a single byte of the ClientHello.
func TestUQUICRandomFramesPreservesTheCryptoStream(t *testing.T) {
	q := chromeShapedBuilder()
	chunks := testChunks()
	for i := 0; i < 50; i++ {
		out, err := q.Build(chunks, 1215)
		require.NoError(t, err)
		pf := parseInitialPayload(t, out)
		requireCryptoStreamEquals(t, pf.crypto, chunks)
	}
}

// TestUQUICRandomFramesEmitsTheChaosShape asserts the layout has the three ingredients the capture
// shows: MORE CRYPTO frames than the chunks handed in (i.e. the stream was split), PING frames, and
// several separate PADDING runs.
func TestUQUICRandomFramesEmitsTheChaosShape(t *testing.T) {
	q := chromeShapedBuilder()
	chunks := testChunks()
	var sawSplit, sawMultiRun bool
	for i := 0; i < 50; i++ {
		out, err := q.Build(chunks, 1215)
		require.NoError(t, err)
		pf := parseInitialPayload(t, out)
		require.GreaterOrEqualf(t, pf.pings, int(q.MinPING), "payload carries %d PING frames, want at least %d", pf.pings, q.MinPING)
		require.LessOrEqual(t, pf.pings, int(q.MaxPING))
		require.Positive(t, pf.padding, "payload carries no PADDING at all")
		if len(pf.crypto) > len(chunks) {
			sawSplit = true
		}
		if pf.runs > 1 {
			sawMultiRun = true
		}
	}
	require.True(t, sawSplit, "the builder never split a CRYPTO chunk in 50 attempts: the layout is not chaos-shaped")
	require.True(t, sawMultiRun, "the builder never emitted more than one PADDING run in 50 attempts")
}

// TestUQUICRandomFramesOrderVariesBetweenConnections is the anti-determinism guard. The frame ORDER
// is the fingerprint-bearing property this file exists to randomise; if two builds of identical
// input ever came out byte-identical every time, the layout would be a constant tell.
//
// It is also the guard that makes the crypto/rand shuffle ablatable: seeding math/rand's global
// source makes a math/rand shuffle produce the same permutation on every run of the process.
func TestUQUICRandomFramesOrderVariesBetweenConnections(t *testing.T) {
	q := chromeShapedBuilder()
	chunks := testChunks()
	first, err := q.Build(chunks, 1215)
	require.NoError(t, err)
	for i := 0; i < 50; i++ {
		out, err := q.Build(chunks, 1215)
		require.NoError(t, err)
		if !bytes.Equal(first, out) {
			return
		}
	}
	t.Fatal("51 builds of identical input produced byte-identical payloads: the Initial frame layout is deterministic, which is a stronger fingerprint than the layout it is meant to randomise")
}

// TestUQUICRandomFramesLoudFailsRatherThanEmitAWrongSizedPacket: HR-6. When the budget cannot hold
// the crypto bytes plus their minimum framing, the builder must return an error, never a short or
// truncated payload.
func TestUQUICRandomFramesLoudFailsRatherThanEmitAWrongSizedPacket(t *testing.T) {
	q := chromeShapedBuilder()
	chunks := testChunks()
	out, err := q.Build(chunks, 100)
	require.Error(t, err)
	require.Nil(t, out)
	assert.Contains(t, err.Error(), "Initial packet budget is 100 B")

	_, err = q.Build(nil, 1215)
	require.EqualError(t, err, "quic u-layer: Build called with no CRYPTO chunks")

	_, err = q.Build([]CryptoChunk{{Offset: 0, Data: nil}}, 1215)
	require.EqualError(t, err, "quic u-layer: Build called with only empty CRYPTO chunks")
}

// TestUQUICRandomFramesRejectsAnImpossibleShape: a builder whose bounds cannot produce the shape it
// describes must say so instead of quietly producing a different one.
func TestUQUICRandomFramesRejectsAnImpossibleShape(t *testing.T) {
	chunks := testChunks()
	for _, tc := range []struct {
		name string
		q    QUICRandomFrames
		want string
	}{
		{"no CRYPTO frame", QUICRandomFrames{MinCRYPTO: 0, MaxCRYPTO: 4, MinPADDING: 1, MaxPADDING: 2}, "quic u-layer: MinCRYPTO must be >= 1"},
		{"no PADDING run", QUICRandomFrames{MinCRYPTO: 1, MaxCRYPTO: 4, MinPADDING: 0, MaxPADDING: 2}, "quic u-layer: MinPADDING must be >= 1"},
		{"inverted CRYPTO bounds", QUICRandomFrames{MinCRYPTO: 5, MaxCRYPTO: 4, MinPADDING: 1, MaxPADDING: 2}, "quic u-layer: QUICRandomFrames has a Min bound above its Max bound"},
		{"inverted PING bounds", QUICRandomFrames{MinPING: 3, MaxPING: 1, MinCRYPTO: 1, MaxCRYPTO: 4, MinPADDING: 1, MaxPADDING: 2}, "quic u-layer: QUICRandomFrames has a Min bound above its Max bound"},
		{"inverted PADDING bounds", QUICRandomFrames{MinCRYPTO: 1, MaxCRYPTO: 4, MinPADDING: 3, MaxPADDING: 2}, "quic u-layer: QUICRandomFrames has a Min bound above its Max bound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.q.Build(chunks, 1215)
			require.EqualError(t, err, tc.want)
		})
	}
}

// TestUQUICRandomFramesMaxOverheadCoversWhatBuildAdds: the packer RESERVES MaxOverhead() before it
// asks quic-go for crypto data. If the reserve were smaller than what Build actually adds, the
// packet would overflow its budget and packSpecInitialPacket would loud-fail on every dial.
func TestUQUICRandomFramesMaxOverheadCoversWhatBuildAdds(t *testing.T) {
	q := chromeShapedBuilder()
	chunks := testChunks()
	raw := 0
	for _, c := range chunks {
		raw += len(c.Data)
	}
	for i := 0; i < 50; i++ {
		out, err := q.Build(chunks, raw+q.MaxOverhead())
		require.NoErrorf(t, err, "Build could not fit the chunks into raw+MaxOverhead() = %d B", raw+q.MaxOverhead())
		pf := parseInitialPayload(t, out)
		requireCryptoStreamEquals(t, pf.crypto, chunks)
	}
}

// TestUQUICRandomFramesShufflesTheFrameOrder is the guard for step (5) of Build: the Fisher-Yates
// shuffle. Without it the frames come out in construction order — every CRYPTO piece first (lowest
// stream offset leading), then the PINGs, then the PADDING — which is a fixed, recognisable layout
// no matter how the LENGTHS are randomised, and the opposite of the interleaved shape this file
// exists to reproduce.
//
// It measures the POSITION of the lowest-offset CRYPTO frame among the frames of the payload. In
// construction order that position is always 0.
func TestUQUICRandomFramesShufflesTheFrameOrder(t *testing.T) {
	q := chromeShapedBuilder()
	chunks := testChunks()
	positions := map[int]int{}
	trailingPadOnly := 0
	const n = 60
	for i := 0; i < n; i++ {
		out, err := q.Build(chunks, 1215)
		require.NoError(t, err)
		frames := splitFrames(t, out)
		lowest, lowestAt := ^uint64(0), -1
		lastNonPad := -1
		for j, f := range frames {
			if f.kind == frameCrypto && f.offset < lowest {
				lowest, lowestAt = f.offset, j
			}
			if f.kind != framePadding {
				lastNonPad = j
			}
		}
		require.GreaterOrEqual(t, lowestAt, 0)
		positions[lowestAt]++
		// Construction order also puts every PADDING run after every other frame.
		firstPad := -1
		for j, f := range frames {
			if f.kind == framePadding {
				firstPad = j
				break
			}
		}
		if firstPad > lastNonPad {
			trailingPadOnly++
		}
	}
	require.Greaterf(t, len(positions), 1,
		"in %d builds the lowest-offset CRYPTO frame was always at position %v: the frame order is not shuffled, so the Initial layout is a constant tell", n, positions)
	require.Lessf(t, positions[0], n,
		"the lowest-offset CRYPTO frame led the payload in all %d builds: the frames are in construction order", n)
	require.Lessf(t, trailingPadOnly, n,
		"all %d builds put every PADDING run after every other frame: the frames are in construction order", n)
}

type frameKind int

const (
	framePadding frameKind = iota
	framePing
	frameCrypto
)

type builtFrame struct {
	kind   frameKind
	offset uint64
}

// splitFrames decodes a built payload into one entry per frame, collapsing each PADDING run.
func splitFrames(t *testing.T, b []byte) []builtFrame {
	t.Helper()
	var out []builtFrame
	inPad := false
	for i := 0; i < len(b); {
		switch b[i] {
		case 0x00:
			if !inPad {
				out = append(out, builtFrame{kind: framePadding})
				inPad = true
			}
			i++
			continue
		case 0x01:
			out = append(out, builtFrame{kind: framePing})
			i++
		case 0x06:
			r := bytes.NewReader(b[i+1:])
			off, err := quicvarint.Read(r)
			require.NoError(t, err)
			l, err := quicvarint.Read(r)
			require.NoError(t, err)
			out = append(out, builtFrame{kind: frameCrypto, offset: off})
			i += 1 + quicvarint.Len(off) + quicvarint.Len(l) + int(l)
		default:
			t.Fatalf("unexpected frame type 0x%02x at offset %d", b[i], i)
		}
		inPad = false
	}
	return out
}

// TestUQUICRandomFramesHonoursTheDeclaredFrameBounds is the guard for the SIX spec fields the
// builder reads and nothing else in this fork asserted: MinCRYPTO/MaxCRYPTO, MinPING/MaxPING and
// MinPADDING/MaxPADDING.
//
// WHY IT EXISTS. Every other test here drives ONE builder value (1,3,3,8,2,6), so a builder that
// stopped reading the spec and used CONSTANTS inside that value's range stayed green everywhere.
// Measured, on this machine, one factor at a time:
//
//	randUint64(uint64(q.MinCRYPTO), uint64(q.MaxCRYPTO)) -> randUint64(3, 3)
//	randUint64(uint64(q.MinPADDING), uint64(q.MaxPADDING)) -> randUint64(2, 2)
//	  => ok  github.com/Berserk-Automation-Hub/quic-go-utls  17.962s   (the WHOLE package)
//
// Under that mutation every Initial carries exactly 3 CRYPTO frames and 2 PADDING runs whatever the
// profile declares — chrome-152.json declares 4..17 and 3..8 — i.e. the chaos layout collapses to a
// CONSTANT shape, which is precisely the tell this file exists to remove. That is the same defect
// class as E5/E6: a profile value quietly stops being read.
//
// WHY A RANGE ASSERTION IS NOT ENOUGH. A pair of Min<=x<=Max assertions is satisfied by every
// constant INSIDE the declared range, so it catches a builder that ignores the spec entirely and
// misses one that reads only HALF of it. Five single-factor mutations, each applied ALONE to
// u_quic_frames.go, have defeated earlier versions of this test:
//
//	randUint64(uint64(q.MinPADDING), uint64(q.MaxPADDING)) -> randUint64(uint64(q.MaxPADDING), uint64(q.MaxPADDING))  // MinPADDING unread
//	randUint64(uint64(q.MinPADDING), uint64(q.MaxPADDING)) -> randUint64(uint64(q.MinPADDING), uint64(q.MinPADDING))  // MaxPADDING unread
//	randUint64(uint64(q.MinPING), uint64(q.MaxPING))       -> randUint64(uint64(q.MinPING), uint64(q.MinPING))        // MaxPING unread
//	lo, hi := uint64(q.MinPADDING), uint64(q.MaxPADDING); if hi > lo+1 { lo, hi = lo+1, hi-1 }          // NEITHER PADDING end read
//	mid := (uint64(q.MinPADDING) + uint64(q.MaxPADDING)) / 2; randUint64(mid, mid)                      // PADDING a constant mid-range
//
// The last two are the subtle ones: the count still VARIES build to build (PADDING runs merge, see
// below), so every "the distribution is not a single value" test passes, and neither declared
// endpoint ever reaches the wire.
//
// WHAT REPLACED IT, per frame type and in the strongest form that type admits HERE:
//
//   - CRYPTO frames carry their own length, so they are counted exactly. len(cryptoCounts) > 1 was
//     already immune to a pin; the exact-endpoint form is asserted on the wire (u_transport_test.go).
//   - PING frames never merge (one 0x01 byte each), so the count is EXACT: across n builds the
//     smallest must be exactly MinPING and the largest exactly MaxPING. Every pin, sub-range and
//     mid-pin above fails one of those two equalities with probability 1.
//   - PADDING runs MERGE. The builder emits numPADDING separate PADDING frames and shuffles them in
//     among the CRYPTO and PING frames; two that land side by side read back as ONE run, because a
//     PADDING frame is a single zero byte and a reader cannot tell four of them in one frame from
//     four one-byte frames. So runs <= frames emitted, always, and the exact form is only available
//     when the SEPARATORS so outnumber the PADDING frames that an un-merged build is routine.
//
// THE THIRD BOUND SET EXISTS FOR EXACTLY THAT. With few separators (set 2 below: 4..7 PINGs and
// 6..12 CRYPTO frames against up to 9 PADDING frames) the ceiling is nearly unreachable and only the
// weak distribution bounds are available. Set 3 inverts the ratio — 18..22 PINGs and 14..16 CRYPTO
// frames against 2..4 PADDING frames — and there MaxPADDING runs un-merged is routine, so the
// ceiling is asserted as an EQUALITY, which is what kills the sub-range and the mid-pin.
//
// Measured on this machine with the builder in this tree, n=120 builds per trial, the mutations
// emulated exactly (a pin at k is the degenerate range k..k, which is the same draw the mutated
// randUint64 makes):
//
//	SET 2  CRYPTO 6..12  PING 4..7  PADDING 4..9      60 trials
//	                       max PADDING runs in a trial   builds with runs <= MinPADDING
//	  real builder         7..9  (reached 9 in 8/60)     43..69
//	  pinned at MaxPADDING 8..9                           4..21
//	  pinned at MinPADDING 4  (every trial)             120
//	  mid-pin (6)          6  (every trial)              45..70
//	  sub-range (5..8)     7..8                          36..64
//
//	SET 3  CRYPTO 14..16  PING 18..22  PADDING 2..4     200 trials
//	                       max PADDING runs in a trial   builds with runs <= MinPADDING
//	  real builder         4  in 200/200 trials          35..60
//	  pinned at MaxPADDING 4  in 200/200 trials           0..8
//	  pinned at MinPADDING 2  (every trial)             120
//	  mid-pin / sub-range  3  (every trial)               9..25
//
// so on set 2 the at-or-below count separates the MaxPADDING pin (43 against 21, thresholded at 30,
// ~4.7 sigma either side) and NOTHING separates the mid-pin or the sub-range — their populations sit
// on top of the real one. On set 3 "maxRuns == MaxPADDING" separates the MinPADDING pin, the mid-pin
// and the sub-range with no overlap at all (4 against 2, 3, 3), and the at-or-below count separates
// the MaxPADDING pin (35 against 8, thresholded at 20, ~5 sigma either side). Every histogram is
// logged on every run, so a margin that starts to erode is visible in the test output rather than
// only when it flakes.
//
// NOTE ON SET 2's BOUNDS. They are MinPADDING 4, MaxPADDING 9 — the values this test shipped with
// before set 3 existed. A previous round widened them to 2..9, which silently weakened the absolute
// assertion "some build carries at least 4 runs" into "some build carries more than 2"; set 3 now
// carries the strong assertion, so set 2 is back to its original, tighter bounds.
//
// NO CONSTANT CAN SATISFY ALL THREE SETS even ignoring the distribution assertions: set 1 declares
// PADDING 1..1 and set 2 declares 4..9, PING 1..1 against 4..7, CRYPTO 2..2 against 6..12.
func TestUQUICRandomFramesHonoursTheDeclaredFrameBounds(t *testing.T) {
	for _, tc := range []struct {
		q QUICRandomFrames
		// minBuildsAtOrBelowMinPADDING: how many of the n builds must carry at most MinPADDING
		// PADDING runs. This is what a builder pinned at MaxPADDING cannot produce. Measured per
		// set — see the two tables above.
		minBuildsAtOrBelowMinPADDING int
		// exactPADDINGCeiling: on this set the separators so outnumber the PADDING frames that a
		// build whose runs do not merge at all is routine, so MaxPADDING runs must be REACHED, not
		// merely not exceeded. That equality is what a mid-range constant cannot satisfy.
		exactPADDINGCeiling bool
	}{
		{q: QUICRandomFrames{MinPING: 1, MaxPING: 1, MinCRYPTO: 2, MaxCRYPTO: 2, MinPADDING: 1, MaxPADDING: 1}},
		{q: QUICRandomFrames{MinPING: 4, MaxPING: 7, MinCRYPTO: 6, MaxCRYPTO: 12, MinPADDING: 4, MaxPADDING: 9}, minBuildsAtOrBelowMinPADDING: 30},
		{q: QUICRandomFrames{MinPING: 18, MaxPING: 22, MinCRYPTO: 14, MaxCRYPTO: 16, MinPADDING: 2, MaxPADDING: 4}, minBuildsAtOrBelowMinPADDING: 20, exactPADDINGCeiling: true},
	} {
		q := tc.q
		t.Run(fmt.Sprintf("CRYPTO %d..%d PING %d..%d PADDING %d..%d", q.MinCRYPTO, q.MaxCRYPTO, q.MinPING, q.MaxPING, q.MinPADDING, q.MaxPADDING), func(t *testing.T) {
			chunks := testChunks()
			require.LessOrEqualf(t, len(chunks), int(q.MinCRYPTO),
				"this bound set asks for fewer CRYPTO frames (%d) than the %d chunks handed in; the builder cannot merge chunks, so the lower bound below would be unsatisfiable by construction rather than by the spec",
				q.MinCRYPTO, len(chunks))

			const n = 120
			cryptoCounts := map[int]int{}
			pingCounts := map[int]int{}
			runCounts := map[int]int{}
			maxRuns, minPings, maxPings, atOrBelowMinPADDING := 0, -1, -1, 0
			for i := 0; i < n; i++ {
				out, err := q.Build(chunks, 1215)
				require.NoError(t, err)
				pf := parseInitialPayload(t, out)

				require.GreaterOrEqualf(t, len(pf.crypto), int(q.MinCRYPTO),
					"the payload carries %d CRYPTO frame(s) and the spec declares at least %d: the CRYPTO split is not being driven by the spec's bounds, so every Initial this profile sends has a layout the document never declared",
					len(pf.crypto), q.MinCRYPTO)
				require.LessOrEqualf(t, len(pf.crypto), int(q.MaxCRYPTO),
					"the payload carries %d CRYPTO frame(s) and the spec declares at most %d: the CRYPTO split is not being driven by the spec's bounds",
					len(pf.crypto), q.MaxCRYPTO)
				require.GreaterOrEqualf(t, pf.pings, int(q.MinPING),
					"the payload carries %d PING frame(s), the spec declares at least %d", pf.pings, q.MinPING)
				require.LessOrEqualf(t, pf.pings, int(q.MaxPING),
					"the payload carries %d PING frame(s), the spec declares at most %d", pf.pings, q.MaxPING)
				require.LessOrEqualf(t, pf.runs, int(q.MaxPADDING),
					"the payload carries %d PADDING run(s) and the spec declares at most %d: the PADDING count is not being driven by the spec's bounds",
					pf.runs, q.MaxPADDING)
				require.Positivef(t, pf.runs, "the payload carries no PADDING at all; the spec declares at least %d run(s)", q.MinPADDING)

				cryptoCounts[len(pf.crypto)]++
				pingCounts[pf.pings]++
				runCounts[pf.runs]++
				if pf.runs > maxRuns {
					maxRuns = pf.runs
				}
				if pf.runs <= int(q.MinPADDING) {
					atOrBelowMinPADDING++
				}
				if minPings < 0 || pf.pings < minPings {
					minPings = pf.pings
				}
				if pf.pings > maxPings {
					maxPings = pf.pings
				}
			}

			// The margins, on the record on every run rather than inferred from a green tick.
			t.Logf("%d builds: CRYPTO frames %v, PING frames %v, PADDING runs %v (%d build(s) at or below MinPADDING=%d, %d required); the spec declares CRYPTO %d..%d, PING %d..%d, PADDING %d..%d",
				n, cryptoCounts, pingCounts, runCounts, atOrBelowMinPADDING, q.MinPADDING, tc.minBuildsAtOrBelowMinPADDING,
				q.MinCRYPTO, q.MaxCRYPTO, q.MinPING, q.MaxPING, q.MinPADDING, q.MaxPADDING)

			require.GreaterOrEqualf(t, maxRuns, int(q.MinPADDING),
				"in %d builds the most PADDING runs any payload carried was %d, and the spec declares at least %d: the PADDING count is pinned below what this profile declares, so the Initial's padding shape is a constant rather than the document's",
				n, maxRuns, q.MinPADDING)
			if q.MinCRYPTO != q.MaxCRYPTO {
				require.Greaterf(t, len(cryptoCounts), 1,
					"in %d builds the CRYPTO-frame count was always %v although the spec declares a range of %d..%d: the count is a constant inside the range, so half the declaration is not being read",
					n, cryptoCounts, q.MinCRYPTO, q.MaxCRYPTO)
			}
			if q.MinPING != q.MaxPING {
				// PING frames do not merge, so both ends of the declared range must be REACHED, not
				// merely respected. min != MinPING means the floor is not being drawn from; max !=
				// MaxPING means the ceiling is not.
				require.Equalf(t, int(q.MinPING), minPings,
					"in %d builds the fewest PING frames any payload carried was %d and the spec declares a floor of %d: the count is not being drawn from [MinPING,MaxPING] (PING frames never merge on the wire, so the floor is reachable exactly) — %v",
					n, minPings, q.MinPING, pingCounts)
				require.Equalf(t, int(q.MaxPING), maxPings,
					"in %d builds the most PING frames any payload carried was %d and the spec declares a ceiling of %d: the count is not being drawn from [MinPING,MaxPING], so MaxPING has stopped being read and every Initial this profile sends carries a PING count the document never declared — %v",
					n, maxPings, q.MaxPING, pingCounts)
			}
			if q.MinPADDING != q.MaxPADDING {
				if tc.exactPADDINGCeiling {
					// The separator-rich set. An un-merged build is routine here (measured: the
					// ceiling was reached in 200 of 200 trials of 120 builds), so the ceiling is an
					// EQUALITY — and an equality no constant inside the range can satisfy, which is
					// what makes the mid-pin and the sub-range go red instead of passing unnoticed.
					require.Equalf(t, int(q.MaxPADDING), maxRuns,
						"in %d builds the most PADDING runs any payload carried was %d and the spec declares a ceiling of %d: on this bound set the separators outnumber the PADDING frames %d..%d to %d, so an un-merged build reaching the ceiling is routine (measured 200/200 trials) — a ceiling that is never reached means the count is not being drawn from [MinPADDING,MaxPADDING] at all but from something strictly inside it, and every Initial this profile sends carries a PADDING shape the document never declared — %v",
						n, maxRuns, q.MaxPADDING, int(q.MinPING)+int(q.MinCRYPTO), int(q.MaxPING)+int(q.MaxCRYPTO), q.MaxPADDING, runCounts)
				} else {
					// PADDING runs merge and this set has too few separators for the ceiling to be
					// reachable, so only the weak lower bound is available here: at least one build
					// must carry MORE than MinPADDING runs, which pinning at MinPADDING cannot do.
					// It does NOT separate a mid-range constant — set 3 above is what does.
					require.Greaterf(t, maxRuns, int(q.MinPADDING),
						"in %d builds no payload carried MORE than %d PADDING run(s) although the spec declares up to %d: a payload can never carry more runs than the frames the builder emitted, so the count is pinned at MinPADDING and MaxPADDING has stopped being read — %v",
						n, q.MinPADDING, q.MaxPADDING, runCounts)
				}
				require.GreaterOrEqualf(t, atOrBelowMinPADDING, tc.minBuildsAtOrBelowMinPADDING,
					"in %d builds only %d carried as few as %d PADDING run(s) (at least %d expected — see the measured tables above this test) although the spec declares a floor of %d: the count is pinned at MaxPADDING and MinPADDING has stopped being read — %v",
					n, atOrBelowMinPADDING, q.MinPADDING, tc.minBuildsAtOrBelowMinPADDING, q.MinPADDING, runCounts)
			}
		})
	}
}
