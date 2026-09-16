package quic

// [SIGHTGLASS U-LAYER] Tests for the per-Transport UDP socket buffer targets (u_conn_buffers.go,
// transport.go, sys_conn_buffers*.go).
//
// The mandate these guard: every Sightglass session is stateless and leaks nothing into another.
// SO_RCVBUF/SO_SNDBUF are the only two UDP socket options an application chooses, so they are part
// of a profile's identity; if they live in a process-global they are per-PROCESS, not per-session,
// and two identities in one binary can wear each other's socket shape. TestUTransportSocketBuffers-
// AreNotProcessGlobal cannot pass while such a global exists.

import (
	"net"
	"sync"
	"syscall"
	"testing"

	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/protocol"
	"github.com/stretchr/testify/require"
)

// The package defaults must be COMPILE-TIME CONSTANTS. This declaration is the guard: if either is
// ever turned back into a package-level `var` (the shape this fork shipped before, with exported
// SetDesiredReceiveBufferSize/SetDesiredSendBufferSize setters), this file stops compiling with
// "protocol.DesiredReceiveBufferSize (variable of type int) is not constant" and the whole package's
// tests go red — which is stronger than any runtime assertion, because a global that only one
// goroutine ever writes can still pass a runtime test.
const (
	_ = protocol.DesiredReceiveBufferSize
	_ = protocol.DesiredSendBufferSize
)

func sockBuf(t *testing.T, c *net.UDPConn) (rcv, snd int) {
	t.Helper()
	rc, err := c.SyscallConn()
	require.NoError(t, err)
	var serr error
	require.NoError(t, rc.Control(func(fd uintptr) {
		rcv, serr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		if serr != nil {
			return
		}
		snd, serr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	}))
	require.NoError(t, serr)
	return rcv, snd
}

func newUDPConn(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c
}

// TestUTransportSocketBuffersComeFromTheTransport: the socket a Transport wraps carries THAT
// Transport's targets, read back off the kernel with getsockopt rather than from our own config.
//
// The values are deliberately above this host's UDP defaults: quic-go only ever RAISES a buffer
// ("if size >= want { return nil }"), so a target below the OS default would make the assertion
// measure the kernel instead of the Transport.
func TestUTransportSocketBuffersComeFromTheTransport(t *testing.T) {
	c := newUDPConn(t)
	defRcv, defSnd := sockBuf(t, c)

	const wantRcv, wantSnd = 1 << 20, 1 << 17
	require.Greater(t, wantRcv, defRcv, "test value is below this host's default SO_RCVBUF; the assertion would be vacuous")
	require.Greater(t, wantSnd, defSnd, "test value is below this host's default SO_SNDBUF; the assertion would be vacuous")

	tr := &Transport{Conn: c, UDesiredReceiveBufferSize: wantRcv, UDesiredSendBufferSize: wantSnd}
	require.NoError(t, tr.init(true))
	t.Cleanup(func() { tr.Close() })

	rcv, snd := sockBuf(t, c)
	require.Equalf(t, wantRcv, rcv, "SO_RCVBUF on the wrapped socket is %d, the Transport asked for %d", rcv, wantRcv)
	require.Equalf(t, wantSnd, snd, "SO_SNDBUF on the wrapped socket is %d, the Transport asked for %d", snd, wantSnd)
}

// TestUTransportSocketBuffersAreNotProcessGlobal is the C6 guard. Two Transports with DIFFERENT
// targets are initialised concurrently; each socket must carry its own Transport's values.
//
// With the process-global this fork used to ship (quic.SetDesiredBufferSizes -> two package vars in
// internal/protocol, read by wrapConn), both sockets would end up with whichever value was written
// last, and the two writes were an unsynchronised data race besides. That is a cross-identity
// fingerprint bleed on the one pair of socket options an application actually chooses.
//
//	go test . -run TestUTransportSocketBuffersAreNotProcessGlobal -race -count=1
func TestUTransportSocketBuffersAreNotProcessGlobal(t *testing.T) {
	type want struct{ rcv, snd int }
	wants := []want{{1 << 20, 1 << 17}, {1 << 21, 1 << 18}}
	require.NotEqual(t, wants[0], wants[1], "both sessions ask for the same sizes; this guard would be vacuous")

	conns := []*net.UDPConn{newUDPConn(t), newUDPConn(t)}
	for _, c := range conns {
		defRcv, defSnd := sockBuf(t, c)
		for _, w := range wants {
			require.Greater(t, w.rcv, defRcv, "test value is below this host's default SO_RCVBUF")
			require.Greater(t, w.snd, defSnd, "test value is below this host's default SO_SNDBUF")
		}
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	trs := make([]*Transport, len(wants))
	for i := range wants {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tr := &Transport{Conn: conns[i], UDesiredReceiveBufferSize: wants[i].rcv, UDesiredSendBufferSize: wants[i].snd}
			trs[i] = tr
			<-start
			if err := tr.init(true); err != nil {
				t.Errorf("session %d: Transport.init: %v", i, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	for _, tr := range trs {
		if tr != nil {
			defer tr.Close()
		}
	}
	if t.Failed() {
		return
	}

	for i, c := range conns {
		rcv, snd := sockBuf(t, c)
		require.Equalf(t, wants[i].rcv, rcv,
			"session %d's socket has SO_RCVBUF %d but its own Transport asked for %d: the other session's value leaked across",
			i, rcv, wants[i].rcv)
		require.Equalf(t, wants[i].snd, snd,
			"session %d's socket has SO_SNDBUF %d but its own Transport asked for %d: the other session's value leaked across",
			i, snd, wants[i].snd)
	}
}

// TestUTransportSocketBuffersAbsentMeansUntouched: Sightglass expresses the two profile fields as
// *int and an ABSENT field means the application made no choice. Substituting quic-go's 7 MB for an
// absent value would put a socket shape on the host that belongs to no browser, so absence must mean
// "issue no setsockopt at all" and leave the kernel default standing (HR-6: never substitute).
func TestUTransportSocketBuffersAbsentMeansUntouched(t *testing.T) {
	c := newUDPConn(t)
	defRcv, defSnd := sockBuf(t, c)
	require.Less(t, defRcv, protocol.DesiredReceiveBufferSize,
		"this host already defaults above quic-go's target, so 'untouched' and 'raised' are indistinguishable here")

	tr := &Transport{Conn: c, UDesiredReceiveBufferSize: UDoNotSetSocketBuffer, UDesiredSendBufferSize: UDoNotSetSocketBuffer}
	require.NoError(t, tr.init(true))
	t.Cleanup(func() { tr.Close() })

	rcv, snd := sockBuf(t, c)
	require.Equalf(t, defRcv, rcv, "SO_RCVBUF changed from %d to %d although the profile declares none", defRcv, rcv)
	require.Equalf(t, defSnd, snd, "SO_SNDBUF changed from %d to %d although the profile declares none", defSnd, snd)
}

// TestUTransportSocketBuffersZeroKeepsUpstreamBehaviour: the zero value is the field's own absence,
// not a profile's. A plain upstream Transport that has never heard of the u-layer must still get
// upstream quic-go's 7 MB targets, or this fork would have changed upstream behaviour behind the
// backs of every other consumer.
func TestUTransportSocketBuffersZeroKeepsUpstreamBehaviour(t *testing.T) {
	c := newUDPConn(t)
	tr := &Transport{Conn: c}
	require.NoError(t, tr.init(true))
	t.Cleanup(func() { tr.Close() })

	rcv, _ := sockBuf(t, c)
	require.Equalf(t, protocol.DesiredReceiveBufferSize, rcv,
		"a zero-valued Transport got SO_RCVBUF %d, upstream quic-go asks for %d", rcv, protocol.DesiredReceiveBufferSize)
}

// uNoSyscallConn hides *net.UDPConn's SyscallConn, so setReceiveBufferTo/setSendBufferTo take the
// branch quic-go uses for a net.PacketConn it cannot inspect with getsockopt. That branch matters
// here because it is the one where the `want < 0` early return is the ONLY thing standing between an
// absent profile field and a setsockopt: on an inspectable socket upstream's "only ever raise"
// comparison (`if size >= want { return nil }`) happens to swallow a negative target as well, so a
// test that only ever reads SO_RCVBUF back cannot tell the tri-state apart from that accident.
type uNoSyscallConn struct {
	net.PacketConn

	readCalls  []int
	writeCalls []int
}

func (c *uNoSyscallConn) SetReadBuffer(n int) error { c.readCalls = append(c.readCalls, n); return nil }
func (c *uNoSyscallConn) SetWriteBuffer(n int) error {
	c.writeCalls = append(c.writeCalls, n)
	return nil
}

// TestUTransportSocketBuffersAbsentIssuesNoSetsockoptAtAll: "the profile declares no socket buffer"
// must mean NO setsockopt is issued, not "a setsockopt with something we made up". The tri-state
// documented on Transport.UDesiredReceiveBufferSize promises exactly that, and this is what holds it
// to it — see uNoSyscallConn for why the getsockopt-based test above cannot.
func TestUTransportSocketBuffersAbsentIssuesNoSetsockoptAtAll(t *testing.T) {
	c := &uNoSyscallConn{PacketConn: newUDPConn(t)}

	require.NoError(t, setReceiveBufferTo(c, UDoNotSetSocketBuffer))
	require.NoError(t, setSendBufferTo(c, UDoNotSetSocketBuffer))
	require.Emptyf(t, c.readCalls,
		"a profile declaring no receive buffer still issued SetReadBuffer%v: absence must leave the kernel default standing, and substituting a size nobody measured invents a fingerprint", c.readCalls)
	require.Emptyf(t, c.writeCalls,
		"a profile declaring no send buffer still issued SetWriteBuffer%v: absence must leave the kernel default standing", c.writeCalls)

	// Vacuity check: this same conn DOES get the call when the profile declares a size, so the two
	// assertions above are about the tri-state and not about a code path that never fires.
	const declared = 1 << 20
	require.NoError(t, setReceiveBufferTo(c, declared))
	require.NoError(t, setSendBufferTo(c, declared))
	require.Equalf(t, []int{declared}, c.readCalls, "this path never calls SetReadBuffer at all, so the absence assertion above is vacuous")
	require.Equalf(t, []int{declared}, c.writeCalls, "this path never calls SetWriteBuffer at all, so the absence assertion above is vacuous")
}
