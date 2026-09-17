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
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

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

// uBufferPathFiles are the files the socket-buffer targets travel through, from the field a caller
// sets to the setsockopt. Any package-level state on this path is state two sessions share.
var uBufferPathFiles = []string{"sys_conn.go", "sys_conn_buffers.go", "sys_conn_buffers_write.go", "u_conn_buffers.go"}

// uBufferPathSeeds are the functions the buffer targets flow through outside those files.
var uBufferPathSeeds = []string{"Transport.init"} // the only caller of wrapConnWithBuffers

// uBufferPathGlobalsAllowed is the ONE package-level identifier the buffer path may touch, with the
// reason. sync.Once is process-global on purpose: it suppresses a repeated log line, it carries no
// per-session value, and nothing reads a target out of it.
var uBufferPathGlobalsAllowed = map[string]string{"setBufferWarningOnce": "sync.Once, log-once only, carries no per-session value"}

// TestUTransportSocketBufferPathHasNoPackageLevelState is the DETERMINISTIC C6 guard, and it exists
// because the concurrent test below is not one on its own.
//
// Measured: reintroducing this fork's old shape verbatim in sys_conn.go —
//
//	var uGlobalWantReceive, uGlobalWantSend int
//	func SetDesiredBufferSizes(receive, send int) { uGlobalWantReceive, uGlobalWantSend = receive, send }
//	func wrapConnWithBuffers(pc net.PacketConn, wantReceive, wantSend int) (rawConn, error) {
//		SetDesiredBufferSizes(wantReceive, wantSend)
//		wantReceive, wantSend = uGlobalWantReceive, uGlobalWantSend
//
// left `go test . -run TestUTransportSocketBuffers -count=10` and `go test . -count=1` GREEN. The
// exported process-global setter was back and nothing said so. It goes red only under `-race`, and
// then as a data-race report rather than as a leaked value — and neither suite here runs `-race`.
// The reason is structural: when a global is written and read inside one call the two goroutines
// serialise in practice and the window never opens.
//
// So the absence is asserted STRUCTURALLY, by parsing the package. Three rules, each of which the
// mutation above breaks:
//
//  1. no package-level `var` holding a number may be declared in the buffer-path files;
//  2. no function on the buffer path may ASSIGN to a package-level var;
//  3. no function on the buffer path may READ one, except the documented allowlist.
//
// This is not a proxy for the property — it IS the property C6 states: "no package-level variable
// that carries per-connection or per-session state". Two sessions cannot observe each other through
// state that does not exist.
func TestUTransportSocketBufferPathHasNoPackageLevelState(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	pkgVars := map[string]bool{} // every package-level var name in the package, any GOOS
	files := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		require.NoErrorf(t, err, "parsing %s", name)
		files[name] = f
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, sp := range gd.Specs {
				for _, id := range sp.(*ast.ValueSpec).Names {
					if id.Name != "_" {
						pkgVars[id.Name] = true
					}
				}
			}
		}
	}
	require.NotEmpty(t, pkgVars, "parsed no package-level vars at all; this guard would be vacuous")
	for _, want := range uBufferPathFiles {
		require.Containsf(t, files, want, "%s is gone; the buffer path moved and this guard no longer covers it", want)
	}

	// Rule 1: a numeric package-level var declared in a buffer-path file.
	numeric := map[string]bool{"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
		"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true, "bool": true}
	for _, name := range uBufferPathFiles {
		for _, d := range files[name].Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				id, isIdent := vs.Type.(*ast.Ident)
				if !isIdent || !numeric[id.Name] {
					continue
				}
				for _, n := range vs.Names {
					if n.Name == "_" {
						continue
					}
					t.Errorf("%s declares a package-level `var %s %s`: a socket-buffer target in package state is shared by every session in the process, which is the cross-identity bleed C6 forbids; it belongs on the Transport that owns the socket",
						name, n.Name, id.Name)
				}
			}
		}
	}

	// Rules 2 and 3: collect the functions on the path, then look at what they touch.
	type fn struct {
		file string
		decl *ast.FuncDecl
	}
	var path []fn
	for name, f := range files {
		inPathFile := slices.Contains(uBufferPathFiles, name)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if inPathFile || slices.Contains(uBufferPathSeeds, uFuncKey(fd)) {
				path = append(path, fn{name, fd})
			}
		}
	}
	require.NotEmpty(t, path, "found no functions on the buffer path; this guard would be vacuous")
	var names []string
	for _, p := range path {
		names = append(names, uFuncKey(p.decl))
	}
	for _, want := range []string{"wrapConnWithBuffers", "setReceiveBufferTo", "setSendBufferTo", "Transport.init"} {
		require.Containsf(t, names, want, "%s is not on the walked path; this guard no longer covers the buffer targets", want)
	}

	for _, p := range path {
		locals := uLocalNames(p.decl)
		report := func(pos token.Pos, id, how string) {
			if uBufferPathGlobalsAllowed[id] != "" || locals[id] {
				return
			}
			t.Errorf("%s: %s %s the package-level var %q: the socket-buffer targets must travel on the Transport that owns the socket and nowhere else, or two sessions in one process can wear each other's SO_RCVBUF/SO_SNDBUF",
				fset.Position(pos), uFuncKey(p.decl), how, id)
		}
		ast.Inspect(p.decl.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && pkgVars[id.Name] {
						report(id.Pos(), id.Name, "assigns to")
					}
				}
			case *ast.IncDecStmt:
				if id, ok := x.X.(*ast.Ident); ok && pkgVars[id.Name] {
					report(id.Pos(), id.Name, "mutates")
				}
			case *ast.Ident:
				if pkgVars[x.Name] {
					report(x.Pos(), x.Name, "reads")
				}
			}
			return true
		})
	}
}

// uFuncKey names a declaration the way uBufferPathSeeds does: "Recv.Name" for a method, "Name" for
// a plain function. Without the receiver, the seed "init" would also match every package `func init`
// in the tree.
func uFuncKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if idx, ok := typ.(*ast.IndexExpr); ok { // generic receiver
		typ = idx.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// uLocalNames collects every identifier a function introduces itself, so an unrelated local that
// happens to share a package-level var's name is not reported as a global.
func uLocalNames(fd *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	add := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				out[n.Name] = true
			}
		}
	}
	add(fd.Recv)
	add(fd.Type.Params)
	add(fd.Type.Results)
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if x.Tok == token.DEFINE {
				for _, lhs := range x.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						out[id.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, id := range x.Names {
				out[id.Name] = true
			}
		case *ast.FuncLit:
			add(x.Type.Params)
			add(x.Type.Results)
		case *ast.TypeSwitchStmt:
			if a, ok := x.Assign.(*ast.AssignStmt); ok {
				for _, lhs := range a.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						out[id.Name] = true
					}
				}
			}
		}
		return true
	})
	return out
}

// uBarrierConn is a UDP socket that SUSPENDS its owner inside the first setsockopt of the pair.
// wrapConnWithBuffers applies SO_RCVBUF and then SO_SNDBUF, so blocking in SetReadBuffer parks one
// session exactly between them, with another session free to run to completion in the gap.
type uBarrierConn struct {
	*net.UDPConn

	once    sync.Once
	entered chan struct{} // closed when this socket's first setsockopt is reached
	release chan struct{} // the test closes it to let that setsockopt finish
	calls   int
}

func (c *uBarrierConn) SetReadBuffer(n int) error {
	c.once.Do(func() {
		c.calls++
		close(c.entered)
		<-c.release
	})
	return c.UDPConn.SetReadBuffer(n)
}

// TestUTransportSocketBuffersCannotBeObservedByAnotherSession is the DETERMINISTIC functional half
// of C6: not "no global exists" (that is the structural test above) but "session 1's target cannot
// reach session 0's socket", proven by making the interleaving that would do it happen on purpose
// instead of hoping the scheduler produces it.
//
// Session 0 is suspended between its SO_RCVBUF and its SO_SNDBUF. Session 1 then declares AND
// applies different targets, start to finish. Session 0 resumes and issues its SO_SNDBUF. If the
// target it uses there came from anywhere but its own arguments — a package var read at each use,
// which is the OTHER shape a reintroduced global takes — session 0's socket wears session 1's
// SO_SNDBUF, every time, with or without `-race`.
//
// The concurrent test below cannot do this: both its goroutines read their targets before either
// blocks, so they serialise and the window never opens (measured — see the structural test).
func TestUTransportSocketBuffersCannotBeObservedByAnotherSession(t *testing.T) {
	type want struct{ rcv, snd int }
	sessions := []want{{1 << 20, 1 << 17}, {1 << 21, 1 << 18}}
	require.NotEqual(t, sessions[0], sessions[1], "both sessions ask for the same sizes; this guard would be vacuous")

	first := &uBarrierConn{UDPConn: newUDPConn(t), entered: make(chan struct{}), release: make(chan struct{})}
	second := newUDPConn(t)
	for _, c := range []*net.UDPConn{first.UDPConn, second} {
		defRcv, defSnd := sockBuf(t, c)
		for _, w := range sessions {
			require.Greater(t, w.rcv, defRcv, "test value is below this host's default SO_RCVBUF; quic-go only ever RAISES a buffer, so the assertion would measure the kernel")
			require.Greater(t, w.snd, defSnd, "test value is below this host's default SO_SNDBUF")
		}
	}

	done := make(chan error, 1)
	go func() { _, err := wrapConnWithBuffers(first, sessions[0].rcv, sessions[0].snd); done <- err }()

	select {
	case <-first.entered:
	case err := <-done:
		t.Fatalf("session 0 finished without ever issuing a setsockopt (err %v): the barrier never engaged, so this test proves nothing", err)
	case <-time.After(10 * time.Second):
		t.Fatal("session 0 never reached SO_RCVBUF within 10s")
	}

	// Session 1, start to finish, while session 0 is parked mid-pair.
	_, err := wrapConnWithBuffers(second, sessions[1].rcv, sessions[1].snd)
	require.NoError(t, err)
	close(first.release)
	require.NoError(t, <-done)
	require.Equal(t, 1, first.calls, "the barrier did not fire exactly once")

	rcv0, snd0 := sockBuf(t, first.UDPConn)
	rcv1, snd1 := sockBuf(t, second)
	require.Equalf(t, sessions[0].rcv, rcv0, "session 0's socket has SO_RCVBUF %d and its own call asked for %d", rcv0, sessions[0].rcv)
	require.Equalf(t, sessions[0].snd, snd0,
		"session 0's socket has SO_SNDBUF %d; its own call asked for %d and session 1 asked for %d. Session 1 ran to completion while session 0 was suspended between its two setsockopts, so a target that is not session 0's own can only have arrived through state the two sessions share",
		snd0, sessions[0].snd, sessions[1].snd)
	require.Equalf(t, sessions[1].rcv, rcv1, "session 1's socket has SO_RCVBUF %d, it asked for %d", rcv1, sessions[1].rcv)
	require.Equalf(t, sessions[1].snd, snd1, "session 1's socket has SO_SNDBUF %d, it asked for %d", snd1, sessions[1].snd)
}
