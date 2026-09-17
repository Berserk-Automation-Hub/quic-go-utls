# Fork: `github.com/Berserk-Automation-Hub/quic-go-utls`

**Upstream base: `github.com/bogdanfinn/quic-go-utls` v1.0.10-utls**, commit
`4e6a46505b5f54c5bff5db72b600795648364e09` (the tip of upstream's default branch; verified with
`git ls-remote --tags https://github.com/bogdanfinn/quic-go-utls.git`, which maps
`refs/tags/v1.0.10-utls -> 4e6a465`). Earlier revisions of this file said **v1.0.9-utls** in the
title while saying v1.0.10-utls further down; v1.0.10-utls is the true base and v1.0.9-utls is
`7011633`, which is not an ancestor of anything here.

Sightglass consumes this fork by a plain `require` with **no `replace` directive**, so the module
path is the fork's own and its utls/fhttp dependencies point at our forks of those. Earlier
revisions of this file described a `replace` in `../../go.mod` and a `third_party/quic-go-utls`
vendor directory; neither exists. There is also no `UQUIC_LAYER_PATCH.md` — this file replaced it.

```
module  github.com/bogdanfinn/quic-go-utls  ->  github.com/Berserk-Automation-Hub/quic-go-utls
        github.com/bogdanfinn/utls  v1.7.8-barnius  ->  .../utls  v1.7.8-sightglass.1
        github.com/bogdanfinn/fhttp v0.6.9          ->  .../fhttp v0.6.9-sightglass.11
go      1.24.1 -> 1.27.0
```

---

## 1. What the patch is, exactly

### 1.1 Files ADDED (17)

`git diff --name-status 4e6a465 HEAD | awk '{print $1}' | sort | uniq -c` -> `17 A / 2 D / 365 M`.
An earlier revision of this section said 17 while enumerating 16; the count below is the
enumeration, and it is 17 because round 3 added a seventh test file (`u_packet_packer_test.go`).

Source (8):

| File | Contents |
|---|---|
| `u_quic_spec.go` | `QUICSpec` / `InitialPacketSpec` — the parrot description: ClientHello spec, connection-ID lengths, first packet number + its on-wire length, client token length, frame builder. Plus `dummyTokenStore`. |
| `u_quic_frames.go` | `QUICFrameBuilder` + `QUICRandomFrames`: lays one Initial packet's CRYPTO stream slices out as randomly split, shuffled CRYPTO frames interleaved with PING and PADDING, filling the packet **exactly**. All randomness from `crypto/rand`. |
| `u_packet_packer.go` | `uPacketPacker`: an Initial carrying CRYPTO becomes a standalone datagram of exactly `Config.InitialPacketSize`, framed by the builder, with the spec's packet-number length on the first one. Every other packet is packed by upstream code. |
| `u_connection.go` | `newUClientConnection`: mirrors `newClientConnection`, but takes the local transport parameters from the ClientHello spec, installs the u crypto setup and the u packer, and passes `uSendsECNMarks` (false) as the sent-packet handler's `enableECN`. |
| `u_transport.go` | `UTransport`: mirrors `Transport.dialEarly`/`doDial`, pinning the source and destination connection-ID lengths and the first Initial packet number, refusing a dial whose spec disagrees with the connection-ID generator the Transport already cached (§7 E3c/E26), and generating the first-flight Destination Connection ID from `crypto/rand` at the spec's length. `DialEarly` is its ONLY dial entry point — see §5 for why the non-early `Dial` was deleted. |
| `u_conn_buffers.go` | `UDoNotSetSocketBuffer` — the "this profile declares no socket buffer" value for the per-Transport SO_RCVBUF/SO_SNDBUF targets, and the note explaining why there is no package-level setter any more. |
| `internal/handshake/u_crypto_setup.go` | `NewUCryptoSetupClient` — `tls.UQUICClient(...)` + `ApplyPreset(spec)`; the `tlsQUICConn` interface and the `*tls.UQUICConn` adapter. |
| `internal/wire/u_transport_parameters.go` | `TransportParameters.PopulateFromUQUIC` — derives quic-go's local flow-control view from the utls transport-parameter extension, so we police exactly what we advertised. |

Tests (7) — the fork's own tests for the fork's own code (see §3):

`u_transport_test.go`, `u_quic_frames_test.go`, `u_quic_spec_test.go`, `u_conn_buffers_test.go`,
`u_packet_packer_test.go`, `internal/handshake/u_crypto_setup_test.go`,
`internal/wire/u_transport_parameters_test.go`.

Other (2): `PATCHES.md` (this file) and `integrationtests/self/self_curveid_test.go` (§2).

8 + 7 + 2 = 17.

### 1.2 Files DELETED (2)

`integrationtests/self/self_go124_test.go` and `integrationtests/self/self_go125_test.go`, replaced
by `self_curveid_test.go`. See §2.

### 1.3 The 365 MODIFIED upstream files, partitioned so the three parts sum

Every one of the 365 was classified mechanically, by counting the `+`/`-` lines in its diff that
contain neither `bogdanfinn` nor `Berserk-Automation-Hub`:

```
$ for f in $(git diff --name-status 4e6a465 HEAD | grep '^M' | awk '{print $2}'); do
    n=$(git diff 4e6a465 HEAD -- "$f" | grep -E '^[+-]' | grep -v '^[+-][+-]' \
        | grep -v bogdanfinn | grep -v Berserk-Automation-Hub | wc -l); echo "$n $f"; done \
  | awk '$1==0' | wc -l        ->  344
                                   (the same loop with $1>0 -> 21)
```

*  **344** change nothing but import paths (`github.com/bogdanfinn/...` ->
   `github.com/Berserk-Automation-Hub/...`). That is the module rename and nothing else.
*  **13** carry the rename AND exactly one moved blank line inside the import block — one `-` and one
   `+`, both empty (`git diff … | sed -n l` shows `-$` / `+$`). That is gofmt regrouping the imports
   after the rename changed their sort order, and it is collateral of the `sed`, not a patch. They
   are, in full: `connection.go`, `connection_test.go`, `fuzzing/handshake/fuzz.go`,
   `http3/client_test.go`, `http3/server_test.go`, `http3/stream_test.go`,
   `integrationtests/self/self_test.go`, `integrationtests/self/zero_rtt_test.go`,
   `internal/handshake/updatable_aead.go`, `internal/handshake/updatable_aead_test.go`, `server.go`,
   `server_test.go`, `transport_test.go`.
*  **8** carry a real change, listed below.

344 + 13 + 8 = 365. An earlier revision of this section said "354 import-path-only" and "7 with a
change"; both were wrong (the 13 blank-line files were unaccounted for, and `go.mod`/`go.sum` shared
one table row while being two files), and the partition did not sum.

### 1.3.1 The 8 upstream files with a behavioural change

| File | Change |
|---|---|
| `go.mod` | module path, `go 1.27.0`, and the fork dependencies above. |
| `go.sum` | the checksums for those. |
| `internal/handshake/crypto_setup.go` | the field `conn *tls.QUICConn` is widened to the interface `conn tlsQUICConn` (declared in the new `u_crypto_setup.go`), so the same crypto setup can drive either `*tls.QUICConn` (upstream, unchanged) or utls' `*tls.UQUICConn`. `var _ tlsQUICConn = (*tls.QUICConn)(nil)` keeps the upstream path type-checked. **This is the only non-test upstream file whose behaviour the u-layer touches at all.** |
| `transport.go` | adds `Transport.UDesiredReceiveBufferSize` / `UDesiredSendBufferSize` and passes them to `wrapConnWithBuffers` in `init`. |
| `sys_conn.go` | `wrapConn(pc)` becomes a wrapper around a new `wrapConnWithBuffers(pc, wantReceive, wantSend)`. |
| `sys_conn_buffers.go` | `setReceiveBuffer(c)` becomes a wrapper around a new `setReceiveBufferTo(c, want)` with tri-state `want` (see §4). |
| `sys_conn_buffers_write.go` | the `go:generate`d send-side twin of the above, regenerated by hand to stay identical to what the generator would emit. |
| `integrationtests/self/handshake_drop_test.go` | test-only: the negotiated-curve assertion becomes unconditional and calls the new `getCurveID(t, …)`. See §2. |

`connection.go` and `connection_test.go` additionally have four comment URLs that the rename `sed`
rewrote from `github.com/bogdanfinn/quic-go-utls/pull/NNNN` to our org. Those PR numbers are
quic-go's, so they are dead links in bogdanfinn's tree too; they are left as the `sed` left them
rather than hand-edited, and recorded here so the diff has no unexplained line.

**`internal/protocol/params.go` is byte-identical to upstream again**, and
`integrationtests/tools/proxy/proxy.go` is now rename-only. Both used to carry a patch that turned
`DesiredReceiveBufferSize`/`DesiredSendBufferSize` from consts into mutable package state; §4
explains why that is gone.

Nothing in the server path, the congestion controller, the streams layer, `http3`, or the frame
codecs is touched.

---

## 2. The whole `integrationtests/self` package never ran — in this fork or in pristine upstream

134 top-level tests, 365 including subtests, and **not one of them had ever executed**, here or
upstream:

```
$ go test ./integrationtests/self/
integrationtests/self/self_go125_test.go:8:19: connState.CurveID undefined
    (type "…/utls".ConnectionState has no field or method CurveID)
FAIL	…/integrationtests/self [build failed]
```

Upstream splits the helper across a `//go:build go1.25` pair because the standard library's
`crypto/tls` only exported `ConnectionState.CurveID` in Go 1.25. This fork does not use
`crypto/tls`; it uses utls, which keeps the same value in the **unexported** field
`testingOnlyCurveID` (set for both peers, utls `conn.go`: `state.testingOnlyCurveID = c.curveID`)
and exports nothing. So the availability has nothing to do with the Go toolchain version, the
`go1.25` variant can never compile, and the `!go1.25` variant can never be selected under
`go 1.27.0` — the package was structurally unbuildable.

Reproduced in pristine upstream v1.0.10-utls (with only `go 1.24.1 -> 1.27.0`, which is needed for
`testing/synctest`):

```
$ cd <pristine v1.0.10-utls> && GOWORK=off go test ./...
integrationtests/self/self_go125_test.go:8:19: connState.CurveID undefined …
FAIL	github.com/bogdanfinn/quic-go-utls/integrationtests/self [build failed]
```

**The fix** is one file, `integrationtests/self/self_curveid_test.go`: a single un-tagged
`getCurveID(t, connState)` that reads `testingOnlyCurveID` reflectively and **loud-fails** (HR-6) if
utls ever renames or re-types it, rather than returning a zero `CurveID` that would make the
caller's `require.Equal` fail with an unexplained `0`. Reading an unexported numeric field through
`reflect.Value.Uint` is allowed — the read-only flag blocks `Interface` and `Set`, not `Uint`. The
alternative, adding an exported accessor to utls, is an API change to a TLS library for the benefit
of one integration test, and is deliberately not done. `handshake_drop_test.go` drops its
`runtime.Version()` guard for the same reason: with utls the value does not depend on the toolchain.

Result:

```
$ go test ./integrationtests/self/ -count=1 -json   # counted from the Test/Action records

                              tests executed   pass   skip   fail
before (and in pristine)                   0      0      0      0   [build failed]
after                                    365    363      0      2
```

`134` top-level, `365` including subtests — the exact population the audit counted. There are **no**
skips at all: the package runs whole, and nothing in it is skipped individually either.

The 2 failures are not this patch's. They are load-sensitive upstream flakes in upstream tests,
newly VISIBLE because the package is newly RUNNING; the run above was made while other `go test`
processes were competing for CPU on this machine, and both tests pass in isolation and in quiet
full-package runs. §9.3 has the counts.

---

## 3. The u-layer had no tests of its own. Now it does.

Coverage of the eight u-layer source files, measured TWICE, because a single averaged number would
hide the thing worth seeing: what the fork's own tests reach, and what the SHIPPED entry point
reaches when Sightglass drives it.

*  **fork suite** — `go test . ./internal/wire ./internal/handshake -count=1 -coverpkg=./...` in this
   repository. "before" is the same command at commit `99b5288` (the last commit before the tests
   existed), measured, not asserted.
*  **shipped path** — `go test ./parity/ -run TestParityH3PeerDeclaredLengthsAreBounded -count=1
   -coverpkg='github.com/Berserk-Automation-Hub/quic-go-utls/...'` in the Sightglass repository, i.e.
   `sg.NewSessionFactory -> SessionFactory.Open -> Session -> quich3.NewH3ClientForSession ->
   h3client.dial -> quic.UTransport.DialEarly`, against a loopback H3 origin.

| File | before (fork suite) | after (fork suite) | shipped path |
|---|---|---|---|
| `internal/handshake/u_crypto_setup.go` | 0.0% (0/25) | **100.0%** (25/25) | 96.0% (24/25) |
| `internal/wire/u_transport_parameters.go` | 0.0% (0/32) | **96.9%** (31/32) | 75.0% (24/32) |
| `u_quic_spec.go` | 0.0% (0/12) | **91.7%** (11/12) | 41.7% (5/12) |
| `u_connection.go` | 0.0% (0/63) | **87.3%** (55/63) | 76.2% (48/63) |
| `u_quic_frames.go` | 0.0% (0/100) | **85.0%** (85/100) | 77.0% (77/100) |
| `u_transport.go` | 0.0% (0/85) | **89.1%** (82/92) | SHIPPED_UT |
| `u_packet_packer.go` | 0.0% (0/84) | **75.6%** (62/82) | SHIPPED_UPP |
| **u-layer total** | **0.0% (0/402)** | **86.5% (351/406)** | **SHIPPED_TOT** |

(402 -> 406 statements: `QUICSpec.UDPDatagramMinSize` and `UTransport.Dial` were deleted, the
`uDialsEarly` branch in `uDoDial` was added (§5), and the post-`init` connection-ID agreement check
added two more — E3c/E26 below. The total is unchanged this round because the two statements the
`InitPacketNumberLength` range check adds to `u_transport.go` are the two the now-unreachable `n > 4`
branch removes from `u_packet_packer.go` (E31); the covered count moved 350 -> 351 because the new
check's `if` and its `return` are both exercised while the deleted branch had one of each. Its `if` executes on the shipped path (`u_transport.go:91`
is `1` in the shipped-path profile) and its refusal branch does not, which is the intended shape: no
Sightglass session sets `Transport.ConnectionIDLength` or `ConnectionIDGenerator`, and every session
builds its own `Transport` (`go/quich3/h3client.go:613`).)

**The tests drive `DialEarly`, which is the function Sightglass calls, and it is the only one there
is.** An earlier revision of this file had every one of these tests calling `UTransport.Dial`
(`use0RTT=false`) while `go/quich3/h3client.go:646` called `DialEarly` (`use0RTT=true`); the two
differ in whether `earlyConnChan` is armed, which `select` arm returns the connection, and whether
`cs.allow0RTT` is set — so the whole ablation table below was ablating a function nobody shipped.
`go tool cover -func` on both profiles now reports `u_transport.go:44 DialEarly 100.0%` and no
`Dial` at all.

The tests assert the u-layer's properties **on the wire**: they capture the datagrams a real
`UTransport.DialEarly` puts on a UDP socket and decrypt them with the RFC 9001 §5.2 Initial keys any
on-path observer can derive, rather than reading back our own configuration. One exception, and it is
declared rather than hidden: `u_packet_packer_test.go` drives the packer directly through upstream's
mock harness, because the state it guards — the connection asking for an ACK-only packet while
Initial CRYPTO is pending — cannot be reached from a dial on demand (§7 E29). One test completes a
full handshake against a stock quic-go server and moves 1 MB of stream data over it. **No value in
any of these tests is a captured browser fingerprint (HR-1) and none is claimed to be one**: the
specs are synthetic, deliberately unlike any browser, and what they prove is the MECHANISM — that
whatever a profile pins is what leaves the socket. The browser's values live in a Sightglass profile
document; this fork contains no engine identity (HR-5).

### 3.1 What is still 0.0% on the shipped path, and why each is kept

| Symbol | fork suite | shipped path | Disposition |
|---|---|---|---|
| `uPacketPacker.PackPTOProbePacket` (`u_packet_packer.go:48`) | 66.7% | 0.0% | KEPT. A PTO probe only fires when an Initial is lost, which a 1.3-second loopback test never does; the shipped path reaches it the first time a real network drops a ClientHello. Deleting it would send the RETRANSMITTED Initial with upstream quic-go's framing while the original carried the browser's — a tell that only appears under loss, which is the worst kind. Exercised by the fork suite. |
| `dummyTokenStore.Pop` (`u_quic_spec.go:93`) | 75.0% | 0.0% | KEPT as profile-driven surface (HR-9). `getTokenStore` installs it only when a profile declares `http3.initial.client_token_length > 0`, and no profile shipped today does: `sightglass/profiles/chrome-152.json:354` says `"client_token_length": 0` and firefox-148/firefox-156 omit the key. The PLUMBING is live and shipped — `go/sightglass/profile_net.go:603` parses the field and `go/quich3/spec.go:692` hands it to `InitialPacketSpec.ClientTokenLength` — so this is a document-driven branch nobody's document takes, not a function nothing calls. Deleting it would make a declared profile field silently do nothing, which is exactly the defect `UDPDatagramMinSize` was deleted for. Guarded by `TestUSpecTokenLengthInstallsATokenStore` (ablation E17). |
| `dummyTokenStore.Put` (`u_quic_spec.go:101`) | reported 0.0%, and the report is an artefact | reported 0.0%, and it genuinely is not called there | KEPT, same reason as `Pop`: it is the other half of a `TokenStore`, and the interface cannot be satisfied without it. Its body is EMPTY — a dummy store must cache nothing — so it contains zero statements and `go tool cover -func` divides 0 by 0 in BOTH profiles. The two profiles differ and an earlier revision of this row quoted the wrong one as if it were the shipped-path number: the FORK-suite profile shows `u_quic_spec.go:101.54,101.54 0 1` (zero statements, one execution, from `u_quic_spec_test.go:28`), while the SHIPPED-PATH profile shows `0 0` — zero executions, because the shipped path only reaches a token store at all when a profile declares `client_token_length > 0` and none does (see the `Pop` row). Called by the fork suite, not called on the shipped path, and 0.0% in neither case means "uncovered". |

## 4. The socket-buffer targets are no longer process-global

`SO_RCVBUF`/`SO_SNDBUF` are the only two UDP socket options an application actually chooses, so they
are part of the identity a profile declares. This fork used to express them as **two mutable package
globals** in `internal/protocol/params.go`, written through an exported
`quic.SetDesiredBufferSizes(receive, send)` and read by `wrapConn` on every dial. That is wrong twice
over:

* the write raced every concurrent dial's read — `go test -race` reported it; and
* worse, because a race detector never sees it on a single-profile run, with **two profiles in one
  process a connection could be wrapped with the OTHER profile's socket buffers**. Per-session
  statelessness with no leaks is the mandate, not a preference.

They now live on the `Transport` that owns the socket, and there is **no package-level setter at
all**. `internal/protocol/params.go` is back to upstream's two `const`s, and
`integrationtests/tools/proxy/proxy.go` is back to using them as values. `SetDesiredBufferSizes` and
`DesiredBufferSizes` are deleted, not deprecated.

`Transport.UDesiredReceiveBufferSize` / `UDesiredSendBufferSize` are tri-state:

| value | meaning |
|---|---|
| `0` (the zero value) | upstream quic-go's behaviour: raise the buffer to `protocol.DesiredReceiveBufferSize` (7 MB). A plain upstream `Transport` that has never heard of the u-layer is unaffected by any of this. |
| `> 0` | raise the buffer to exactly this — the value the profile declares. |
| `UDoNotSetSocketBuffer` | the profile declares **no** socket buffer: issue no `setsockopt` at all and leave the kernel default standing. Sightglass expresses the two profile fields as `*int`, and substituting quic-go's 7 MB for an absent value would invent a fingerprint nobody measured (HR-6). |

Three tests hold that, and the first sentence this section used to carry about them was FALSE by
experiment, so it is recorded here rather than quietly rewritten. It said
`TestUTransportSocketBuffersAreNotProcessGlobal` "cannot pass while one global exists". It can.
Reintroducing this fork's old shape verbatim in `sys_conn.go` —

```go
var uGlobalWantReceive, uGlobalWantSend int
func SetDesiredBufferSizes(receive, send int) { uGlobalWantReceive, uGlobalWantSend = receive, send }
func wrapConnWithBuffers(pc net.PacketConn, wantReceive, wantSend int) (rawConn, error) {
	SetDesiredBufferSizes(wantReceive, wantSend)
	wantReceive, wantSend = uGlobalWantReceive, uGlobalWantSend
```

— leaves `go test . -run TestUTransportSocketBuffers -count=10` at `ok … 0.375s` and `go test .
-count=1` at `ok … 17.847s`: the exported process-global setter is back and the whole package is
green. It goes red only under `-race`, and then as a DATA RACE report rather than as a leaked value,
and no suite here runs `-race`. The reason is structural: when a global is written and read inside
one call, the two goroutines serialise in practice and the window never opens.

So there are now three guards, and each one is red under a mutation the others miss:

| guard | what it makes impossible | the mutation it catches |
|---|---|---|
| `TestUTransportSocketBufferPathHasNoPackageLevelState` | package-level state on the buffer path AT ALL. It parses the package and applies three rules: no numeric package-level `var` declared in `sys_conn.go` / `sys_conn_buffers*.go` / `u_conn_buffers.go`; no function on the path assigns to a package-level var; none reads one, except `setBufferWarningOnce` (a `sync.Once` that carries no per-session value). | the declare-then-read shape above, deterministically, with the offending variable named |
| `TestUTransportSocketBuffersCannotBeObservedByAnotherSession` | one session's target reaching another session's socket. It parks session 0 INSIDE its `SO_RCVBUF` setsockopt with a `net.UDPConn` wrapper whose `SetReadBuffer` blocks, lets session 1 declare and apply different targets start to finish, then releases session 0 into its `SO_SNDBUF`. | a global read at each USE (`setSendBufferTo(pc, uGlobalWantSend)`) — deterministically, as a leaked VALUE: `session 0's socket has SO_SNDBUF 262144; its own call asked for 131072 and session 1 asked for 262144` |
| `TestUTransportSocketBuffersAreNotProcessGlobal` | two concurrent `Transport.init`s wearing each other's sizes | the same read-at-use shape (`session 1's socket has SO_SNDBUF 131072 but its own Transport asked for 262144: the other session's value leaked across`), and the declare-then-read shape **only under `-race`** |

All three carry vacuity checks — they refuse to run if the two sessions ask for the same sizes, if
either target is below this host's default (quic-go only ever RAISES a buffer, so a target below the
OS default would measure the kernel instead of the Transport), if the parser found no package-level
vars or no buffer-path functions at all, or if the barrier never fired.
`TestUTransportSocketBuffersAbsentIssuesNoSetsockoptAtAll` covers the third state: it proves that
absence issues no `setsockopt` AT ALL rather than one the getsockopt reader cannot distinguish from
the kernel default (see §7, E2b). A third, compile-time guard sits in the same file:

```go
const (
	_ = protocol.DesiredReceiveBufferSize
	_ = protocol.DesiredSendBufferSize
)
```

If either is ever turned back into a `var`, the package stops compiling.

---

## 5. Dead code removed

* `quic.SetDesiredBufferSizes` / `quic.DesiredBufferSizes` — Sightglass stopped calling them when the
  targets moved onto the Transport. Deleted (§4).
* `QUICSpec.UDPDatagramMinSize` and `DefaultUDPDatagramMinSize` — **nothing in this package ever read
  the field.** An Initial laid out by the FrameBuilder is padded to exactly
  `Config.InitialPacketSize`, and an Initial packed by upstream code is padded by upstream's own
  `initialPaddingLen` to the same size. A caller setting it believed it was pinning the datagram
  size while the value went nowhere; a profile field the library silently ignores is worse than no
  field at all. Deleted rather than documented.

* The `if n > 4 { return … }` inside `packSpecInitialPacket` — **deleted this round.** The 1..4 range
  is now checked in `dialSpec`, where the document enters the library and the error can name the
  field (E31), and the only route to that packer is
  `dialSpec -> uDoDial -> newUClientConnection -> newUPacketPacker`, so the second check was a branch
  no caller could take. Shipping it as belt and braces would be exactly the unreachable code C2
  forbids; the coverage profile agreed (`u_packet_packer.go` 84 -> 82 statements).

* `UTransport.Dial`, and the `use0RTT` parameter that existed to vary — **deleted this round.** Its
  only callers were this package's own tests. Sightglass constructs a `UTransport` in exactly two
  places (`go/quich3/h3client.go:622`, `go/quich3/capture.go:98`) and both go on to call `DialEarly`;
  `grep -rn 'UTransport' go --include='*.go' | grep -v _test` finds no third. A shipped-path coverage
  profile confirmed it: `u_transport.go:28 Dial 0.0%`. With `Dial` gone, `use0RTT` had one call site
  passing `true`, so the `if use0RTT` false-branch was unreachable too; the parameter is now the
  named constant `uDialsEarly`, which keeps the ablation a one-token edit (E25). A browser is never
  cold by policy — Chrome attempts 0-RTT whenever it holds a ticket for the origin — so there was
  never a shipped reason for a non-early entry point.

Everything else in the u-layer has a caller reachable from `sightglass.NewSessionFactory ->
Session.Do`: `quich3.Scope.H3Client -> h3client.dial -> quic.UTransport.DialEarly -> dialSpec ->
uDoDial -> newUClientConnection -> {NewUCryptoSetupClient, PopulateFromUQUIC, newUPacketPacker ->
QUICRandomFrames.Build}`, with `Transport.init` applying the socket buffers on the way in. That is a
claim about a coverage profile, not about a grep, and §3.1 lists the three symbols it does NOT cover
together with the reason each is kept rather than deleted.

---

## 6. Why the patch exists at all (the observable properties)

Upstream `quic-go` builds its ClientHello from `tls.Config` and picks its own Initial-packet shape.
Neither can be made to look like a specific browser, and every one of the following is **passively
observable** — QUIC Initial packets are decryptable by anyone who sees the Destination Connection ID
(RFC 9001 §5.2):

| Property | Upstream quic-go | Chrome 152 (measured) |
|---|---|---|
| ClientHello bytes | Go's, from `tls.Config` | fixed extension set/order → q-JA4 `q13d0312h3_55b375c5d22e_178839b6cec1` |
| `quic_transport_parameters` body | quic-go's `wire.TransportParameters.Marshal` | Chrome's set, incl. `google_connection_options` 0x3128 and a GREASE parameter, order shuffled per connection |
| Destination Connection ID length | random 8..20 | **8** |
| Source Connection ID length | 4 (default) | **0** |
| First Initial packet number / length | 0, always ≥ 2-byte field | **1**, in a **1-byte** field |
| Initial datagram size | `Config.InitialPacketSize` (1280 default) | **1250, every time** |
| Initial frame layout | one CRYPTO frame + trailing PADDING | "chaos protected": out-of-order CRYPTO fragments interleaved with PING and PADDING |
| outgoing IP TOS byte | `0x02` (ECT(0)) from the first one-RTT packet | `0x00` on **444/444** datagrams across 13 connections |
| `SO_RCVBUF` / `SO_SNDBUF` | 7340032 / 7340032 | 1048576 / 29040 |

Ground truth for the right-hand column, decrypted from the genuine-Chrome oracle capture with the
`quicfp` decoder (`reversing/oracle_verify/quicfp`, `QUICFP_FRAMES=1`):

```
[pkt] dcid=5a632d0f45dbb050 scidlen=0 pn=1 pnLen=1 tokenLen=0 pktBytes=1250
[frames] payload=1215B layout=PINGx1 PADDINGx169 CRYPTO(off=1048,len=257) PADDINGx1
  CRYPTO(off=1305,len=641) PINGx1 PADDINGx3 CRYPTO(off=0,len=42) PINGx2 PADDINGx51 CRYPTO(off=42,len=31)
[pkt] dcid=5a632d0f45dbb050 scidlen=0 pn=2 pnLen=2 tokenLen=0 pktBytes=1250
```

The two rows that are not about the Initial flight:

* **Socket buffers.** `SO_RCVBUF = kQuicSocketReceiveBufferSize = 1048576` (`net/quic/quic_context.h:105`,
  applied `quic_session_pool.cc:1212/1327`); `SO_SNDBUF = quic::kMaxOutgoingPacketSize * 20 = 1452*20
  = 29040` (`quic_session_pool.cc:1237/1349`). Values live in the profile, never here.
* **No ECN marking.** Upstream runs RFC 9000 §13.4.2 ECN validation on every connection, so every
  one-RTT datagram carries an `IP_TOS` control message with ECT(0). Chrome never marks:
  `QuicPacketWriterParams::ecn_codepoint` defaults to `ECN_NOT_ECT` (`quic_packet_writer.h:45`) and
  `QuicConnection::SetFromConfig` only overrides it when the congestion controller opts in
  (`quic_connection.cc:473-477`); every sender Chrome ships returns `false` from
  `EnableECT0()/EnableECT1()` (`bbr2_sender.h:101-102`, `bbr_sender.h:142-143`, `bbr3_sender.h:97-98`,
  `tcp_cubic_sender_bytes.h:79-80`). Only the SEND side is disabled here — `oobConn` still sets
  `IP_RECVTOS` and `receivedPacketTracker` still counts ECT0/ECT1/CE off the wire, which is exactly
  Chrome's asymmetry (`socket->SetRecvTos()` and nothing else, `quic_session_pool.cc:1228`).

### Residual (HR-7 — NOT claimed as parity)

QUICHE's exact chaos-protector sequencing (which stream ranges land in which packet, and where the
split points fall) is not reproduced; both stacks randomize per connection, so only the shape is
comparable. Packet timing (pacing, ACK cadence, PMTU probing, retransmit timing) is quic-go's.

---

## 7. Ablation record

"A guard I have not broken is not a guard." Each of the **41** rows below is one mutation, applied
**on its own**, with the named test run and the exact failure text recorded. All were then restored
(`git status --short` clean of every ablation file afterwards).

**A third certification sweep found two more elements green** and one guarded element missing from
the table, so the table moved 35 rows -> 41 (E30a/E30b — the frame builder's CRYPTO and PADDING
bounds; E31 — the `InitPacketNumberLength` range check; E32 — the packer's "first Initial only"
condition, which WAS guarded and had no row; E2d/E2e — the two shapes a reintroduced socket-buffer
global takes, §4). That is the third time an attack on this table found something, and it is the reason the
"Element with no guard" section below now states a NUMBER instead of an absolute: the honest claim is
not "everything is guarded", it is "everything anyone has attacked so far is guarded, and here is
what was attacked".

Three things about this table that were not true of the one it replaces:

* **Four mutations that used to leave the suite green now turn it red**, and they were found by a
  certifier attacking the previous revision of this table, not by us: a zero-entropy Destination
  Connection ID (E24, twice), the two packet-number pins replaced by the browser's own values as
  library constants (E5/E6 — the HR-5 defect itself), and the "explicit caller wins" connection-ID
  condition (E3c/E26). Each has its own section below. Nothing in this table is claimed to be
  guarded that has not been turned red on this machine, and the one element that still has no guard
  is named as such.
* **Three more were found the same way, by us, after fixing those** — because the lesson of the
  first four is that the mutations nobody tried are where the unguarded elements are (E27, E28,
  E29). One of them, E28, needed TWO attempts: the obvious assertion (frame counts) passed under the
  mutation and only the PADDING did not. See "Three elements we found by attacking our own table".

* **Every dial-path ablation drives `UTransport.DialEarly`**, the only entry point this fork has and
  the only one `go/quich3/h3client.go:646` calls. The previous table ablated `UTransport.Dial`
  (`use0RTT=false`), a function Sightglass never invoked and which has since been deleted (§5).
* **No row names a test that merely restates the thing being ablated.** The previous E10 named
  `TestUTransportDoesNotECNMarkWhatItSends`, which was `require.False(t, uSendsECNMarks, …)` — an
  assertion about a constant. Mutating the CALL SITE (`u_connection.go:141`) instead of the constant
  left that test PASSING. It has been deleted, not renamed, and E10 now names the two tests that
  actually go red under the call-site mutation.

| # | Element reverted | Test that went red | Failure text |
|---|---|---|---|
| E1a | `self_curveid_test.go` -> upstream's `//go:build go1.25` pair (and `handshake_drop_test.go` back to the 1-arg call) | whole package | `integrationtests/self/self_go125_test.go:8:19: connState.CurveID undefined (type "…/utls".ConnectionState has no field or method CurveID)` / `FAIL … [build failed]` |
| E1b | `getCurveID` returns 0 instead of reading the field | `TestHandshakeWithPacketLoss/drop_1st_packet_in_direction_to_client/*` (every leaf) | `the handshake negotiated key-exchange group 0x0000, want X25519MLKEM768 (0x11ec)` |
| E2a | `setReceiveBufferTo`/`setSendBufferTo` ignore the Transport's value | `TestUTransportSocketBuffersComeFromTheTransport`, `…AreNotProcessGlobal` | `SO_RCVBUF on the wrapped socket is 7340032, the Transport asked for 1048576` / `session 0's socket has SO_RCVBUF 7340032 but its own Transport asked for 1048576: the other session's value leaked across` |
| E2b | the `want < 0` (absent) branch. **Two mutations, because the obvious one is inert — see below.** (i) delete the early return; (ii) collapse absent into the default (`if want <= 0 { want = protocol.Desired…BufferSize }`) | (i) `TestUTransportSocketBuffersAbsentIssuesNoSetsockoptAtAll`; (ii) that test AND `…AbsentMeansUntouched` | (i) `a profile declaring no receive buffer still issued SetReadBuffer[-1]: absence must leave the kernel default standing, and substituting a size nobody measured invents a fingerprint` (ii) `SO_RCVBUF changed from 786896 to 7340032 although the profile declares none` |
| E2c | `protocol.DesiredReceiveBufferSize` back to a `var` | whole package | `./u_conn_buffers_test.go:29:6: protocol.DesiredReceiveBufferSize (variable of type int) is not constant` |
| E3a | drop the spec's `SrcConnIDLength` pin | `TestUTransportPinsWhateverSourceConnectionIDLengthTheSpecAsks/*` (3/3) | `the spec asked for a 3 byte source connection ID and the wire carries 0` |
| E3b | `t.init(false)` — upstream's refusal of a zero-length SCID | `TestUTransportPinsTheInitialPacketShapeOnTheWire` | `Source Connection ID is 4 bytes, the spec pins 0 (upstream defaults to 4)` |
| E3c | the pre-`init` condition `if t.ConnectionIDGenerator == nil && t.ConnectionIDLength == 0` made UNCONDITIONAL, so a spec silently overwrites the connection-ID decision a caller made itself | `TestUTransportRefusesASpecThisTransportCannotHonour/the_caller_pinned_the_Transport's_own_connection-ID_length` | `expected: "quic u-layer: this Transport issues 4-byte source connection IDs and this dial's spec pins SrcConnIDLength 0; a Transport's connection-ID generator is fixed at its first dial, so one Transport cannot send both" / actual: "context deadline exceeded"` — `the dial went ahead although the Transport pins a 4-byte source connection ID and the spec pins 0: one of those two is silently not what left the socket` |
| E4 | `uGenerateDestConnID` ignores `DestConnIDLength` | `TestUTransportPinsTheInitialPacketShapeOnTheWire`, `TestUTransportGeneratesAFreshDestConnIDEveryDial` | `Destination Connection ID is 10 bytes, the spec pins 8 (upstream picks a random length in [8,20])` (and `expected: 8 / actual: 20` in the second) |
| E5 | the first Initial's packet NUMBER, two mutations: (i) dial with packet number 0 instead of the spec's; (ii) `protocol.PacketNumber(t.QUICSpec.InitialPacketSpec.InitPacketNumber)` -> the constant `protocol.PacketNumber(1)` — the browser's own value burned into library code (HR-5) | (i) `TestUTransportPinsTheInitialPacketShapeOnTheWire`; (ii) `TestUTransportPinsWhateverFirstPacketNumberTheSpecAsks/*` (4/4) | (i) `first Initial packet number is 0, the spec pins 1 (upstream always starts at 0)`; (ii) `the spec asked for first Initial packet number 7 and the wire carries 1` (and 42, 3, 2 in the other three cases) |
| E6 | the first Initial's packet-number FIELD WIDTH, two mutations: (i) let upstream choose it; (ii) `hdr.PacketNumberLen = protocol.PacketNumberLen(n)` -> the constant `protocol.PacketNumberLen(1)` — again the browser's own value as a library constant (HR-5) | (i) `TestUTransportPinsTheInitialPacketShapeOnTheWire`; (ii) `TestUTransportPinsWhateverFirstPacketNumberTheSpecAsks/*` (3/4 — the 1-byte case is what the mutation hard-codes, so it cannot fail) | (i) `first Initial packet-number field is 2 bytes, the spec pins 1 (upstream emits only 2 or 4)`; (ii) `the spec asked for a 2-byte packet-number field and the wire carries 1` (and 3, 4) |
| E7 | `useSpecInitial` always false — upstream framing | `TestUTransportLaysTheInitialOutWithTheSpecsFrameBuilder` | `the Initial carries no PING frames: the spec's frame builder did not lay this packet out` |
| E8 | drop the `crypto/rand` Fisher-Yates shuffle | `TestUQUICRandomFramesShufflesTheFrameOrder` | `in 60 builds the lowest-offset CRYPTO frame was always at position map[0:60]: the frame order is not shuffled, so the Initial layout is a constant tell` |
| E9a | do not call `PopulateFromUQUIC` | `TestUTransportLocalFlowControlComesFromTheSpec` | `quic-go believes it advertised initial_max_data 262144; the ClientHello spec says 15728640` |
| E9b | drop the empty-`initial_source_connection_id` write-back | `TestPopulateFromUQUICWritesBackAnEmptySourceConnectionID` | `the spec's empty initial_source_connection_id was not replaced with the connection's real one, so the peer would reject the handshake` |
| E10 | the CALL SITE `uSendsECNMarks` -> `true` (`u_connection.go:141`), not the constant | `TestUTransportCompletesARealHandshake` (this fork) and `quich3.TestNoECNMarksOnAnyDatagram` (Sightglass) | `the connection ECN-marks its 1-RTT packets; every datagram would leave the host with IP TOS 0x02` (`expected 0x0, actual 0x3`) / `datagram #3 carries an ECN control message [level=0 type=3 tos=0x02 (ecn bits 10) data=02 00 00 00]; genuine Chrome 152 marks NONE …` |
| E11 | narrow `crypto_setup.go`'s `conn` back to `*tls.QUICConn` | `internal/handshake` | `internal/handshake/u_crypto_setup.go:88:12: cannot use uQUICConn{…} (value of struct type uQUICConn) as *"…/utls".QUICConn value in assignment` |
| E12 | packer emits an Initial 7 B short of the configured size | `TestUTransportPinsTheInitialPacketShapeOnTheWire` | `the dial put nothing on the wire; it failed with: INTERNAL_ERROR (local): quic u-layer BUG: Initial packet is 1243 B, want exactly 1250 B` |
| E13 | `uQUICTransportParameters` returns a zero value instead of an error | `TestUTransportLoudFailsWithoutTransportParameters` | `An error is expected but got nil.` |
| E14 | drop the nil-spec / nil-ClientHelloSpec checks in `dialSpec` | `TestUTransportRejectsAnIncompleteSpec/no_spec_at_all` | `panic: runtime error: invalid memory address or nil pointer dereference … (*UTransport).dialSpec u_transport.go:53 … (*UTransport).DialEarly u_transport.go:45` |
| E15 | accept a `DestConnIDLength` below RFC 9000's minimum | `TestUTransportRejectsAnUndiallableDestConnIDLength` | `expected: "quic u-layer: DestConnIDLength below the RFC 9000 minimum of 8" / actual: "context deadline exceeded"` |
| E16 | `QUICRandomFrames.validate` not called | `TestUQUICRandomFramesRejectsAnImpossibleShape/*` (5/5) | `An error is expected but got nil.` (no-CRYPTO, no-PADDING cases) and `expected "…has a Min bound above its Max bound" / actual "quic u-layer: bad random range [5,4]"` |
| E17 | a declared `ClientTokenLength` installs no token store | `TestUSpecTokenLengthInstallsATokenStore` | `a spec declaring a client token length installed no token store` |
| E18 | ClientHello built from `tls.Config` (`HelloGolang`, no `ApplyPreset`) | `TestUCryptoSetupClientHelloComesFromTheSpec` | `the ClientHello's cipher suites are not the spec's, in the spec's order: the hello was built from tls.Config` (`expected []uint16{0x1303,0x1302,0x1301} / actual []uint16{0x1301,0x1302,0x1303}`) |
| E19 | apply the TLS 1.3 floor BEFORE `ApplyPreset` (where `ApplyPreset` overwrites it) | `TestUCryptoSetupPinsTLS13RegardlessOfTheConfig/the_spec's_supported_versions_lists_TLS_1.2` | `Received unexpected error: CRYPTO_ERROR 0x150 (local): tls: Config MinVersion must be at least TLS 1.13` |
| E20 | do not clone the caller's `tls.Config` | `TestUCryptoSetupPinsTLS13RegardlessOfTheConfig/the_caller's_Config_says_TLS_1.2` | `NewUCryptoSetupClient mutated the CALLER's tls.Config (MinVersion is now 0x0304); it must clone it first` |
| E21 | drop `EnableSessionEvents` | `TestUCryptoSetupStoresAResumptionTicket` | `the cached session carries no quic-go session data: no QUICStoreSession event fired, so 0-RTT is structurally impossible on this connection` (`Should NOT be empty, but was []`) |
| E22 | drop the RFC 9000 §17.2 upper bound on `DestConnIDLength` | `TestUTransportRejectsAConnectionIDLengthAboveTheRFCMaximum/destination` | `panic: runtime error: slice bounds out of range [:21] with length 20 … internal/protocol.GenerateConnectionID(…) connection_id.go:44 … (*UTransport).uGenerateDestConnID u_transport.go:199` |
| E23 | drop the `SrcConnIDLength` range check | `TestUTransportRejectsAConnectionIDLengthAboveTheRFCMaximum/source` | same panic, from `Transport.init`'s connection-ID generator (`internal/protocol.(*DefaultConnectionIDGenerator).GenerateConnectionID … connection_id.go:111`) |
| E24 | `uGenerateDestConnID` returns something that is not random, three mutations: (i) a CONSTANT of the right length (`bytes.Repeat([]byte{0xAB}, l)`); (ii) a big-endian `time.Now().UnixNano()` — no `crypto/rand` anywhere; (iii) `crypto/rand` with the first FIVE of eight bytes forced to `0x11` | `TestUTransportGeneratesAFreshDestConnIDEveryDial` (all three) and `TestUTransportDestConnIDIsUniformlyRandom` (ii, iii) | (i) `3 dials produced only 1 distinct Destination Connection ID(s) ([abababababababab abababababababab abababababababab]): the first-flight DCID is not freshly random, so every connection from this host is linkable by its Initial header`; (ii) `4 of 8 byte positions are identical across all three Destination Connection IDs ([18d5f0725764c500 18d5f07299183e28 18d5f072dad4ac48]): the DCID is structured, not random` and `byte 0 of the Destination Connection ID took only 1 of 256 possible values in 4096 generations: that position is not random, so every Initial this host sends carries a stable pattern any observer on the path can link`; (iii) `5 of 8 byte positions are identical across all three Destination Connection IDs ([111111111126465d 1111111111fdf313 1111111111d35efb]): the DCID is structured, not random` and the same byte-0 failure |
| E25 | `uDialsEarly` -> `false` (the u-layer stops attempting 0-RTT) | `quich3.TestQUICResumptionHelloMatchesChromeQJA4` (Sightglass, shipped path) | `warm q-JA4 = q13d0313h3_55b375c5d22e_b0954bf1abdf, want q13d0314h3_55b375c5d22e_79cc91d6b50c` — the warm ClientHello loses `early_data` (0x002a) and emits a q-JA4 no Chrome emits |
| E26 | drop the post-`init` check that the Transport's connection-ID generator agrees with the spec's `SrcConnIDLength` | both subtests of `TestUTransportRefusesASpecThisTransportCannotHonour` | `expected: "quic u-layer: this Transport issues 3-byte source connection IDs and this dial's spec pins SrcConnIDLength 5; a Transport's connection-ID generator is fixed at its first dial, so one Transport cannot send both" / actual: "context deadline exceeded"` — `the second session was served the first session's source connection ID length instead of its own` |
| E27 | `uGenerateDestConnID`'s "the profile declares no length" branch: `generateConnectionIDForInitial()` -> `protocol.GenerateConnectionID(8)`, a CONSTANT length inside the legal range | `TestUSpecDestConnIDLengthZeroKeepsTheUpstreamRandomLength` | `a spec declaring no DestConnIDLength produced only 1 distinct length(s) in 512 dials (map[8:512]): upstream draws the first-flight DCID length uniformly from [8,20], and a client that always picks one of them is telling on itself in the length field` |
| E28 | the frame builder's reserve in the packer: `reserve := protocol.ByteCount(fb.MaxOverhead())` -> `0` | `TestUTransportKeepsTheSpecLayoutWhenTheClientHelloFillsThePacket` | `the saturated Initial carries no PADDING at all (2 CRYPTO frame(s), 1 PING(s)): the packer reserved nothing for the frame builder, so the layout the spec declares — 2..6 PADDING runs — could not be applied and upstream's shape went out instead` |
| E29 | `useSpecInitial`'s `!onlyAck`: the spec layout runs even when the connection asked for an ACK-only packet | `TestUPacketPackerLeavesAnAckOnlyInitialToUpstream` | `the ACK-only Initial carries 3 frame(s): the connection asked for an ACK and the spec layout sent the pending ClientHello instead, in a window the congestion controller had closed` |
| E2d | the structural buffer guard: reintroduce `var uGlobalWantReceive, uGlobalWantSend int` + exported `SetDesiredBufferSizes` in `sys_conn.go`, read by `wrapConnWithBuffers` (§4) | `TestUTransportSocketBufferPathHasNoPackageLevelState` | `sys_conn.go declares a package-level var uGlobalWantReceive int: a socket-buffer target in package state is shared by every session in the process, which is the cross-identity bleed C6 forbids; it belongs on the Transport that owns the socket` (and 6 more: two declarations, four reads/assignments, each with file:line) |
| E2e | the same global, but read at each USE (`setSendBufferTo(pc, uGlobalWantSend)`) | `TestUTransportSocketBuffersCannotBeObservedByAnotherSession`, `…AreNotProcessGlobal` | `session 0's socket has SO_SNDBUF 262144; its own call asked for 131072 and session 1 asked for 262144. Session 1 ran to completion while session 0 was suspended between its two setsockopts, so a target that is not session 0's own can only have arrived through state the two sessions share` |
| E30a | the frame builder's CRYPTO bound: `randUint64(uint64(q.MinCRYPTO), uint64(q.MaxCRYPTO))` -> `randUint64(3, 3)` — a constant inside the one bound set every other test drove | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds/*` (2/2), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds/*` (2/2, on the wire) | `the payload carries 3 CRYPTO frame(s) and the spec declares at most 2: the CRYPTO split is not being driven by the spec's bounds` / `the payload carries 3 CRYPTO frame(s) and the spec declares at least 6: …so every Initial this profile sends has a layout the document never declared` / on the wire: `the Initial on the wire carries 3 CRYPTO frame(s) and this dial's spec declares at least 9: the layout that left the socket is not the one the profile declared` |
| E30b | the frame builder's PADDING bound: `randUint64(uint64(q.MinPADDING), uint64(q.MaxPADDING))` -> `randUint64(2, 2)`. A third mutation was run for `MaxCRYPTO` alone (`randUint64(Min, Min)`) | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds/*` (2/2) | `the payload carries 2 PADDING run(s) and the spec declares at most 1: the PADDING count is not being driven by the spec's bounds` / `in 120 builds the most PADDING runs any payload carried was 2, and the spec declares at least 4: the PADDING count is pinned below what this profile declares, so the Initial's padding shape is a constant rather than the document's` / (Max-only) `in 120 builds the CRYPTO-frame count was always map[6:120] although the spec declares a range of 6..12: the count is a constant inside the range, so half the declaration is not being read` |
| E31 | the `InitPacketNumberLength` 1..4 range check in `dialSpec` | `TestUTransportRejectsAPacketNumberLengthNoLongHeaderCanCarry/*` (3/3) | `expected: "quic u-layer: InitPacketNumberLength 5 is outside the RFC 9000 §17.2 range 1..4 (0 means \"let quic-go choose\")" / actual: "INTERNAL_ERROR (local): invalid packet number length: 5"` and, for `-1`, `actual: "context deadline exceeded"` — the dial went ahead |
| E32 | the packer's `&& uint64(hdr.PacketNumber) == p.uSpec.InitialPacketSpec.InitPacketNumber`, i.e. the pn-length pin applied to EVERY Initial rather than the first | `TestUTransportSecondInitialKeepsUpstreamPacketNumberLength` | `the second Initial also uses a 1-byte packet-number field; the spec pins only the first` (`Should not be: 0x1`) |

### E24 is here because the reverse attack worked TWICE

**Round one.** The table's DCID row (E4) only asserted the LENGTH. A certifier replaced
`protocol.GenerateConnectionID(l)` with a fixed `0xAB`-filled ID **of the correct length** and the
entire fork suite stayed green (`ok … 9.225s`), while on the Sightglass side the only fallout was
`Connect: … APPLICATION_ERROR (remote)` and `timeout: no recent network activity` — failures that
merely differ and do not describe the defect, which C1 forbids. A constant first-flight Destination
Connection ID is a catastrophic linkability tell: it is in clear text in every client Initial and it
is what RFC 9001 §5.2 derives the Initial keys from. `TestUTransportGeneratesAFreshDestConnIDEveryDial`
was written for it: three dials, three distinct DCIDs read off the wire.

**Round two, and this is the part the previous revision of this file got wrong.** That test also
required that the three IDs not share "most" byte positions, and this file claimed the consequence
that **"a counter or a timestamp fails it too"**. It did not. The threshold was
`require.Less(shared, uTestDCIDLen-2)` — up to FIVE of eight byte positions could be identical — and
a certifier walked two mutations straight through it:

```
uGenerateDestConnID -> big-endian time.Now().UnixNano(), no crypto/rand at all   ok … 4.945s
uGenerateDestConnID -> crypto/rand with the first five of eight bytes = 0x11     ok … 4.865s
```

Three dials about 1.1 s apart differ in a nanosecond timestamp's low four bytes, so the timestamp
scored `shared = 4` and passed under a threshold of 6. **The sentence was false and it has been
deleted rather than softened**; the same claim was repeated in `docs/PROGRAMME.md` F65 and in
`docs/tasks.json` T0482 and has been corrected in both. What replaces it is two guards, because one
of them cannot be run enough times to measure randomness:

* `TestUTransportGeneratesAFreshDestConnIDEveryDial` — unchanged in what it reads (the DCID off the
  WIRE, on three real dials) but the tolerance is now **one** shared byte position, not five. Three
  uniform 8-byte values share a given position with probability 2^-16, so "two or more shared" has
  probability 28·2^-32 ≈ 6·10^-9: it cannot flake, and a timestamp (4) or a five-byte prefix (5) or a
  counter (7) fails it.
* `TestUTransportDestConnIDIsUniformlyRandom` — 4096 calls to the same `(*UTransport).uGenerateDestConnID`
  the dial calls (`uDoDial` <- `dialSpec` <- `DialEarly` <- `go/quich3/h3client.go:646`), requiring
  that **every byte position takes at least 250 of its 256 values** and every bit is set between 40%
  and 60% of the time. In 4096 uniform draws a value is missed with probability (255/256)^4096 =
  1.1e-7, so both thresholds are tens of standard deviations from anything random, and both are far
  outside anything structured: a constant or timestamp position scores 1.

**What this pair does NOT catch, stated plainly rather than claimed away.** A keyed PRF — AES or
SHA-256 of a counter — is uniform by construction and passes both. No statistical test can separate
one from randomness without the key, so no test here pretends to. What is excluded is the whole
family a real mistake produces: constants, counters, timestamps, per-host prefixes, truncated or
biased randomness, and reuse across dials.

### E5/E6 are here because the HR-5 reverse attack worked

Every other u-layer test drives the single pair (first Initial packet number 1, 1-byte packet-number
field), which is what the browser this fork was written for happens to send. A certifier therefore
replaced the two profile reads with that browser's values as literals:

```
dialSpec:        protocol.PacketNumber(t.QUICSpec…InitPacketNumber) -> protocol.PacketNumber(1)      ok … 12.544s
packSpecInitial: hdr.PacketNumberLen = protocol.PacketNumberLen(n)  -> protocol.PacketNumberLen(1)   ok … 12.647s
```

Both are exactly the defect HR-5 exists to forbid — an engine's identity as a constant in library
code — and both were invisible, while the SCID and DCID lengths already had engine-agnostic guards
that loop over 3/5/12 and 8..20. `TestUTransportPinsWhateverFirstPacketNumberTheSpecAsks` closes it
symmetrically: four dials, packet numbers 7/42/3/2 in fields of 1/2/3/4 bytes, each read back out of
the long header on the wire. (Each case keeps the number inside the field it pins; a truncated packet
number is a different and legitimate QUIC behaviour, not this pin.)

### E3c/E26: "explicit caller wins" was a behaviour no test could see

`dialSpec` carried `if t.ConnectionIDGenerator == nil && t.ConnectionIDLength == 0` with the
documented intent that "the spec pins what the caller left open, it does not overwrite what the
caller decided". A certifier removed the condition entirely and the whole root package stayed green
(`ok … 12.909s`), which made it both unguarded (C1) and — since no Sightglass code sets either field
(`grep -rn 'ConnectionIDLength\|ConnectionIDGenerator' go --include='*.go'` returns nothing) — an
unreachable branch on the shipped path (C2).

Trying to guard it showed the condition was hiding a real defect rather than expressing a policy.
`Transport.init` runs under a `sync.Once` and caches ONE connection-ID generator for the life of the
Transport, so the Source Connection ID length is decided at the FIRST dial. A second u-layer dial on
that Transport with a different `SrcConnIDLength` was therefore served the first spec's length —
silently, in clear text, in every long header. The condition made that silent in one more way: a
caller that had pinned `Transport.ConnectionIDLength` itself got its value used while its profile
declared another.

Neither can be honoured after the fact, so neither is guessed at. After `init`, the dial now compares
the generator's actual length with the spec's and **refuses** (HR-6):

```
quic u-layer: this Transport issues 3-byte source connection IDs and this dial's spec pins
SrcConnIDLength 5; a Transport's connection-ID generator is fixed at its first dial, so one
Transport cannot send both
```

Both halves are ablated separately (E3c makes the pre-`init` condition unconditional; E26 deletes the
post-`init` check) and both go red. Nothing changes for Sightglass, which builds a fresh
`quic.Transport` per session (`go/quich3/h3client.go:613`) and sets neither field — the check executes
on the shipped path and its refusal branch does not, which the shipped-path coverage profile shows as
`u_transport.go:91 … 1` and `u_transport.go:92 … 0`.

### E2b is here twice because the obvious mutation is inert

Deleting `if want < 0 { return nil }` from `setReceiveBufferTo` changes nothing on an ordinary UDP
socket: upstream only ever RAISES a buffer, and its `if size >= want { return nil }` swallows a
negative target by accident a few lines later. A guard that reads `SO_RCVBUF` back with `getsockopt`
therefore cannot tell the tri-state from that accident.
`TestUTransportSocketBuffersAbsentIssuesNoSetsockoptAtAll` asserts the property the tri-state
actually promises — that NO `setsockopt` is issued — through a `net.PacketConn` whose `SyscallConn`
is hidden, which is the branch where the early return is the only thing between an absent profile
field and a call. It carries its own vacuity check: the same conn DOES get `SetReadBuffer(1<<20)`
when a size is declared.

### Three elements we found by attacking our own table

After fixing what the certifier broke, the same method was turned on the rest of the u-layer:
mutations nobody had tried, one at a time, restored after each. Three more elements were green.

**E27 — "the profile declares no DCID length" was only checked for a legal RANGE.**
`TestUSpecDestConnIDLengthZeroKeepsTheUpstreamRandomLength` generated ONE connection ID and asserted
`8 <= len <= 20`, which any constant in that range satisfies. But upstream's behaviour is not "a
length in [8,20]", it is a length drawn uniformly from that range on every dial, and a client that
always picks 8 is distinguishable from stock quic-go by the length field alone. 512 generations, ten
of the thirteen lengths required (a given one is missed with probability (12/13)^512 = 10^-18).

**E28 — the packer's reserve, and the assertion that was not sharp enough.**
`packSpecInitialPacket` subtracts `fb.MaxOverhead()` before asking upstream for a payload, so the
frame builder has room for the extra frame headers a split costs and for a PING. Every wire test used
a small synthetic ClientHello with hundreds of spare bytes, where the reserve is slack: setting it to
`0` left the whole suite green. Under saturation — a ClientHello too big for one Initial, which is
what the browser this parrots actually sends — it is load-bearing. The first attempt at a guard was
still not enough, and that is worth recording: asserting "more than one CRYPTO frame and at least one
PING" on the saturated Initial ALSO passed under the mutation, because the initial crypto stream
splits the hello itself and a one-byte rounding gap admits a single PING. Measured, with and without:

```
reserve = fb.MaxOverhead()    crypto=5 pings=2 padding=65 runs=3
reserve = 0                   crypto=2 pings=1 padding=0  runs=0
```

PADDING is what separates them, and it is also what the spec actually declares (2..6 runs), so that
is what the test asserts.

**E29 — `!onlyAck`, which no dial can reach on demand.**
When the congestion controller will not let anything ack-eliciting out, the connection asks the
packer for an ACK-ONLY packet. If the spec path ran there it would send the pending ClientHello
instead — a full-size, ack-eliciting datagram in a window the controller had closed. Removing
`!onlyAck` left every wire test green, because a real dial only reaches the packer in the state a
real dial produces. This one is therefore guarded at the packer, not on the wire:
`u_packet_packer_test.go` drives `uPacketPacker.PackCoalescedPacket` — the method the connection
calls — through upstream's own mock harness (`newTestPacketPacker`), with a real ClientHello queued
on the initial stream, and requires the ACK-only packet to carry no frames. It ships with a positive
control in the same file (`onlyAck=false`, same state, the spec layout DOES run and fills the packet
to exactly `Config.InitialPacketSize`), so the assertion cannot pass by the packer doing nothing.

### Four more the THIRD sweep found — two green elements, one missing row, one false sentence

The same method, turned on this table a third time by a certifier. It is worth recording what it
found, because the pattern is now consistent: **the unguarded element is always the one where every
test in the tree drives a single value.**

**E30a/E30b — the frame builder's CRYPTO and PADDING bounds did not have to come from the profile.**
Every test in this fork drove ONE builder value (`MinPING 1, MaxPING 3, MinCRYPTO 3, MaxCRYPTO 8,
MinPADDING 2, MaxPADDING 6` — `u_quic_frames_test.go`, `u_transport_test.go`, `u_packet_packer_test.go`).
Replacing the two spec reads in `Build` with CONSTANTS INSIDE that range —

```go
randUint64(uint64(q.MinCRYPTO), uint64(q.MaxCRYPTO))   -> randUint64(3, 3)
randUint64(uint64(q.MinPADDING), uint64(q.MaxPADDING)) -> randUint64(2, 2)
```

— left the whole root package green (`ok … 17.962s`). Under it, every Initial carries exactly 3
CRYPTO frames and 2 PADDING runs no matter what the document says, i.e. the chaos layout — the one
thing this file exists to produce — collapses to a CONSTANT shape. Four of the six profile fields
that reach the builder stop being read. Nothing anywhere noticed: the old
`TestUQUICRandomFramesEmitsTheChaosShape` bounds the PING count against the spec but nothing bounded
the CRYPTO-frame count or the PADDING-run count against it at all. Same defect class as E5/E6.

The fix is the same shape as E3a's and E5/E6's: drive TWO bound sets that share no value, at the
builder (`TestUQUICRandomFramesHonoursTheDeclaredFrameBounds`, 120 builds each) and on the wire
through a real `DialEarly` (`TestUTransportInitialFrameCountsComeFromTheSpecsBounds`). One honest
limitation is documented in both: the per-build PADDING-run count has an exact UPPER bound
(runs <= frames emitted <= `MaxPADDING`) but its lower bound is only reachable across builds, because
the builder shuffles its PADDING frames in among the others and two that land side by side read back
off the wire as one run — QUIC's PADDING frame is a single zero byte and no reader can tell four in
one frame from four one-byte frames. So the lower bound is asserted as "the largest run count in 120
builds is at least `MinPADDING`", which is what goes red under E30b's second failure.

**E31 — `InitPacketNumberLength` had no range check that could name the field.** The two directions
failed differently, and neither was a guard:

* `n > 4` did reach the wire writer and upstream stopped it, but as
  `INTERNAL_ERROR (local): invalid packet number length: 5` — a connection-level error from inside
  `wire`, after the dial had started, with the profile field named nowhere. A failure that merely
  differs is not a guard (C1).
* `n < 0` was not caught at all. The packer's pin reads `n > 0 && …`, so a negative width was treated
  as "absent", the dial went ahead, and the client sent a packet-number width its document never
  declared — HR-6's silent substitution.

Both are now refused in `dialSpec`, where the document enters the library and the error can name the
field, exactly like E22/E23 for the two connection-ID lengths. The old `if n > 4` inside
`packSpecInitialPacket` is DELETED rather than kept as belt and braces: the only route to that packer
is `dialSpec -> uDoDial -> newUClientConnection -> newUPacketPacker`, so a second check there is a
branch no caller can take, and shipping one would be C2's dead code.

**E32 — an element that WAS guarded and had no row.** The packer confines the packet-number-length
pin to the FIRST Initial (`n > 0 && uint64(hdr.PacketNumber) == …InitPacketNumber`), because the
capture shows the second packet of the flight using a 2-byte field. Dropping the condition is red —
`the second Initial also uses a 1-byte packet-number field; the spec pins only the first`,
`TestUTransportSecondInitialKeepsUpstreamPacketNumberLength` — but the table had no row for it, so
the table's "each distinct element" claim was not true. It has one now.

**And one sentence in §4 was false by experiment** — see §4 for the reintroduced global that left
`TestUTransportSocketBuffersAreNotProcessGlobal` passing 10/10, and the two guards added because of
it (E2d, E2e).

### Element with no guard

**One, as of this sweep — and the honest form of that claim is a NUMBER, not an absolute.** Three
successive attacks on this table have each found something (four elements in the first, three in the
second, three plus a missing row and a false sentence in the third), so "every element is guarded"
is a claim this document has been wrong about twice and will not make again. What it says instead is:
every element ANYONE HAS ATTACKED is guarded, every attack is in the table with its failure text, and
the one element with no possible test is named below.

Counting from the table: the four a certifier turned green against the first revision (E24 ii/iii,
E5 ii, E6 ii, E3c/E26), the three we then found ourselves (E27, E28, E29), and the three the third
sweep found (E30a, E30b, E31) are all red now. One element has no test that can go red:

The **fhttp pin alignment** (§8) has no test that can go red, and that is not an oversight. Go's
minimal-version selection means a consumer that requires a newer fhttp gets the newer one regardless
of what this fork's `go.mod` says, so a stale pin here is invisible from outside. What it does affect
is which fhttp **this fork's own suite runs against** — i.e. whether the combination we test is the
combination Sightglass ships. That is a property of the `go.mod` text, checked mechanically, not
something a test can assert without hard-coding a version in the fork (which would be circular, and
would put a moving pin inside library code).

### Two elements that were real defects, found by trying to ablate them

**E22/E23.** RFC 9000 §17.2 caps a connection ID at 20 bytes and `protocol.GenerateConnectionID`
slices a fixed 20-byte array, so `http3.initial.dest_conn_id_length: 21` — a value a profile can
perfectly well contain — panicked inside `connection_id.go`, several frames below any code that
knows the word "profile". Both lengths now fail at the point where the document enters the library,
with the field named.

**E19.** The TLS 1.3 floor used to be written before `uc.ApplyPreset(chs)`, and `ApplyPreset` ->
`UConn.SetTLSVers` writes a `MinVersion` derived from the SPEC onto the very `tls.Config` installed a
line earlier. A profile whose `supported_versions` lists TLS 1.2 alongside TLS 1.3 — an ordinary
thing for a browser document to carry — therefore lowered the local policy, and `UQUICConn.Start`
refused the connection with `tls: Config MinVersion must be at least TLS 1.13` before a byte reached
the wire. The line is now applied after `ApplyPreset`, where it is load-bearing. Nothing observable
changes: the ClientHello bytes, `supported_versions` included, come from the spec either way.

### One assertion REMOVED this round, and why that is not a weakening

`TestUTransportLaysTheInitialOutWithTheSpecsFrameBuilder` used to require more than one PADDING RUN
in the single Initial it captured. That is a property of the per-connection permutation, not of the
layout: the 2..6 PADDING pieces are shuffled in among the CRYPTO and PING frames, and a permutation
that happens to put two of them side by side reads back as one run. **Measured: 1 failure in 12
consecutive runs of that test.** A guard that fails one dial in twelve is not a guard. The multi-run
property is real and is still guarded, statistically and where repeating is cheap —
`TestUQUICRandomFramesEmitsTheChaosShape` builds 50 payloads and requires more than one PADDING run
in at least one of them. What the wire test now asserts is what is DETERMINISTIC there: a PING frame
and several CRYPTO frames, neither of which upstream quic-go ever puts in an Initial. E7's ablation
was re-run afterwards and still goes red on the PING assertion.

---

## 8. Dependency pins

`go.mod` requires `github.com/Berserk-Automation-Hub/fhttp v0.6.9-sightglass.11` — the version
`Sightglass/go/go.mod` ships. It previously said `v0.6.9-sightglass.1`, a ten-version skew, so the
fork's own suite ran against an fhttp nobody deploys. `utls` is on `v1.7.8-sightglass.1`, which is
also what Sightglass ships. There are no `replace` directives.

---

## 9. Verification

### 9.1 This fork

```
$ gofmt -l <every file this patch touches>      # clean (NOT gofmt -w across the tree: this fork
                                                #        promises a gofmt baseline identical to upstream)
$ go vet ./...                                  # clean
$ go test ./... -count=1                        # all packages ok, modulo the load flakes in §9.3
```

### 9.2 Regression diff against pristine v1.0.10-utls

Baseline: a fresh clone of `bogdanfinn/quic-go-utls@v1.0.10-utls`
(`git rev-parse HEAD` = `4e6a46505b5f54c5bff5db72b600795648364e09`) with **only** `go 1.24.1 ->
1.27.0` (needed for `testing/synctest`, which `go 1.24.1` excludes; without it ten packages fail to
build for that one reason). Both trees, `go test ./... -count=1`, same machine:

```
                                                pristine v1.0.10-utls   this fork
packages failing                                                    1           0 *
  integrationtests/self  [build failed: CurveID]                  yes          no  (fixed, §2)
```

`*` one `./...` run of this fork reported `integrationtests/versionnegotiation` failing on a
wall-clock assertion while the machine was loaded; it passes 3/3 quiet, as does pristine's. §9.3.

**REGRESSION DIFF FOR THIS ROUND'S CHANGES.** `go test ./... -count=1 -timeout 900s` at the base of
this round and again with every change in this section applied, same machine, nothing cached
(`grep -c '(cached)'` = 0):

```
                                   before this round   after this round
packages failing                                   0                  0
NEW failures                                       —               none
```

The full listing of the "after" run is 26 `ok` lines and no `FAIL` line, `integrationtests/self`
included (`ok … 13.178s`). The three load-sensitive upstream flakes in §9.3 did not fire in it.

**NEW failures introduced by this patch: none.** Every test that fails here also fails, or cannot
run at all, in pristine.

### 9.3 Known flakiness, present on both sides, all of it load-sensitive

`integrationtests/self` is newly RUNNING here, so its flakes are newly VISIBLE; they are not new.
Everything below was measured on this machine, which was running other `go test` processes
throughout.

```
this fork, integrationtests/self        3 quiet full-package runs, 1 failure
                                          (TestHTTP3ListenerGracefulShutdown/listener_created_by_the_http3.Server)
                                        earlier, under load: TestConnDataBlocked, packetization_test.go:220
  the same test, -count=1 x3 in isolation                      3/3 ok
pristine, integrationtests/self         cannot run at all      [build failed: CurveID]

this fork, integrationtests/versionnegotiation
  in a full ./... run under load        1 failure  TestVersionNegotiationFailure
                                        `"2.5125716" is not less than "2"` — a wall-clock assertion
  the same package, -count=1 x3 quiet                          3/3 ok
pristine, same package, -count=1 x3                            3/3 ok
```

A THIRD member of the same class was found by a certifier, not by us, and it is listed because the
previous revision of this section presented its list as complete when it was only the part we had
hit:

```
this fork, integrationtests/self
  in a certifier's full ./... run  1 failure  TestHTTPReestablishConnectionAfterDialError (5.01s)
                                   http_test.go:575 Get "https://localhost:59127/hello":
                                   timeout: no recent network activity
  the same package in isolation, that certifier                1 x ok  0.507s
  our own full ./... run after this round's changes            ok  13.178s (0 failures, 0 cached)
```

`TestHTTPReestablishConnectionAfterDialError` is upstream's test in upstream's package; it waits for
a connection to be re-established within a wall-clock budget and misses it when the machine is busy,
the same shape as the two above. Nothing this patch changes is on its path. The honest statement is
that this section lists the load-sensitive failures ANYONE has observed on this machine, and that a
`./...` run of this fork has now come back clean twice with the list non-empty — not that the list is
closed.

`TestVersionNegotiationFailure` asserts that a failed version negotiation completes in under 2
seconds of WALL CLOCK; it is upstream's test, in a package this patch does not touch, and it fails
only when the machine is busy. Its pristine counterpart passes for the same reason its fork
counterpart does when the machine is quiet.

The fork's own new tests are NOT in this list, and one of them nearly was: see the last note in §7
for the assertion that was failing 1 run in 12 and what replaced it. After that change,
`TestUTransportLaysTheInitialOutWithTheSpecsFrameBuilder` and
`TestUTransportGeneratesAFreshDestConnIDEveryDial` ran 14/14 green.

This round's tests were measured the same way, because two of them tighten a threshold and a third
is statistical:

```
$ go test . -count=8 -run 'TestUTransportGeneratesAFreshDestConnIDEveryDial|
                           TestUTransportDestConnIDIsUniformlyRandom|
                           TestUTransportRefusesASpecThisTransportCannotHonour|
                           TestUTransportPinsWhateverFirstPacketNumberTheSpecAsks'
ok  github.com/Berserk-Automation-Hub/quic-go-utls  64.808s          # 8/8
$ go test . ./internal/wire ./internal/handshake -count=2
ok … 35.196s / 0.374s / 1.010s
```

Round 3's later additions were measured too — `TestUTransportKeepsTheSpecLayoutWhenTheClientHelloFillsThePacket`
4/4 with `-count=4`, and the whole root package plus `./internal/wire ./internal/handshake` green
under `-count=2` (35.4s / 0.6s / 1.0s) after they landed.

One flake WAS found and fixed while doing it, and it is recorded rather than quietly repaired: the
second subtest of `TestUTransportRefusesASpecThisTransportCannotHonour` originally dialled a dead
localhost port and required `context.DeadlineExceeded` from the first dial. A datagram to a closed
port draws an ICMP port-unreachable, which races the 300 ms deadline, so it failed once in eight. It
now dials an unanswering sink socket and asserts the thing it actually needs — that `Transport.init`
left the Transport issuing the first spec's 3-byte connection IDs — instead of inferring it from
which error came back.

### 9.4 Known pre-existing failure under `-count=2`

```
$ go test ./interop/http09/ -count=2
panic: http: multiple registrations for /helloworld
  …/interop/http09/http_test.go:42
```

`TestHTTPRequest` registers a handler on fhttp's `DefaultServeMux` at top level, so running it twice
in one process panics. Reproduced identically in pristine v1.0.10-utls and at this fork's own base
commit; not a consequence of anything here, and not fixed here because it is an upstream test bug in
a package Sightglass does not use.
