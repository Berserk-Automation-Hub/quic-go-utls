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
        github.com/bogdanfinn/utls  v1.7.8-barnius  ->  .../utls  v1.7.8-sightglass.6
        github.com/bogdanfinn/fhttp v0.6.9          ->  .../fhttp v0.6.9-sightglass.21
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
reaches when Sightglass drives it. **Seven of the eight are in the table**; the eighth,
`u_conn_buffers.go`, is a single `const` block (`protocol.DesiredReceiveBufferSize` and its three
siblings, §4) with NO statements at all, so `go tool cover` emits no block for it and it can be
neither covered nor uncovered — counted in the file list, absent from a statement table by
construction rather than by omission.

*  **fork suite** — `go test . ./internal/wire ./internal/handshake -count=1 -coverpkg=./...` in this
   repository. "before" is the same command at commit `99b5288` (the last commit before the tests
   existed), measured, not asserted.
*  **shipped path** — `go test ./parity/ -run TestParityH3PeerDeclaredLengthsAreBounded -count=1
   -coverpkg='github.com/Berserk-Automation-Hub/quic-go-utls/...'` in the Sightglass repository, i.e.
   `sg.NewSessionFactory -> SessionFactory.Open -> Session -> quich3.NewH3ClientForSession ->
   h3client.dial -> quic.UTransport.DialEarly`, against a loopback H3 origin.

| File | before (fork suite) | after (fork suite) | shipped path |
|---|---|---|---|
| `internal/handshake/u_crypto_setup.go` | 0.0% (0/26) | **100.0%** (25/25) | 96.0% (24/25) |
| `internal/wire/u_transport_parameters.go` | 0.0% (0/32) | **96.9%** (31/32) | 75.0% (24/32) |
| `u_quic_spec.go` | 0.0% (0/12) | **91.7%** (11/12) | 41.7% (5/12) |
| `u_connection.go` | 0.0% (0/63) | **87.3%** (55/63) | 76.2% (48/63) |
| `u_quic_frames.go` | 0.0% (0/100) | **85.0%** (85/100) | 77.0% (77/100) |
| `u_transport.go` | 0.0% (0/85) | **89.1%** (82/92) | 73.9% (68/92) |
| `u_packet_packer.go` | 0.0% (0/84) | **75.6%** (62/82) | 73.2% (60/82) |
| **u-layer total** | **0.0% (0/402)** | **86.5% (351/406)** | **75.4% (306/406)** |

(402 -> 406 statements, and the arithmetic is `u_crypto_setup.go` -1, `u_transport.go` +7,
`u_packet_packer.go` -2 = +4: `QUICSpec.UDPDatagramMinSize` and `UTransport.Dial` were deleted, the
`uDialsEarly` branch in `uDoDial` was added (§5), the post-`init` connection-ID agreement check added
two more — E3c/E26 below — and `u_crypto_setup.go` LOST one when its `NewUCryptoSetupClient` preamble
was rewritten (`63.2,67.1` carried one statement more than today's `66.2,69.1`), which is why its
BEFORE cell above reads 0/26 and not the 0/25 an earlier revision of this table printed. With 0/25
the BEFORE column summed to 401 against its own stated total of 0/402; re-measured at `99b5288` by
the command at the head of this section, `internal/handshake/u_crypto_setup.go` is `0/26` and the
column adds up. The total is unchanged this round because the two statements the
`InitPacketNumberLength` range check adds to `u_transport.go` are the two the now-unreachable `n > 4`
branch removes from `u_packet_packer.go` (E31); the fork-suite covered count moved 350 -> 351 because
the new check's `if` and its `return` are both exercised there, while the deleted branch had one of
each. The shipped-path total is unchanged at 306/406 and the split is the intended one. Re-measured at the
tag `go/go.mod` consumes, by the command at the head of this section, and quoted from the profile it
writes rather than from memory — an earlier revision of this paragraph quoted blocks 70/71, which are
not where either check is:

```
$ grep u_transport.go shipped.cov
u_transport.go:75.2,75.78  1 1     # if n := …InitPacketNumberLength; n < 0 || n > 4 {
u_transport.go:76.3,77.1   1 0     #     return nil, fmt.Errorf("… outside the RFC 9000 §17.2 range 1..4 …")
u_transport.go:107.2,107.101 1 1   # if got := t.connIDGenerator.ConnectionIDLen(); got != …SrcConnIDLength {
u_transport.go:108.3,111.1 1 0     #     return nil, fmt.Errorf("… one Transport cannot send both")
```

i.e. BOTH checks run on every Sightglass dial and NEITHER refusal branch is taken, which is the
intended shape: no shipped profile declares a packet-number width outside 1..4, no Sightglass session
sets `Transport.ConnectionIDLength` or `ConnectionIDGenerator`, and every session builds its own
`Transport` (`go/quich3/h3client.go:613`). Line 91 — which this paragraph and §7 both used to name
for the connection-ID check — is `if err := t.init(true); err != nil {`.)

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

"A guard I have not broken is not a guard." Each of the **57** rows below is one mutation, applied
**on its own**, with the named test run and the exact failure text recorded. All were then restored
(`git status --short` clean of every ablation file afterwards).

**A third certification sweep found two more elements green** and one guarded element missing from
the table, so the table moved 35 rows -> 41 (E30a/E30b — the frame builder's CRYPTO and PADDING
bounds; E31 — the `InitPacketNumberLength` range check; E32 — the packer's "first Initial only"
condition, which WAS guarded and had no row; E2d/E2e — the two shapes a reintroduced socket-buffer
global takes, §4).

**A fourth sweep then falsified the sentence this section used to end with.** The guard E30a/E30b
record asserted only `Min <= x <= Max`, which EVERY CONSTANT INSIDE THE DECLARED RANGE satisfies, so
it caught a builder that ignored the profile and missed one that read only HALF of it. A certifier
ran three SINGLE-FACTOR mutations against the consumed tag `v1.0.10-sightglass.9` and the entire root
package stayed green for all three (`ok … 21.318s / 21.344s / 21.251s`):

```go
randUint64(uint64(q.MinPADDING), uint64(q.MaxPADDING)) -> randUint64(uint64(q.MaxPADDING), uint64(q.MaxPADDING))  // MinPADDING unread
randUint64(uint64(q.MinPADDING), uint64(q.MaxPADDING)) -> randUint64(uint64(q.MinPADDING), uint64(q.MinPADDING))  // MaxPADDING unread
randUint64(uint64(q.MinPING), uint64(q.MaxPING))       -> randUint64(uint64(q.MinPING), uint64(q.MinPING))        // MaxPING unread
```

E30b's row claimed a coverage it did not have: what its mutation `randUint64(2, 2)` actually tested
was a constant OUTSIDE the declared range (`MinPADDING 4`), which the range assertions do catch. That
row was replaced, and the six bounds were re-guarded one at a time by distribution rather than by
range (`41 rows -> 45`).

**A fifth sweep then falsified the replacement.** The fourth sweep's PADDING assertions separated a
pin at an ENDPOINT and nothing else, because both were one-sided: "some build carries MORE than
`MinPADDING` runs" and "enough builds carry no more than `MinPADDING` runs". Two mutations a
certifier applied ALONE to `u_quic_frames.go:202` satisfied both — a strict SUB-RANGE
(`if hi > lo+1 { lo, hi = lo+1, hi-1 }`, under which NEITHER declared endpoint ever reaches the wire)
and a MID-PIN (`mid := (Min+Max)/2; randUint64(mid, mid)`, a literal constant inside the range). Both
still VARY build to build once PADDING runs merge, so every "it is not a single value" assertion
passed. The sub-range was green at all three sites; the mid-pin was green at the builder in 2 runs of
3 and green in Sightglass.

The fix is a THIRD bound set, `{MinPING: 18, MaxPING: 22, MinCRYPTO: 14, MaxCRYPTO: 16, MinPADDING: 2,
MaxPADDING: 4}`, in BOTH the builder test and the wire test. Its separators (32..38 CRYPTO+PING
frames) so outnumber its PADDING frames (at most 4) that an Initial whose PADDING runs do not merge
at all is routine — measured, the ceiling was reached in 200 of 200 trials of 120 builds and in 20 of
20 trials of 200 dials — so on that set the ceiling is asserted as an EQUALITY, `maxRuns ==
MaxPADDING`, which no constant strictly inside the range can satisfy. `41 rows -> 45 -> 51`: the
table now carries all TWELVE single-factor mutations of the three `randUint64` calls (each bound
pinned at either end, plus a mid-pin and a sub-range per frame type), each run alone with its failure
text, at each site.

**A sixth sweep then falsified the fifth's replacement, at all three sites at once.** Everything the
fifth sweep added bounds the ENDS of a distribution — `min == Min`, `max == Max`, `maxRuns ==
MaxPADDING`, "enough builds at or below `MinPADDING`" — and NOTHING bounded its INTERIOR. A certifier
replaced the uniform draw with a BIMODAL one, a coin flip between the two declared endpoints:

```go
pcoin, err := randUint64(0, 1)                  // u_quic_frames.go:188, applied ALONE
numPING := uint64(q.MinPING)
if pcoin == 1 { numPING = uint64(q.MaxPING) }
```

Both fields are still read, both ends still reach the wire, so every equality is satisfied with
probability 1 — and under the chrome-152 form of it every Initial carries either 1 or 10 PING frames
and never 2..9, which is the same "the chaos layout collapses to a CONSTANT shape" tell this family
of tests exists to remove, collapsed to two points instead of one. It was green at the builder (3/3),
on the wire (3/3) and in Sightglass, in its PING form and its PADDING form. What replaced it, per
frame type, is in the E30m..E30r rows and in the "SIXTH sweep" section below; `45 -> 51 -> 57` rows.

That is the sixth time an attack on this table found something, and it is the reason the "Element
with no guard" section below states a NUMBER instead of an absolute, and why the claim this section
makes is now the checkable one — **every mutation in the table below is red at the site(s) its row
names, with the failure text recorded** — rather than the unfalsifiable "everything anyone has
attacked is guarded", which has been wrong in four consecutive revisions.

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
| E30a | the frame builder's **MinCRYPTO** alone: `randUint64(uint64(q.MinCRYPTO), uint64(q.MaxCRYPTO))` -> `randUint64(uint64(q.MaxCRYPTO), uint64(q.MaxCRYPTO))` — the field stops being read, and the count stays INSIDE the declared range | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 2/3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 2/3/4 (wire), and in Sightglass `quich3.TestInitialPacketShapeMatchesChrome` (built through a temporary `replace`, removed afterwards) | builder (set 4): `in 2000 builds the CRYPTO-frame count was always map[16:2000] although the spec declares a range of 14..16: the count is a constant inside the range, so half the declaration is not being read` / wire (set 4): `in 1000 dials the fewest CRYPTO frames any Initial carried was 16 and this dial's spec declares a floor of 14: the split count is not being drawn from [MinCRYPTO,MaxCRYPTO], so MinCRYPTO never reaches the packer — map[16:1000]` / Sightglass: `in 400 cold Initials the fewest CRYPTO frames any one carried was 17 and the profile declares a floor of 4: the split count is not being drawn from min_crypto..max_crypto, so min_crypto never reaches the packer and every Initial this profile sends has a layout the document never declared — map[17:400]` |
| E30b | the frame builder's **MaxCRYPTO** alone: `randUint64(uint64(q.MinCRYPTO), uint64(q.MaxCRYPTO))` -> `randUint64(uint64(q.MinCRYPTO), uint64(q.MinCRYPTO))` | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 2/3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 2/3/4 (wire), and in Sightglass `quich3.TestInitialPacketShapeMatchesChrome` (built through a temporary `replace`, removed afterwards) | builder (set 4): `in 2000 builds the CRYPTO-frame count was always map[14:2000] although the spec declares a range of 14..16: the count is a constant inside the range, so half the declaration is not being read` / wire (set 4): `in 1000 dials the most CRYPTO frames any Initial carried was 14 and this dial's spec declares a ceiling of 16: the split count is not being drawn from [MinCRYPTO,MaxCRYPTO], so MaxCRYPTO never reaches the packer — map[14:1000]` / Sightglass: `in 400 cold Initials the most CRYPTO frames any one carried was 4 and the profile declares a ceiling of 17: the split count is not being drawn from min_crypto..max_crypto, so max_crypto never reaches the packer — map[4:400]` |
| E30c | the frame builder's **MinPING** alone: `randUint64(uint64(q.MinPING), uint64(q.MaxPING))` -> `randUint64(uint64(q.MaxPING), uint64(q.MaxPING))` | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 2/3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 2/3/4 (wire), and in Sightglass `quich3.TestInitialPacketShapeMatchesChrome` (built through a temporary `replace`, removed afterwards) | builder (set 4): `in 2000 builds the fewest PING frames any payload carried was 152 and the spec declares a floor of 148: the count is not being drawn from [MinPING,MaxPING] (PING frames never merge on the wire, so the floor is reachable exactly) — map[152:2000]` / wire (set 4): `in 1000 dials the fewest PING frames any Initial carried was 152 and this dial's spec declares a floor of 148: PING frames never merge on the wire, so a floor that is never reached means MinPING is not what the packer drew from — map[152:1000]` / Sightglass: `in 400 cold Initials the fewest PING frames any one carried was 10 and the profile declares a floor of 1: PING frames never merge on the wire, so a floor that is never reached means min_ping is not what the packer drew from — map[10:400]` |
| E30d | the frame builder's **MaxPING** alone: `randUint64(uint64(q.MinPING), uint64(q.MaxPING))` -> `randUint64(uint64(q.MinPING), uint64(q.MinPING))` — **one of the three mutations that left `v1.0.10-sightglass.9` entirely green** | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 2/3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 2/3/4 (wire), and in Sightglass `quich3.TestInitialPacketShapeMatchesChrome` (built through a temporary `replace`, removed afterwards) | builder (set 4): `in 2000 builds the most PING frames any payload carried was 148 and the spec declares a ceiling of 152: the count is not being drawn from [MinPING,MaxPING], so MaxPING has stopped being read and every Initial this profile sends carries a PING count the document never declared — map[148:2000]` / wire (set 4): `in 1000 dials the most PING frames any Initial carried was 148 and this dial's spec declares a ceiling of 152: MaxPING has stopped reaching the packer, so every Initial this profile sends carries a PING count the document never declared — map[148:1000]` / Sightglass: `in 400 cold Initials the most PING frames any one carried was 1 and the profile declares a ceiling of 10: max_ping has stopped reaching the packer, so every Initial this profile sends carries a PING count the document never declared — map[1:400]` |
| E30e | the frame builder's **MinPADDING** alone, pinned at the CEILING: `randUint64(uint64(q.MinPADDING), uint64(q.MaxPADDING))` -> `randUint64(uint64(q.MaxPADDING), uint64(q.MaxPADDING))` — **green at `.9`**. PADDING runs MERGE, so what separates this is the AT-OR-BELOW COUNT, not the range | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 2/3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 2/3/4 (wire), and in Sightglass `quich3.TestInitialPacketShapeMatchesChrome` (built through a temporary `replace`, removed afterwards) | builder (set 4): `in 2000 builds only 2 carried as few as 2 PADDING run(s) (at least 300 expected — see the measured tables above this test) although the spec declares a floor of 2: the count is pinned at MaxPADDING and MinPADDING has stopped being read — map[2:2 3:120 4:1878]` / wire (set 4): `in 1000 dials only 1 Initial(s) carried as few as 2 PADDING run(s) (at least 150 expected — see the measured tables above this test) although this dial's spec declares a floor of 2: the count is pinned at MaxPADDING and MinPADDING never reaches the packer — map[2:1 3:64 4:935]` / Sightglass: `in 400 cold Initials only 14 carried as few as 3 PADDING run(s) (at least 60 expected — see the measured table above this function) although the profile declares a floor of 3: the count is pinned at max_padding and min_padding never reaches the packer — map[2:1 3:13 4:65 5:120 6:121 7:66 8:14]` |
| E30f | the frame builder's **MaxPADDING** alone, pinned at the FLOOR: `randUint64(uint64(q.MinPADDING), uint64(q.MaxPADDING))` -> `randUint64(uint64(q.MinPADDING), uint64(q.MinPADDING))` — **green at `.9`** | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 2/3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 2/3/4 (wire), and in Sightglass `quich3.TestInitialPacketShapeMatchesChrome` (built through a temporary `replace`, removed afterwards) | builder (set 4): `in 2000 builds the most PADDING runs any payload carried was 2 and the spec declares a ceiling of 4: on this bound set the separators outnumber the PADDING frames 162..168 to 4, so an un-merged build reaching the ceiling is routine (measured: reached in every one of 2000 trials on each separator-rich set, see the tables above this test) — a ceiling that is never reached means the count is not being drawn from [MinPADDING,MaxPADDING] at all but from something strictly inside it, and every Initial this profile sends carries a PADDING shape the document never declared — map[1:21 2:1979]` / wire (set 4): `in 1000 dials the most PADDING runs any Initial carried was 2 and this dial's spec declares a ceiling of 4: on this bound set the separators outnumber the PADDING frames 162..168 to 4, so an un-merged Initial reaching the ceiling is routine (measured: reached in every trial of both separator-rich sets, see the tables above this test) — a ceiling that is never reached means the count never comes from [MinPADDING,MaxPADDING] but from something strictly inside it, and every Initial this spec sends carries a PADDING shape the document never declared — map[1:12 2:988]` / Sightglass: `in 400 cold Initials the busiest carried 3 PADDING run(s), no more than the midpoint 5 of the declared range 3..8: an Initial can never carry more runs than the frames the builder emitted, so a count that never exceeds the midpoint is a CONSTANT at or below it rather than a draw from the document's range, and max_padding is not reaching the packer — map[1:6 2:116 3:278]` |
| E30g | the frame builder's CRYPTO range replaced by its **MIDPOINT**: `mid := (uint64(q.MinCRYPTO)+uint64(q.MaxCRYPTO))/2; randUint64(mid, mid)` — a constant strictly INSIDE the declared range, neither endpoint read | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 2/3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 2/3/4 (wire), and in Sightglass `quich3.TestInitialPacketShapeMatchesChrome` (built through a temporary `replace`, removed afterwards) | builder (set 4): `in 2000 builds the CRYPTO-frame count was always map[15:2000] although the spec declares a range of 14..16: the count is a constant inside the range, so half the declaration is not being read` / wire (set 4): `in 1000 dials the fewest CRYPTO frames any Initial carried was 15 and this dial's spec declares a floor of 14: the split count is not being drawn from [MinCRYPTO,MaxCRYPTO], so MinCRYPTO never reaches the packer — map[15:1000]` / Sightglass: `in 400 cold Initials the fewest CRYPTO frames any one carried was 10 and the profile declares a floor of 4: the split count is not being drawn from min_crypto..max_crypto, so min_crypto never reaches the packer and every Initial this profile sends has a layout the document never declared — map[10:400]` |
| E30h | the frame builder's CRYPTO range narrowed to a strict **SUB-RANGE**: `lo, hi := uint64(q.MinCRYPTO), uint64(q.MaxCRYPTO); if hi > lo+1 { lo, hi = lo+1, hi-1 }` — the count still VARIES, but NEITHER declared endpoint ever reaches the wire | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 2/3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 2/3/4 (wire), and in Sightglass `quich3.TestInitialPacketShapeMatchesChrome` (built through a temporary `replace`, removed afterwards) | builder (set 4): `in 2000 builds the CRYPTO-frame count was always map[15:2000] although the spec declares a range of 14..16: the count is a constant inside the range, so half the declaration is not being read` / wire (set 4): `in 1000 dials the fewest CRYPTO frames any Initial carried was 15 and this dial's spec declares a floor of 14: the split count is not being drawn from [MinCRYPTO,MaxCRYPTO], so MinCRYPTO never reaches the packer — map[15:1000]` / Sightglass: `in 400 cold Initials the fewest CRYPTO frames any one carried was 5 and the profile declares a floor of 4: the split count is not being drawn from min_crypto..max_crypto, so min_crypto never reaches the packer and every Initial this profile sends has a layout the document never declared — map[5:39 6:29 7:32 8:30 9:33 10:36 11:33 12:35 13:30 14:31 15:30 16:42]` |
| E30i | the frame builder's PING range replaced by its **MIDPOINT** | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 2/3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 2/3/4 (wire), and in Sightglass `quich3.TestInitialPacketShapeMatchesChrome` (built through a temporary `replace`, removed afterwards) | builder (set 4): `in 2000 builds the fewest PING frames any payload carried was 150 and the spec declares a floor of 148: the count is not being drawn from [MinPING,MaxPING] (PING frames never merge on the wire, so the floor is reachable exactly) — map[150:2000]` / wire (set 4): `in 1000 dials the fewest PING frames any Initial carried was 150 and this dial's spec declares a floor of 148: PING frames never merge on the wire, so a floor that is never reached means MinPING is not what the packer drew from — map[150:1000]` / Sightglass: `in 400 cold Initials the fewest PING frames any one carried was 5 and the profile declares a floor of 1: PING frames never merge on the wire, so a floor that is never reached means min_ping is not what the packer drew from — map[5:400]` |
| E30j | the frame builder's PING range narrowed to a strict **SUB-RANGE** | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 2/3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 2/3/4 (wire), and in Sightglass `quich3.TestInitialPacketShapeMatchesChrome` (built through a temporary `replace`, removed afterwards) | builder (set 4): `in 2000 builds the fewest PING frames any payload carried was 149 and the spec declares a floor of 148: the count is not being drawn from [MinPING,MaxPING] (PING frames never merge on the wire, so the floor is reachable exactly) — map[149:700 150:661 151:639]` / wire (set 4): `in 1000 dials the fewest PING frames any Initial carried was 149 and this dial's spec declares a floor of 148: PING frames never merge on the wire, so a floor that is never reached means MinPING is not what the packer drew from — map[149:339 150:339 151:322]` / Sightglass: `in 400 cold Initials the fewest PING frames any one carried was 2 and the profile declares a floor of 1: PING frames never merge on the wire, so a floor that is never reached means min_ping is not what the packer drew from — map[2:49 3:50 4:63 5:58 6:52 7:49 8:42 9:37]` |
| E30k | the frame builder's PADDING range replaced by its **MIDPOINT**: `mid := (uint64(q.MinPADDING)+uint64(q.MaxPADDING))/2; randUint64(mid, mid)` — **this is the mutation a certifier used to defeat the FOURTH sweep's guard**: the run count still varies (merging), so every one-sided distribution bound passed | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 3/4 (wire), and in Sightglass `quich3.TestInitialPacketShapeMatchesChrome` (built through a temporary `replace`, removed afterwards) | builder (set 4): `in 2000 builds the most PADDING runs any payload carried was 3 and the spec declares a ceiling of 4: on this bound set the separators outnumber the PADDING frames 162..168 to 4, so an un-merged build reaching the ceiling is routine (measured: reached in every one of 2000 trials on each separator-rich set, see the tables above this test) — a ceiling that is never reached means the count is not being drawn from [MinPADDING,MaxPADDING] at all but from something strictly inside it, and every Initial this profile sends carries a PADDING shape the document never declared — map[2:75 3:1925]` / wire (set 4): `in 1000 dials the most PADDING runs any Initial carried was 3 and this dial's spec declares a ceiling of 4: on this bound set the separators outnumber the PADDING frames 162..168 to 4, so an un-merged Initial reaching the ceiling is routine (measured: reached in every trial of both separator-rich sets, see the tables above this test) — a ceiling that is never reached means the count never comes from [MinPADDING,MaxPADDING] but from something strictly inside it, and every Initial this spec sends carries a PADDING shape the document never declared — map[2:43 3:957]` / Sightglass: `in 400 cold Initials the busiest carried 5 PADDING run(s), no more than the midpoint 5 of the declared range 3..8: an Initial can never carry more runs than the frames the builder emitted, so a count that never exceeds the midpoint is a CONSTANT at or below it rather than a draw from the document's range, and max_padding is not reaching the packer — map[1:1 2:15 3:88 4:175 5:121]` |
| E30l | the frame builder's PADDING range narrowed to a strict **SUB-RANGE**: `if hi > lo+1 { lo, hi = lo+1, hi-1 }` — **the other mutation that defeated the FOURTH sweep's guard**, at all three sites | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 3/4 (wire) | builder (set 4): `in 2000 builds the most PADDING runs any payload carried was 3 and the spec declares a ceiling of 4: on this bound set the separators outnumber the PADDING frames 162..168 to 4, so an un-merged build reaching the ceiling is routine (measured: reached in every one of 2000 trials on each separator-rich set, see the tables above this test) — a ceiling that is never reached means the count is not being drawn from [MinPADDING,MaxPADDING] at all but from something strictly inside it, and every Initial this profile sends carries a PADDING shape the document never declared — map[2:78 3:1922]` / wire (set 4): `in 1000 dials the most PADDING runs any Initial carried was 3 and this dial's spec declares a ceiling of 4: on this bound set the separators outnumber the PADDING frames 162..168 to 4, so an un-merged Initial reaching the ceiling is routine (measured: reached in every trial of both separator-rich sets, see the tables above this test) — a ceiling that is never reached means the count never comes from [MinPADDING,MaxPADDING] but from something strictly inside it, and every Initial this spec sends carries a PADDING shape the document never declared — map[2:36 3:964]` / Sightglass: **GREEN, and that is recorded rather than hidden** — see the scope note below |
| E30m | the frame builder's PING range replaced by a **BIMODAL DRAW** — a coin flip between the two declared ENDPOINTS: `pcoin, err := randUint64(0, 1); numPING := uint64(q.MinPING); if pcoin == 1 { numPING = uint64(q.MaxPING) }`. **This is the mutation a certifier used to defeat the FIFTH sweep's guard at ALL THREE SITES AT ONCE**: both fields are still read and both ends still reach the wire, so every endpoint equality is satisfied with probability 1, while what leaves the socket is a TWO-VALUED count where the document declares a range | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 2/3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 2/3/4 (wire), and in Sightglass `quich3.TestInitialPacketShapeMatchesChrome` (built through a temporary `replace`, removed afterwards) | builder (set 4): `in 2000 builds no payload ever carried [149 150 151] PING frame(s) although the spec declares 148..152: the count is not being DRAWN from the declared range, it is being chosen from a strict subset of it (a coin flip between the two endpoints reaches both ends and never the middle), so every Initial this profile sends carries a PING count the document never declared — map[148:1001 152:999]` / wire (set 4): `in 1000 dials no payload ever carried [149 150 151] PING frame(s) although the spec declares 148..152: the count is not being DRAWN from the declared range, it is being chosen from a strict subset of it (a coin flip between the two endpoints reaches both ends and never the middle), so every Initial this profile sends carries a PING count the document never declared — map[148:512 152:488]` / Sightglass: `in 400 cold Initials not one carried [2 3 4 5 6 7 8 9] PING frame(s), although the profile declares 1..10: the count is not being DRAWN from the declared range, it is being chosen from a strict subset of it — a draw over only the two declared endpoints reaches both ends, so every equality above passes, and still puts a two-valued PING count on the wire where the document declares 10 — map[1:190 10:210]` |
| E30n | the same BIMODAL DRAW on **PADDING** (`dcoin`/`MinPADDING`/`MaxPADDING`). PADDING runs MERGE, so an interior run count is manufactured out of the top mode and set 3 cannot see this: measured over 2000 trials of 120 builds, the interior bucket holds 30..62 under the real draw and 6..29 under this one — populations that TOUCH. Set 4 is the set that separates them. **GREEN at the Sightglass site**, for the same reason E30l is — see the scope note below. | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` set 4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` set 4 (wire) | builder (set 4): `in 2000 builds only 67 carried exactly 3 PADDING run(s) — a count strictly inside the declared range 2..4 — and at least 300 are expected on this separator-saturated set (measured 624..763 over 300 trials of 2000 builds, against 47..90 for a two-valued draw): both declared endpoints are still reached, so every end-of-range assertion above passes, but the count is not being drawn UNIFORMLY across the range — it is coming from a strict subset of it, or from it with the weight piled on the ends, which is what a coin flip between MinPADDING and MaxPADDING looks like; the document declares 3 values and every Initial this profile sends carries a PADDING shape drawn from fewer — map[1:17 2:1003 3:67 4:913]` / wire (set 4): `in 1000 dials only 36 Initial(s) carried exactly 3 PADDING run(s) — a count strictly inside the declared range 2..4 — and at least 150 are expected on this separator-saturated set: both declared endpoints still reach the wire, so every end-of-range assertion above passes, but the count that reaches the packer is not drawn UNIFORMLY across the range — it comes from a strict subset of it, or from it with the weight piled on the ends, which is what a coin flip between MinPADDING and MaxPADDING looks like on the wire — map[1:3 2:485 3:36 4:476]` / Sightglass: **GREEN, and that is recorded rather than hidden** — see the scope note below |
| E30o | the same BIMODAL DRAW on **CRYPTO** (`ccoin`/`MinCRYPTO`/`MaxCRYPTO`) | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` sets 2/3/4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` sets 2/3/4 (wire), and in Sightglass `quich3.TestInitialPacketShapeMatchesChrome` (built through a temporary `replace`, removed afterwards) | builder (set 4): `in 2000 builds no payload ever carried [15] CRYPTO frame(s) although the spec declares 14..16: the count is not being DRAWN from the declared range, it is being chosen from a strict subset of it (a coin flip between the two endpoints reaches both ends and never the middle), so every Initial this profile sends carries a CRYPTO count the document never declared — map[14:978 16:1022]` / wire (set 4): `in 1000 dials no payload ever carried [15] CRYPTO frame(s) although the spec declares 14..16: the count is not being DRAWN from the declared range, it is being chosen from a strict subset of it (a coin flip between the two endpoints reaches both ends and never the middle), so every Initial this profile sends carries a CRYPTO count the document never declared — map[14:512 16:488]` / Sightglass: `in 400 cold Initials not one carried [5 6 7 8 9 10 11 12 13 14 15 16] CRYPTO frame(s), although the profile declares 4..17: the count is not being DRAWN from the declared range, it is being chosen from a strict subset of it — a draw over only the two declared endpoints reaches both ends, so every equality above passes, and still puts a two-valued CRYPTO count on the wire where the document declares 14 — map[4:195 17:205]` |
| E30p | the frame builder's PING range replaced by a **WEIGHTED DRAW** over the FULL declared support — `pw, err := randUint64(0, 3); numPING := uint64(q.MinPING); if pw == 3 { numPING, err = randUint64(uint64(q.MinPING), uint64(q.MaxPING)) }`, i.e. `MinPING` three times in four. Every declared count still reaches the wire, so support coverage alone passes; what is wrong is the SHAPE of the distribution. Caught by the n/2w population floor, which only set 4 draws enough samples to carry. **GREEN at the Sightglass site**, and disclosed rather than hidden: chrome-152's PING range is 10 values wide, so 400 cold Initials put ~40 in each bucket against ~7..15 under the mutation, and no population floor separates those without a flake budget this repository will not spend. Guarded at the fork, where the bound set is ours to choose and the margin is 11 sigma. | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` set 4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` set 4 (wire) | builder (set 4): `in 2000 builds only 91 payload(s) carried 149 PING frame(s) — a count the spec declares, in the range 148..152 — and a uniform draw over 5 values puts about 400 there: every declared count still reaches the wire, so plain support coverage passes, but the count is being drawn with the weight piled on one end of the range instead of uniformly across it, which is a PING distribution the document never declared — map[148:1613 149:91 150:98 151:86 152:112]` / wire (set 4): `in 1000 dials only 44 payload(s) carried 149 PING frame(s) — a count the spec declares, in the range 148..152 — and a uniform draw over 5 values puts about 200 there: every declared count still reaches the wire, so plain support coverage passes, but the count is being drawn with the weight piled on one end of the range instead of uniformly across it, which is a PING distribution the document never declared — map[148:805 149:44 150:62 151:43 152:46]` / Sightglass: **GREEN, and that is recorded rather than hidden** — see the scope note below |
| E30q | the same WEIGHTED DRAW on **CRYPTO**. **GREEN at the Sightglass site**, same reason as E30p (14 declared CRYPTO counts, ~29 per bucket against ~4..11). | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` set 4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` set 4 (wire) | builder (set 4): `in 2000 builds only 154 payload(s) carried 15 CRYPTO frame(s) — a count the spec declares, in the range 14..16 — and a uniform draw over 3 values puts about 666 there: every declared count still reaches the wire, so plain support coverage passes, but the count is being drawn with the weight piled on one end of the range instead of uniformly across it, which is a CRYPTO distribution the document never declared — map[14:1677 15:154 16:169]` / wire (set 4): `in 1000 dials only 93 payload(s) carried 15 CRYPTO frame(s) — a count the spec declares, in the range 14..16 — and a uniform draw over 3 values puts about 333 there: every declared count still reaches the wire, so plain support coverage passes, but the count is being drawn with the weight piled on one end of the range instead of uniformly across it, which is a CRYPTO distribution the document never declared — map[14:821 15:93 16:86]` / Sightglass: **GREEN, and that is recorded rather than hidden** — see the scope note below |
| E30r | the same WEIGHTED DRAW on **PADDING**. **GREEN at the Sightglass site**, same reason as E30l/E30n. | `TestUQUICRandomFramesHonoursTheDeclaredFrameBounds` set 4 (builder), `TestUTransportInitialFrameCountsComeFromTheSpecsBounds` set 4 (wire) | builder (set 4): `in 2000 builds only 175 carried exactly 3 PADDING run(s) — a count strictly inside the declared range 2..4 — and at least 300 are expected on this separator-saturated set (measured 624..763 over 300 trials of 2000 builds, against 47..90 for a two-valued draw): both declared endpoints are still reached, so every end-of-range assertion above passes, but the count is not being drawn UNIFORMLY across the range — it is coming from a strict subset of it, or from it with the weight piled on the ends, which is what a coin flip between MinPADDING and MaxPADDING looks like; the document declares 3 values and every Initial this profile sends carries a PADDING shape drawn from fewer — map[1:16 2:1660 3:175 4:149]` / wire (set 4): `in 1000 dials only 84 Initial(s) carried exactly 3 PADDING run(s) — a count strictly inside the declared range 2..4 — and at least 150 are expected on this separator-saturated set: both declared endpoints still reach the wire, so every end-of-range assertion above passes, but the count that reaches the packer is not drawn UNIFORMLY across the range — it comes from a strict subset of it, or from it with the weight piled on the ends, which is what a coin flip between MinPADDING and MaxPADDING looks like on the wire — map[1:5 2:838 3:84 4:73]` / Sightglass: **GREEN, and that is recorded rather than hidden** — see the scope note below |
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
`u_transport.go:107.2,107.101 1 1` and `u_transport.go:108.3,111.1 1 0`. (Earlier revisions of this
paragraph and of §3 cited `u_transport.go:91`, which is `if err := t.init(true); err != nil {` — the
line the check follows, not the check. The block ids above are copied from the profile §3's command
writes.)

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

The fix was the same shape as E3a's and E5/E6's: drive TWO bound sets that share no value, at the
builder (`TestUQUICRandomFramesHonoursTheDeclaredFrameBounds`, 120 builds each) and on the wire
through a real `DialEarly` (`TestUTransportInitialFrameCountsComeFromTheSpecsBounds`). **It was not
enough, and the next section says exactly how much it missed.**

### The FOURTH sweep: a range is not a guard for a range

A certifier attacked E30a/E30b the way this table has been attacked four times now, and found that
both guards asserted only `Min <= x <= Max`. **Every constant inside the declared range satisfies
that**, so the guard caught a builder that ignored the profile and missed one that read only HALF of
it — which is the more likely defect, because it is what a careless edit produces. Three
single-factor mutations, each applied ALONE to `v1.0.10-sightglass.9` and each leaving the WHOLE root
package green:

```
u_quic_frames.go:202  randUint64(uint64(q.MinPADDING), uint64(q.MaxPADDING)) -> randUint64(uint64(q.MaxPADDING), uint64(q.MaxPADDING))   ok 21.318s
u_quic_frames.go:202  randUint64(uint64(q.MinPADDING), uint64(q.MaxPADDING)) -> randUint64(uint64(q.MinPADDING), uint64(q.MinPADDING))   ok 21.344s
u_quic_frames.go:188  randUint64(uint64(q.MinPING), uint64(q.MaxPING))       -> randUint64(uint64(q.MinPING), uint64(q.MinPING))         ok 21.251s
```

The CRYPTO half was already immune, and the reason is instructive: it asserted the DISTRIBUTION
(`len(cryptoCounts) > 1`) rather than the range. E30b's old row claimed more than it covered — its
mutation `randUint64(2, 2)` is a constant OUTSIDE the declared `MinPADDING 4`, which the range
assertions do catch — and that row has been replaced.

All six bounds were then guarded one at a time by distribution — but only against a pin at an
ENDPOINT, which the FIFTH sweep found out, below.

### The FIFTH sweep: a one-sided distribution bound is not a guard for a range either

Two mutations of `u_quic_frames.go:202` that the fourth sweep's PADDING assertions could not see, each
applied ALONE by a certifier, with the tests of the fourth sweep in place:

```go
lo, hi := uint64(q.MinPADDING), uint64(q.MaxPADDING)
if hi > lo+1 { lo, hi = lo+1, hi-1 }                 // SUB-RANGE: NEITHER declared endpoint reaches the wire
numPADDING, err := randUint64(lo, hi)

mid := (uint64(q.MinPADDING) + uint64(q.MaxPADDING)) / 2
numPADDING, err := randUint64(mid, mid)              // MID-PIN: a constant strictly inside the range
```

The sub-range was green at all three sites (builder 3/3, wire 3/3, Sightglass with
`PADDING runs map[2:5 3:44 4:63 5:60 6:23 7:5]` against a declared 3..8). The mid-pin was green in
Sightglass (`map[2:10 3:39 4:93 5:58]`, i.e. a CONSTANT five PADDING frames per Initial) and green at
the builder in two runs of three. Both still VARY build to build, because PADDING runs merge, so
every "the count is not a single value" assertion passed.

**What the fourth sweep got wrong** is that both of its PADDING assertions were ONE-SIDED — "some
build carries MORE than `MinPADDING` runs" and "enough builds carry NO MORE than `MinPADDING` runs" —
and a constant in the middle satisfies both. The exact form (`the ceiling must be REACHED`) is the
one that separates it, and the reason the fourth sweep did not use it is real: on its bound sets the
ceiling was not reachable. A third bound set was added to make it reachable.

**The four bound sets and what each carries**, in both the builder test and the wire test. The table
rows below name them by these numbers.

| set | builder bounds | wire bounds | n | what it decides |
|---|---|---|---|---|
| 1 | CRYPTO 2..2, PING 1..1, PADDING 1..1 | CRYPTO 4..5, PING 1..1, PADDING 1..1 | 120 / 1 | every bound pinned; one build/dial decides the per-packet bounds |
| 2 | CRYPTO 6..12, PING 4..7, PADDING 4..9 | CRYPTO 9..12, PING 4..7, PADDING 3..6 | 120 / 200 | wide ranges, FEW separators; CRYPTO/PING exactly, PADDING only against an endpoint pin |
| 3 | CRYPTO 14..16, PING 18..22, PADDING 2..4 | the same | 120 / 200 | SEPARATOR-RICH: 32..38 separators against at most 4 PADDING frames, so the PADDING ceiling is exactly reachable and is asserted as an EQUALITY |
| 4 | CRYPTO 14..16, PING 148..152, PADDING 2..4 | the same | 2000 / 1000 | SEPARATOR-SATURATED: 162..168 separators against at most 4 PADDING frames, so merging is rare (measured P(4 runs \| 4 frames) = 0.933 against 0.718 on set 3) and the INTERIOR of the PADDING range becomes observable — which is the only thing that separates a two-valued draw. Its sample count is what lets it also carry the n/2w uniformity floor (E30p/E30q) |

No single constant satisfies all four (set 1 declares PADDING 1..1, set 2 declares 4..9; PING 1..1
against 4..7; CRYPTO 2..2 against 6..12).

* **CRYPTO and PING frames are counted EXACTLY off the decrypted wire** — a PING is one `0x01` byte,
  a CRYPTO frame carries its own length — so both ENDS of each declared range must be REACHED, not
  merely respected. For those two frame types a count pinned anywhere inside the range, a mid-pin and
  a sub-range all fail one of the two equalities with probability 1 (E30a..E30d, E30g..E30j). **A
  two-valued draw fails NEITHER equality** — it reaches both ends by construction — which is what the
  sixth sweep found (E30m, E30o); the assertion that catches it is on the SUPPORT, `every count the
  spec declares was actually drawn`, and the one that catches a full-support draw with the weight
  piled on one end is the n/2w population floor on set 4 (E30p, E30q).
* **PADDING runs MERGE**: the builder shuffles its PADDING frames in among the others and two that
  land side by side read back as ONE run, because QUIC's PADDING frame is a single zero byte and no
  reader can tell four in one frame from four one-byte frames. So `runs <= frames emitted`, always,
  and the ceiling is reachable only where the separators outnumber the PADDING frames. **On set 3 they
  do**, and the ceiling is therefore asserted as `maxRuns == MaxPADDING`, which kills the floor pin,
  the mid-pin and the sub-range at once (E30f, E30k, E30l). **On set 2 they do not** — the ceiling is
  reached in 8 of 60 trials at the builder and 4% of dials on the wire — so set 2 keeps the weak
  lower bound and says so in the test's own header comment. The CEILING pin is killed on both sets by
  the at-or-below count (E30e). **Set 3 still cannot see a two-valued draw**, because merging
  manufactures an interior run count out of the top mode: measured over 2000 trials of 120 builds the
  interior bucket holds 30..62 under the real draw and 6..29 under the bimodal one, populations that
  TOUCH. **Set 4 can**: 57..108 against 1..18 at 240 builds, 624..763 against 47..90 at 2000, so the
  interior is asserted as a POPULATION there (E30n, E30r).

Measured on this machine, 120 builds and 200 dials per trial, the mutations emulated exactly (a pin
at `k` is the degenerate range `k..k`, which is the draw the mutated `randUint64` makes):

```
builder set 3 (PADDING 2..4)   max runs in a trial   builds with runs <= MinPADDING   (200 trials)
  real builder                 4 in 200/200          35..60
  pinned at MaxPADDING         4 in 200/200           0..8      <- killed by the at-or-below count (>= 20)
  pinned at MinPADDING         2 always             120         <- killed by maxRuns == 4
  mid-pin / sub-range          3 always               9..25     <- killed by maxRuns == 4

wire set 3 (PADDING 2..4)      max runs in a trial   dials with runs <= MinPADDING    (20 trials)
  real builder                 4 in 20/20            69..88
  pinned at MaxPADDING         4 in 20/20             1..10     <- killed by the at-or-below count (>= 45)
  pinned at MinPADDING         2 always             200         <- killed by maxRuns == 4
  mid-pin / sub-range          3 always              23..43     <- killed by maxRuns == 4
```

**A LOOSENING from the fourth sweep, disclosed rather than left in the diff.** That round widened the
builder's set 2 from `MinPADDING 4` to `2` and the wire's from `MinPADDING 3, MaxPADDING 6` to
`2, 8`, which silently weakened two pre-existing ABSOLUTE assertions: "some build carries at least 4
runs" became "more than 2", and the per-dial ceiling `runs <= 6` became `runs <= 8`. Set 3 now carries
the strong assertion, so both sets are back to their original, tighter bounds (builder `PADDING 4..9`,
wire `PADDING 3..6`) — a NARROWING relative to the tag this round starts from, and a restoration
relative to the one before it.

**Scope note, stated because an earlier revision claimed more than it had.** `min_padding` and
`max_padding` are guarded at THREE sites against a pin at either endpoint and against a mid-range
constant, and at the TWO FORK sites against a sub-range draw, a two-valued draw and a weighted draw.
They are **NOT** guarded at the Sightglass site against any draw whose SUPPORT is a strict subset of
the declared range: chrome-152 declares PADDING 3..8 against only 5..27 separators, so merging makes
the declared ceiling unreachable there (8 runs occur about once in 200 Initials) and neither a 4..7
draw nor a coin flip over {3,8} is distinguishable from 3..8 by any observable measured — E30l and
E30n, both recorded GREEN, the second with `PADDING runs map[1:7 2:64 3:136 4:17 5:69 6:64 7:31 8:12]
(207 at or below min_padding=3, 60 required; busiest 8 runs, more than the midpoint 5 required)`. The
exact-ceiling equality and the interior population that DO separate them need a separator-rich and a
separator-saturated bound set, and this repository's Sightglass-side test may only drive the SHIPPED
document (HR-1/HR-5), so both assertions live in the fork, at both fork sites. `docs/tasks.json`
T0517 tracks the residual and names what would unblock it.

**A second Sightglass-side residual, same shape, disclosed for the same reason.** A draw over the
FULL declared support with the weight piled on one end (E30p, E30q) is red at the fork and GREEN at
the Sightglass site, for PING and for CRYPTO. Closing it needs a per-count POPULATION floor, and a
floor is only a guard when it sits many sigma below the bucket mean. chrome-152's ranges are wide —
10 declared PING counts and 14 declared CRYPTO counts — so 400 cold Initials give bucket means of ~40
and ~29 (measured thinnest buckets over five clean runs: 25..33 and 17..23) against ~7..15 and ~4..11
under the mutation. No floor separates those two populations without a flake budget this repository
will not spend, and buying the margin with samples would mean thousands of cold Initials in a test
that runs in the default `go test ./...`. The floor therefore lives on set 4 of the two fork tests,
where the bound set is ours to choose: 5 declared PING counts over 2000 builds is a mean of 400
against a floor of 200, and the worst bucket in 300 trials was 339 — 11 sigma of margin, against the
100 per starved bucket the mutation leaves (measured 95, 96, 99, 105).

### The SIXTH sweep: bounding both ENDS of a distribution says nothing about its INTERIOR

Every assertion the fifth sweep added is an end-of-range assertion — `min == Min`, `max == Max`,
`maxRuns == MaxPADDING`, "enough builds at or below `MinPADDING`". A certifier defeated ALL of them,
at ALL THREE SITES, with one mutation applied alone and restored:

```go
pcoin, err := randUint64(0, 1)                       // u_quic_frames.go:188 — BIMODAL
numPING := uint64(q.MinPING)
if pcoin == 1 { numPING = uint64(q.MaxPING) }
// and the same shape at :202 for MinPADDING/MaxPADDING
```

Builder 3/3 PASS, wire 3/3 PASS, Sightglass `ok`. Both fields are still read and both ends still
reach the wire — which is precisely why the equalities cannot see it — and what leaves the socket is
a TWO-VALUED count where the document declares a range: under the chrome-152 form every Initial
carries either 1 or 10 PING frames and never 2..9.

**What replaced it, per frame type, and why PADDING needed a new bound set.**

* **PING and CRYPTO are counted exactly**, so the fix is free and total: every count the spec declares
  must actually have been drawn (`requireEveryDeclaredCountWasDrawn`). That kills a two-valued draw
  and every other strict-subset draw at once, on the sets already there. With `w = hi-lo+1` values and
  `n >= 120` draws the chance a uniform builder misses one is below 1e-8.
* **PADDING runs MERGE, so the obvious form of the same fix does not work.** "The histogram contains
  an interior value" is satisfied by a bimodal draw, because a merge turns one of the top mode's runs
  into an interior count. Measured, 2000 trials of 120 builds, the population of set 3's single
  interior bucket: **real 30..62, bimodal 6..29** — they touch, and no threshold separates them. Set 4
  raises the PING bound to 148..152, i.e. 162..168 separators against at most 4 PADDING frames, until
  an un-merged build is the common case; there the same measurement gives **real 57..108 against
  bimodal 1..18** at 240 builds and **624..763 against 47..90** at the 2000 builds set 4 ships, so
  the interior is asserted as a POPULATION (threshold 300 at the builder, 150 on the wire).
* **One mutation further out, tried and closed rather than left for the next sweep:** a draw over the
  FULL support with the weight piled on one end (three draws in four returning the floor). It reaches
  every declared count, so support coverage passes. Set 4's sample count buys a per-count floor of
  n/2w — a count may be at most twice under-represented — with 11 to 16 sigma of margin, and that is
  E30p/E30q/E30r. It is GREEN at the Sightglass site and the scope note above says why.

All twelve mutations of the fifth sweep were re-run against the guard this sweep leaves behind, and
all twelve are still red at the sites their rows name; the six new ones are E30m..E30r. The bound
sets 1..3 were not touched, so the earlier rows' bounds and their failure texts are the same
assertions on the same data.

Nothing in `u_quic_frames.go` changed in the fourth, fifth or sixth sweep. All three are GUARD
changes, and the coverage number is the proof that they had to be: fork-suite u-layer coverage is
**86.5% (351/406) before and after**, measured both ways by the command at the head of §3, because
the mutations these assertions catch were all inside branches the old tests already executed. A
coverage number could never have shown this gap.

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

**One with no possible test, plus five mutations recorded GREEN at one of their three sites — and the
honest form of the claim is a NUMBER and a table, not an absolute.** Six successive attacks on this
table have each found something (four elements in the first, three in the second, three plus a missing
row and a false sentence in the third, three single-factor pins in the fourth, a sub-range plus a
mid-pin in the fifth, and a two-valued draw at all three sites in the sixth), so "every element is
guarded" and "every element anyone has attacked is guarded" are both claims this document has been
wrong about. What it says instead is the checkable one: **every mutation in the table above is red at
the site(s) its row names, with the failure text recorded, and the five rows that are GREEN at the
Sightglass site (E30l, E30n, E30p, E30q, E30r — a PADDING sub-range, a two-valued PADDING draw, and
the three weighted draws) say so in the row and are measured in the scope notes above.**

Counting from the table: the four a certifier turned green against the first revision (E24 ii/iii,
E5 ii, E6 ii, E3c/E26), the three we then found ourselves (E27, E28, E29), the three the third sweep
found (E30a, E30b, E31), the three the FOURTH sweep found inside E30a/E30b's own guard (E30d, E30e,
E30f — the single-factor pins that a range assertion cannot see), the two the FIFTH sweep found
inside that guard in turn (E30k, E30l — the mid-pin and the sub-range, which a one-sided distribution
bound cannot see) and the two the SIXTH found inside THAT one (E30m, E30n — the two-valued draw,
which no end-of-range assertion can see) are all red at the fork, and all but the five Sightglass
columns named above are red everywhere their rows name. One element has no test that can go red at
all:

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

`go.mod` requires `github.com/Berserk-Automation-Hub/fhttp v0.6.9-sightglass.21` and
`github.com/Berserk-Automation-Hub/utls v1.7.8-sightglass.6` — the two versions
`Sightglass/go/go.mod` ships. There are no `replace` directives, here or in `Sightglass/go/go.mod`.
Checked mechanically, both sides, this round:

```
$ grep Berserk /tmp/quic-go-utls-fork/go.mod        fhttp v0.6.9-sightglass.21
                                                    utls  v1.7.8-sightglass.6
$ grep Berserk Sightglass/go/go.mod                 fhttp v0.6.9-sightglass.21
                                                    utls  v1.7.8-sightglass.6
$ grep -c '^replace' Sightglass/go/go.mod           0
```

**Both pins moved in `v1.0.10-sightglass.14`, and the second one was not optional.** Up to
`v1.0.10-sightglass.13` this file said fhttp `.11` and utls `.1` and both were true of `go.mod` —
but `Sightglass/go/go.mod` had moved fhttp to `.21`, so this fork's own suite was running against an
fhttp the product does not deploy. That is the harm `parity.TestForkGoModsDoNotPinOlderSiblingForks`
names, and it reported the pair as KNOWN drift under ledger T0521 rather than as a failure. Bumping
fhttp to `.21` forces the utls bump with it: fhttp `v0.6.9-sightglass.21`'s own `go.mod` requires
utls `v1.7.8-sightglass.6`, so minimal version selection builds this module against utls `.6`
whatever this file's `require` line says. Leaving `.1` written there would have been a line `go build`
silently overrides — the exact class of untrue documentation this file exists to stop. Both entries
for this fork are therefore gone from `knownSiblingPinDrift` in Sightglass, and T0521 is closed.

**Regression diff for the two pin bumps** (`go test ./... -count=1 -timeout 900s`, same machine, no
cached results — `grep -c '(cached)'` is 0 in all four runs):

```
                              run 1                       run 2
before  fhttp .11 / utls .1   26 ok   0 FAIL              26 ok   0 FAIL
after   fhttp .21 / utls .6   25 ok   1 FAIL              26 ok   0 FAIL
```

NEW failures: none that reproduce. The single failure was
`TestMITCorruptPackets/towards_the_client` in `integrationtests/self` —
`mitm_test.go:218: Received unexpected error: context deadline exceeded`, the subtest's own 1s
scaled budget — and it is a FOURTH member of the load-sensitive class §9.3 already lists, measured
rather than assumed:

```
$ go test ./integrationtests/self/ -run TestMITCorruptPackets -count=25
after  (fhttp .21 / utls .6)   ok  15.882s   25/25
before (fhttp .11 / utls .1)   ok  18.524s   25/25
```

The test corrupts a random byte of a randomly chosen packet (`mrand.IntN`) and then requires the
connection to complete inside `scaleDuration(time.Second)`, in a package whose whole `./...` run
executes beside twenty-five others. It passed 25 consecutive times on BOTH sides in isolation and the
second full `./...` run of the after side is clean, so the failure is not a consequence of either
pin; recording it here with both sides' numbers is the alternative to a green-suite claim.

**Tag sequence, stated because the shipped-path column cannot be measured before a tag exists.**
The shipped-path coverage figures in §3 can only be measured from the Sightglass repository AGAINST a
published tag, which is why the table has historically lagged a tag behind: `.8` carried the code and
test changes with three cells still placeholders, `.9` added the measured numbers, and `.9` is the
tag those numbers were taken at. `.10` through `.13` changed **no `.go` source file at all** —
`git diff --name-only v1.0.10-sightglass.9 HEAD` lists `u_quic_frames_test.go`, `u_transport_test.go`
and this file, and nothing else — so the shipped-path column measured at `.9` is still the column
`.13` produces, and it was re-run from the Sightglass repository to confirm rather than assumed
(`306/406`, with the four `u_transport.go` blocks §3 quotes reproducing exactly). `.14` is the tag
`Sightglass/go/go.mod` consumes; `.12` is superseded by `.13`, which corrects three measured numbers
in the two test files' comments and the two failure texts that quote one of them, and `.13` is
superseded by `.14`, which moves the two sibling-fork pins in §8 and changes **no `.go` file at
all** — `git diff --name-only v1.0.10-sightglass.13 HEAD` lists `go.mod`, `go.sum` and this file,
and nothing else, so the shipped-path column measured at `.9` is still the column `.14` produces.
The Go module proxy caches a tag's content immutably, so amending a published tag in place is never
an option once it has been fetched.

---

## 9. Verification

### 9.1 This fork

```
$ gofmt -l <every file this patch touches>      # clean (NOT gofmt -w across the tree: this fork
                                                #        promises a gofmt baseline identical to upstream)
$ go vet ./...                                  # clean
$ go test ./... -count=1                        # all packages ok, modulo the load flakes in §9.3
```

This round, by command, in `/tmp/quic-go-utls-fork`:

```
$ gofmt -l u_quic_frames_test.go u_transport_test.go       # clean (the only two files this round touches)
$ go vet ./...                                             # clean
$ go test ./... -count=1 -timeout 1800s                    # 26 ok, 0 FAIL, 0 cached
$ go test . ./internal/wire ./internal/handshake -count=2  # ok 38.627s / 0.742s / 0.684s
```

REGRESSION DIFF for this round, by command, rather than a green-suite claim: the same
`go test ./... -count=1 -timeout 1800s` with these two test files stashed (`git stash push`) and then
restored, nothing cached (`grep -c '(cached)'` = 0 on both runs), and the per-package verdict lines
diffed against each other —

```
BEFORE (v1.0.10-sightglass.11 tree)  26 ok, 0 FAIL, 0 cached
AFTER  (this round)                  26 ok, 0 FAIL, 0 cached
diff of the 26 verdict lines         empty  -> NEW failures: none
```

EIGHTEEN single-factor mutations of the three `randUint64` calls in `u_quic_frames.go` were then
applied ONE AT A TIME (`cp` backup, mutate, run, restore; `git status --short` clean of
`u_quic_frames.go` afterwards) and each was run against BOTH guard tests and against the Sightglass
site. All eighteen are red at both fork sites — the twelve from earlier sweeps re-run unchanged, plus
E30m..E30r — and fourteen are red in Sightglass as well; the five recorded GREEN there are E30l,
E30n, E30p, E30q and E30r, each with the measurement that explains it. The per-mutation failure text
is in rows E30a..E30r. The Sightglass column was produced through a temporary `GOWORK` overlay
pointing at this working tree, so `Sightglass/go/go.mod` was never edited to produce it
(`grep -n replace go/go.mod` finds only the two occurrences inside the header comment).

`-count=2` matters here: every assertion in these two tests is statistical (120 to 2000 builds at the
builder, 1 to 1000 dials on the wire), so a guard that passes once and fails on repeat would be the
exact failure mode this repository has had before. The margins are printed by the tests themselves on
every run — see the `t.Logf` census in both, and the Sightglass census now prints the THINNEST
declared bucket explicitly, because that single number is what the support assertions actually run
on. Every threshold in this round was set from a measured distribution, not from a model: 2000 trials
for the interior-bucket populations, 300 trials for the per-count floors.

Fork-suite u-layer coverage is **86.5% (351/406) before and after**, measured both ways by the
command at the head of §3. This round adds no statements to the fork's source; it replaces range
assertions with distribution assertions over code the old tests already executed, which is precisely
why no coverage number could have revealed the gap.

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
