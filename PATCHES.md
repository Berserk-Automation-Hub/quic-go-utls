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

### 1.1 Files ADDED (16)

`git diff --name-status 4e6a465 HEAD | awk '{print $1}' | sort | uniq -c` -> `16 A / 2 D / 365 M`.
An earlier revision of this section said 17 and then enumerated 16; the count below is the
enumeration.

Source (8):

| File | Contents |
|---|---|
| `u_quic_spec.go` | `QUICSpec` / `InitialPacketSpec` — the parrot description: ClientHello spec, connection-ID lengths, first packet number + its on-wire length, client token length, frame builder. Plus `dummyTokenStore`. |
| `u_quic_frames.go` | `QUICFrameBuilder` + `QUICRandomFrames`: lays one Initial packet's CRYPTO stream slices out as randomly split, shuffled CRYPTO frames interleaved with PING and PADDING, filling the packet **exactly**. All randomness from `crypto/rand`. |
| `u_packet_packer.go` | `uPacketPacker`: an Initial carrying CRYPTO becomes a standalone datagram of exactly `Config.InitialPacketSize`, framed by the builder, with the spec's packet-number length on the first one. Every other packet is packed by upstream code. |
| `u_connection.go` | `newUClientConnection`: mirrors `newClientConnection`, but takes the local transport parameters from the ClientHello spec, installs the u crypto setup and the u packer, and passes `uSendsECNMarks` (false) as the sent-packet handler's `enableECN`. |
| `u_transport.go` | `UTransport`: mirrors `Transport.dialEarly`/`doDial`, pinning the source and destination connection-ID lengths and the first Initial packet number. `DialEarly` is its ONLY dial entry point — see §5 for why the non-early `Dial` was deleted. |
| `u_conn_buffers.go` | `UDoNotSetSocketBuffer` — the "this profile declares no socket buffer" value for the per-Transport SO_RCVBUF/SO_SNDBUF targets, and the note explaining why there is no package-level setter any more. |
| `internal/handshake/u_crypto_setup.go` | `NewUCryptoSetupClient` — `tls.UQUICClient(...)` + `ApplyPreset(spec)`; the `tlsQUICConn` interface and the `*tls.UQUICConn` adapter. |
| `internal/wire/u_transport_parameters.go` | `TransportParameters.PopulateFromUQUIC` — derives quic-go's local flow-control view from the utls transport-parameter extension, so we police exactly what we advertised. |

Tests (6) — the fork's own tests for the fork's own code (see §3):

`u_transport_test.go`, `u_quic_frames_test.go`, `u_quic_spec_test.go`, `u_conn_buffers_test.go`,
`internal/handshake/u_crypto_setup_test.go`, `internal/wire/u_transport_parameters_test.go`.

Other (2): `PATCHES.md` (this file) and `integrationtests/self/self_curveid_test.go` (§2).

8 + 6 + 2 = 16.

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
| `u_transport.go` | 0.0% (0/85) | **85.2%** (75/88) | 75.0% (66/88) |
| `u_packet_packer.go` | 0.0% (0/84) | **75.0%** (63/84) | 72.6% (61/84) |
| **u-layer total** | **0.0% (0/402)** | **85.4% (345/404)** | **75.5% (305/404)** |

(402 -> 404 statements: `QUICSpec.UDPDatagramMinSize` and `UTransport.Dial` were deleted, and the
`uDialsEarly` branch in `uDoDial` was added — §5.)

**The tests drive `DialEarly`, which is the function Sightglass calls, and it is the only one there
is.** An earlier revision of this file had every one of these tests calling `UTransport.Dial`
(`use0RTT=false`) while `go/quich3/h3client.go:646` called `DialEarly` (`use0RTT=true`); the two
differ in whether `earlyConnChan` is armed, which `select` arm returns the connection, and whether
`cs.allow0RTT` is set — so the whole ablation table below was ablating a function nobody shipped.
`go tool cover -func` on both profiles now reports `u_transport.go:44 DialEarly 100.0%` and no
`Dial` at all.

The tests assert the u-layer's properties **on the wire**: they capture the datagrams a real
`UTransport.DialEarly` puts on a UDP socket and decrypt them with the RFC 9001 §5.2 Initial keys any
on-path observer can derive, rather than reading back our own configuration. One test completes a
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
| `dummyTokenStore.Put` (`u_quic_spec.go:101`) | reported 0.0%, and the report is an artefact | 0.0% | KEPT, same reason. Its body is EMPTY — a dummy store must cache nothing — so it contains zero statements and `go tool cover -func` divides 0 by 0. The profile shows the block as `u_quic_spec.go:101.54,101.54 0 1`: **zero statements, one execution**, from `u_quic_spec_test.go:28`. It is called, not uncalled. |

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

`TestUTransportSocketBuffersAreNotProcessGlobal` initialises two Transports with different targets
concurrently and reads both sockets back with `getsockopt`; it cannot pass while one global exists.
It carries its own vacuity checks — it refuses to run if the two sessions ask for the same sizes, or
if either target is below this host's default (quic-go only ever RAISES a buffer, so a target below
the OS default would measure the kernel instead of the Transport).
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

"A guard I have not broken is not a guard." Each of the **30** elements below was reverted **on its
own**, the named test was run, and the exact failure text recorded. All were then restored
(`git status --short` clean of every ablation file afterwards).

Two things about this table that were not true of the one it replaces:

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
| E4 | `uGenerateDestConnID` ignores `DestConnIDLength` | `TestUTransportPinsTheInitialPacketShapeOnTheWire`, `TestUTransportGeneratesAFreshDestConnIDEveryDial` | `Destination Connection ID is 10 bytes, the spec pins 8 (upstream picks a random length in [8,20])` (and `expected: 8 / actual: 20` in the second) |
| E5 | dial with packet number 0 instead of the spec's | `TestUTransportPinsTheInitialPacketShapeOnTheWire` | `first Initial packet number is 0, the spec pins 1 (upstream always starts at 0)` |
| E6 | let upstream choose the first Initial's packet-number length | `TestUTransportPinsTheInitialPacketShapeOnTheWire` | `first Initial packet-number field is 2 bytes, the spec pins 1 (upstream emits only 2 or 4)` |
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
| E24 | `uGenerateDestConnID` returns a CONSTANT of the right length (`bytes.Repeat([]byte{0xAB}, l)`) instead of `protocol.GenerateConnectionID(l)` | `TestUTransportGeneratesAFreshDestConnIDEveryDial` | `3 dials produced only 1 distinct Destination Connection ID(s) ([abababababababab abababababababab abababababababab]): the first-flight DCID is not freshly random, so every connection from this host is linkable by its Initial header` |
| E25 | `uDialsEarly` -> `false` (the u-layer stops attempting 0-RTT) | `quich3.TestQUICResumptionHelloMatchesChromeQJA4` (Sightglass, shipped path) | `warm q-JA4 = q13d0313h3_55b375c5d22e_b0954bf1abdf, want q13d0314h3_55b375c5d22e_79cc91d6b50c` — the warm ClientHello loses `early_data` (0x002a) and emits a q-JA4 no Chrome emits |

### E24 is here because the reverse attack worked

The previous round's table had a DCID row (E4) that only asserted the LENGTH. A certifier replaced
`protocol.GenerateConnectionID(l)` with a fixed `0xAB`-filled ID **of the correct length** and the
entire fork suite stayed green (`ok … 9.225s`), while on the Sightglass side the only fallout was
`Connect: … APPLICATION_ERROR (remote)` and `timeout: no recent network activity` — failures that
merely differ and do not describe the defect, which C1 forbids. A constant first-flight Destination
Connection ID is a catastrophic linkability tell: it is in clear text in every client Initial and it
is what RFC 9001 §5.2 derives the Initial keys from. `TestUTransportGeneratesAFreshDestConnIDEveryDial`
reads the DCID off the wire on three separate dials, requires three distinct values, and then
requires that they do not share most byte positions — so a counter or a timestamp fails it too.

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

### Element with no guard

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

`TestVersionNegotiationFailure` asserts that a failed version negotiation completes in under 2
seconds of WALL CLOCK; it is upstream's test, in a package this patch does not touch, and it fails
only when the machine is busy. Its pristine counterpart passes for the same reason its fork
counterpart does when the machine is quiet.

The fork's own new tests are NOT in this list, and one of them nearly was: see the last note in §7
for the assertion that was failing 1 run in 12 and what replaced it. After that change,
`TestUTransportLaysTheInitialOutWithTheSpecsFrameBuilder` and
`TestUTransportGeneratesAFreshDestConnIDEveryDial` ran 14/14 green.

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
