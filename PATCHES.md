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

Source (8):

| File | Contents |
|---|---|
| `u_quic_spec.go` | `QUICSpec` / `InitialPacketSpec` — the parrot description: ClientHello spec, connection-ID lengths, first packet number + its on-wire length, client token length, frame builder. Plus `dummyTokenStore`. |
| `u_quic_frames.go` | `QUICFrameBuilder` + `QUICRandomFrames`: lays one Initial packet's CRYPTO stream slices out as randomly split, shuffled CRYPTO frames interleaved with PING and PADDING, filling the packet **exactly**. All randomness from `crypto/rand`. |
| `u_packet_packer.go` | `uPacketPacker`: an Initial carrying CRYPTO becomes a standalone datagram of exactly `Config.InitialPacketSize`, framed by the builder, with the spec's packet-number length on the first one. Every other packet is packed by upstream code. |
| `u_connection.go` | `newUClientConnection`: mirrors `newClientConnection`, but takes the local transport parameters from the ClientHello spec, installs the u crypto setup and the u packer, and passes `uSendsECNMarks` (false) as the sent-packet handler's `enableECN`. |
| `u_transport.go` | `UTransport`: mirrors `Transport.dial`/`doDial`, pinning the source and destination connection-ID lengths and the first Initial packet number. |
| `u_conn_buffers.go` | `UDoNotSetSocketBuffer` — the "this profile declares no socket buffer" value for the per-Transport SO_RCVBUF/SO_SNDBUF targets, and the note explaining why there is no package-level setter any more. |
| `internal/handshake/u_crypto_setup.go` | `NewUCryptoSetupClient` — `tls.UQUICClient(...)` + `ApplyPreset(spec)`; the `tlsQUICConn` interface and the `*tls.UQUICConn` adapter. |
| `internal/wire/u_transport_parameters.go` | `TransportParameters.PopulateFromUQUIC` — derives quic-go's local flow-control view from the utls transport-parameter extension, so we police exactly what we advertised. |

Tests (6) — the fork's own tests for the fork's own code (see §3):

`u_transport_test.go`, `u_quic_frames_test.go`, `u_quic_spec_test.go`, `u_conn_buffers_test.go`,
`internal/handshake/u_crypto_setup_test.go`, `internal/wire/u_transport_parameters_test.go`.

Other (3): `PATCHES.md` (this file), `integrationtests/self/self_curveid_test.go` (§2), and — for
completeness — nothing else.

### 1.2 Files DELETED (2)

`integrationtests/self/self_go124_test.go` and `integrationtests/self/self_go125_test.go`, replaced
by `self_curveid_test.go`. See §2.

### 1.3 Upstream files MODIFIED with a behavioural change (7)

`git diff 4e6a465 HEAD` touches 365 upstream files. **354 of them change nothing but import paths**
(`github.com/bogdanfinn/...` -> `github.com/Berserk-Automation-Hub/...`), which is the module rename
and nothing else. Earlier revisions of this file claimed "two upstream files are touched"; that was
never true. The files with a real change are:

| File | Change |
|---|---|
| `go.mod`, `go.sum` | module path, `go 1.27.0`, and the fork dependencies above. |
| `internal/handshake/crypto_setup.go` | the field `conn *tls.QUICConn` is widened to the interface `conn tlsQUICConn` (declared in the new `u_crypto_setup.go`), so the same crypto setup can drive either `*tls.QUICConn` (upstream, unchanged) or utls' `*tls.UQUICConn`. `var _ tlsQUICConn = (*tls.QUICConn)(nil)` keeps the upstream path type-checked. **This is the only non-test upstream file whose behaviour the u-layer touches at all.** |
| `transport.go` | adds `Transport.UDesiredReceiveBufferSize` / `UDesiredSendBufferSize` and passes them to `wrapConnWithBuffers` in `init`. |
| `sys_conn.go` | `wrapConn(pc)` becomes a wrapper around a new `wrapConnWithBuffers(pc, wantReceive, wantSend)`. |
| `sys_conn_buffers.go` | `setReceiveBuffer(c)` becomes a wrapper around a new `setReceiveBufferTo(c, want)` with tri-state `want` (see §4). |
| `sys_conn_buffers_write.go` | the `go:generate`d send-side twin of the above, regenerated by hand to stay identical to what the generator would emit. |
| `integrationtests/self/handshake_drop_test.go` | test-only: the negotiated-curve assertion becomes unconditional and calls the new `getCurveID(t, …)`. See §2. |

Two more files (`connection.go`, `connection_test.go`) contain no change other than four comment
URLs that the rename sed rewrote from `github.com/bogdanfinn/quic-go-utls/pull/NNNN` to our org.
Those PR numbers are quic-go's, so they are dead links in bogdanfinn's tree too; they are left as
upstream had them rather than touched, and recorded here so the diff has no unexplained line.

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
                              tests executed   pass   skip   fail
before (and in pristine)                   0      0      0      0   [build failed]
after                                    365    365      0      0
```

`134` top-level, `365` including subtests — the exact population the audit counted. There are **no**
skips: the package runs whole.

---

## 3. The u-layer had no tests of its own. Now it does.

Coverage of the eight u-layer source files, measured with
`go test . ./internal/wire ./internal/handshake -coverpkg=./...`:

| File | before | after |
|---|---|---|
| `internal/handshake/u_crypto_setup.go` | 0.0% | 100.0% (25/25) |
| `internal/wire/u_transport_parameters.go` | 0.0% | 96.9% (31/32) |
| `u_quic_spec.go` | 0.0% | 91.7% (11/12) |
| `u_connection.go` | 0.0% | 87.3% (55/63) |
| `u_quic_frames.go` | 0.0% | 85.0% (85/100) |
| `u_transport.go` | 0.0% | 82.4% (70/85) |
| `u_packet_packer.go` | 0.0% | 75.0% (63/84) |
| **u-layer total** | **0.0% (0/402)** | **84.8% (340/401)** |

(401 vs 402 statements: `QUICSpec.UDPDatagramMinSize` was deleted — §5.)

The tests assert the u-layer's properties **on the wire**: they capture the datagrams a real
`UTransport.Dial` puts on a UDP socket and decrypt them with the RFC 9001 §5.2 Initial keys any
on-path observer can derive, rather than reading back our own configuration. One test completes a
full handshake against a stock quic-go server and moves 1 MB of stream data over it. **No value in
any of these tests is a captured browser fingerprint (HR-1) and none is claimed to be one**: the
specs are synthetic, deliberately unlike any browser, and what they prove is the MECHANISM — that
whatever a profile pins is what leaves the socket. The browser's values live in a Sightglass profile
document; this fork contains no engine identity (HR-5).

---

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
A second, compile-time guard sits in the same file:

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

Everything else in the u-layer has a caller reachable from `sightglass.NewSessionFactory ->
Session.Do`: `quich3.Scope.H3Client -> h3client.dial -> quic.UTransport.DialEarly -> dialSpec ->
uDoDial -> newUClientConnection -> {NewUCryptoSetupClient, PopulateFromUQUIC, newUPacketPacker ->
QUICRandomFrames.Build}`, with `Transport.init` applying the socket buffers on the way in.

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

"A guard I have not broken is not a guard." Every element below was reverted **on its own**, the
suite was run, and the exact failure text recorded. All were then restored.

| # | Element reverted | Test that went red | Failure text |
|---|---|---|---|
| E1a | `self_curveid_test.go` -> upstream's `//go:build go1.25` pair | whole package | `integrationtests/self/self_go125_test.go:8:19: connState.CurveID undefined (type "…/utls".ConnectionState has no field or method CurveID)` / `FAIL … [build failed]` |
| E1b | `getCurveID` returns 0 instead of reading the field | `TestHandshakeWithPacketLoss/drop_1st_packet_in_direction_to_client/*` | `the handshake negotiated key-exchange group 0x0000, want CurveP384 (0x0018) — the client config restricts CurvePreferences to it` |
| E2a | `setReceiveBufferTo`/`setSendBufferTo` ignore the Transport's value | `TestUTransportSocketBuffersComeFromTheTransport`, `…AreNotProcessGlobal`, `…AbsentMeansUntouched` | `SO_RCVBUF on the wrapped socket is 7340032, the Transport asked for 1048576` / `session 0's socket has SO_RCVBUF 7340032 but its own Transport asked for 1048576: the other session's value leaked across` |
| E2b | drop the `want < 0` (absent) branch | `TestUTransportSocketBuffersAbsentMeansUntouched` | `SO_RCVBUF changed from 786896 to 7340032 although the profile declares none` |
| E2c | `protocol.DesiredReceiveBufferSize` back to a `var` | whole package | `./u_conn_buffers_test.go:29:6: protocol.DesiredReceiveBufferSize (variable of type int) is not constant` |
| E3a | drop the spec's `SrcConnIDLength` pin | `TestUTransportPinsWhateverSourceConnectionIDLengthTheSpecAsks` | `the spec asked for a 3 byte source connection ID and the wire carries 0` |
| E3b | `t.init(false)` — upstream's refusal of a zero-length SCID | `TestUTransportPinsTheInitialPacketShapeOnTheWire` | `Source Connection ID is 4 bytes, the spec pins 0 (upstream defaults to 4)` |
| E4 | `uGenerateDestConnID` ignores `DestConnIDLength` | `TestUTransportPinsTheInitialPacketShapeOnTheWire` | `Destination Connection ID is 10 bytes, the spec pins 8 (upstream picks a random length in [8,20])` |
| E5 | dial with packet number 0 instead of the spec's | `TestUTransportPinsTheInitialPacketShapeOnTheWire` | `first Initial packet number is 0, the spec pins 1 (upstream always starts at 0)` |
| E6 | let upstream choose the first Initial's packet-number length | `TestUTransportPinsTheInitialPacketShapeOnTheWire` | `first Initial packet-number field is 2 bytes, the spec pins 1 (upstream emits only 2 or 4)` |
| E7 | `useSpecInitial` always false — upstream framing | `TestUTransportLaysTheInitialOutWithTheSpecsFrameBuilder` | `the Initial carries no PING frames: the spec's frame builder did not lay this packet out` |
| E8 | drop the `crypto/rand` Fisher-Yates shuffle | `TestUQUICRandomFramesShufflesTheFrameOrder` | `in 60 builds the lowest-offset CRYPTO frame was always at position map[0:60]: the frame order is not shuffled, so the Initial layout is a constant tell` |
| E9 | do not call `PopulateFromUQUIC` | `TestUTransportLocalFlowControlComesFromTheSpec` | `quic-go believes it advertised initial_max_data 262144; the ClientHello spec says 15728640` |
| E9b | drop the empty-`initial_source_connection_id` write-back | `TestPopulateFromUQUICWritesBackAnEmptySourceConnectionID` | `the spec's empty initial_source_connection_id was not replaced with the connection's real one, so the peer would reject the handshake` |
| E10 | `uSendsECNMarks = true` | `TestUTransportDoesNotECNMarkWhatItSends`, `TestUTransportCompletesARealHandshake` | `the connection ECN-marks its 1-RTT packets; every datagram would leave the host with IP TOS 0x02` (`expected 0x0, actual 0x3`) |
| E11 | narrow `crypto_setup.go`'s `conn` back to `*tls.QUICConn` | `internal/handshake` | `internal/handshake/u_crypto_setup.go:76:12: cannot use uQUICConn{…} (value of struct type uQUICConn) as *"…/utls".QUICConn value in assignment` |
| E12 | packer emits an Initial 7 B short of the configured size | `TestUTransportPinsTheInitialPacketShapeOnTheWire` | `the dial put nothing on the wire; it failed with: INTERNAL_ERROR (local): quic u-layer BUG: Initial packet is 1243 B, want exactly 1250 B` |
| E13 | `uQUICTransportParameters` returns a zero value instead of an error | `TestUTransportLoudFailsWithoutTransportParameters` | `An error is expected but got nil.` |
| E14 | drop the nil-spec / nil-ClientHelloSpec checks in `dialSpec` | `TestUTransportRejectsAnIncompleteSpec` | `panic: runtime error: invalid memory address or nil pointer dereference … quic-go-utls.uQUICTransportParameters(…) u_connection.go:221` |
| E15 | accept a `DestConnIDLength` below RFC 9000's minimum | `TestUTransportRejectsAnUndiallableDestConnIDLength` | `expected: "quic u-layer: DestConnIDLength below the RFC 9000 minimum of 8" / actual: "context deadline exceeded"` |
| E16 | `QUICRandomFrames.validate` not called | `TestUQUICRandomFramesRejectsAnImpossibleShape/*` | `An error is expected but got nil.` (no-CRYPTO, no-PADDING cases) and `expected "…has a Min bound above its Max bound" / actual "quic u-layer: bad random range [5,4]"` |
| E17 | a declared `ClientTokenLength` installs no token store | `TestUSpecTokenLengthInstallsATokenStore` | `a spec declaring a client token length installed no token store` |
| E18 | ClientHello built from `tls.Config` rather than the spec | `TestUCryptoSetupClientHelloComesFromTheSpec` | `the ClientHello's cipher suites are not the spec's, in the spec's order: the hello was built from tls.Config` (`expected []uint16{0x1303,0x1302,0x1301} / actual []uint16{0x1301}`) |
| E19 | apply the TLS 1.3 floor BEFORE `ApplyPreset` (where `ApplyPreset` overwrites it) | `TestUCryptoSetupPinsTLS13RegardlessOfTheConfig/the_spec's_supported_versions_lists_TLS_1.2` | `Received unexpected error: CRYPTO_ERROR 0x150 (local): tls: Config MinVersion must be at least TLS 1.13` |
| E20 | do not clone the caller's `tls.Config` | `TestUCryptoSetupPinsTLS13RegardlessOfTheConfig/the_caller's_Config_says_TLS_1.2` | `NewUCryptoSetupClient mutated the CALLER's tls.Config (MinVersion is now 0x0304); it must clone it first` |
| E22 | drop the RFC 9000 §17.2 upper bound on `DestConnIDLength` | `TestUTransportRejectsAConnectionIDLengthAboveTheRFCMaximum/destination` | `panic: runtime error: slice bounds out of range [:21] with length 20 … internal/protocol.GenerateConnectionID(…) connection_id.go:44 … (*UTransport).uGenerateDestConnID u_transport.go:191` |
| E23 | drop the `SrcConnIDLength` range check | `TestUTransportRejectsAConnectionIDLengthAboveTheRFCMaximum/source` | same panic, from `Transport.init`'s connection-ID generator |
| E21 | drop `EnableSessionEvents` | `TestUCryptoSetupStoresAResumptionTicket` | `the cached session carries no quic-go session data: no QUICStoreSession event fired, so 0-RTT is structurally impossible on this connection` |

**E22/E23 were a real defect, and the panic above is the one the audit recorded from a profile
document.** RFC 9000 §17.2 caps a connection ID at 20 bytes and `protocol.GenerateConnectionID`
slices a fixed 20-byte array, so `http3.initial.dest_conn_id_length: 21` — a value a profile can
perfectly well contain — panicked inside `connection_id.go`, several frames below any code that
knows the word "profile". Both lengths now fail at the point where the document enters the library,
with the field named.

**E19 was a real defect, found by trying to ablate it.** The TLS 1.3 floor used to be written before
`uc.ApplyPreset(chs)`, and `ApplyPreset` -> `UConn.SetTLSVers` writes a `MinVersion` derived from the
SPEC onto the very `tls.Config` installed a line earlier. A profile whose `supported_versions` lists
TLS 1.2 alongside TLS 1.3 — an ordinary thing for a browser document to carry — therefore lowered
the local policy, and `UQUICConn.Start` refused the connection with `tls: Config MinVersion must be
at least TLS 1.13` before a byte reached the wire. The line is now applied after `ApplyPreset`, where
it is load-bearing. Nothing observable changes: the ClientHello bytes, `supported_versions` included,
come from the spec either way.

### Element with no guard

The **fhttp pin alignment** (§8) has no test that can go red, and that is not an oversight. Go's
minimal-version selection means a consumer that requires a newer fhttp gets the newer one regardless
of what this fork's `go.mod` says, so a stale pin here is invisible from outside. What it does affect
is which fhttp **this fork's own suite runs against** — i.e. whether the combination we test is the
combination Sightglass ships. That is a property of the `go.mod` text, checked mechanically, not
something a test can assert without hard-coding a version in the fork (which would be circular, and
would put a moving pin inside library code).

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
$ gofmt -l <every file this patch touches>      # clean
$ go vet ./...                                  # clean
$ go test ./... -count=1                        # all packages ok
```

### 9.2 Regression diff against pristine v1.0.10-utls

Baseline: a fresh clone of `bogdanfinn/quic-go-utls@v1.0.10-utls` with **only** `go 1.24.1 ->
1.27.0` (needed for `testing/synctest`, which `go 1.24.1` excludes; without it ten packages fail to
build for that one reason).

```
                                                pristine v1.0.10-utls   this fork
packages failing                                                    1           0
  integrationtests/self  [build failed: CurveID]                  yes          no  (fixed, §2)
```

**NEW failures introduced by this patch: none.**

### 9.3 Known flakiness in `integrationtests/self`, present on both sides

That package is newly RUNNING here, so its flakes are newly visible; they are not new. Both trees
were run repeatedly on the same machine:

```
this fork      23 full-package runs, 2 failures  (TestConnDataBlocked, packetization_test.go:220)
pristine       20 full-package runs, 1 failure   (TestHTTPSettings/server_settings)
```

Both failures occurred only while other `go test` processes were competing for CPU; 12 consecutive
quiet runs of each tree were clean, and `TestConnDataBlocked -count=15` in isolation is clean. They
are load-sensitive upstream flakes in upstream tests, in a package this patch does not otherwise
touch.

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
