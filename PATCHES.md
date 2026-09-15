# Vendored fork: `github.com/bogdanfinn/quic-go-utls` v1.0.9-utls

A copy of upstream `bogdanfinn/quic-go-utls@v1.0.9-utls` (tests, mocks, examples, integration tests,
fuzzing, interop, docs and `internal/mocks` pruned) plus an **additive browser-parroting "u-layer"**,
wired via `replace` in `../../go.mod`.

It exists so the whole library rides **one TLS/QUIC stack**: `tls-client`, `fhttp`, `tlsemu`,
`sightglass` and `quich3` all use `github.com/bogdanfinn/utls`. There is no second TLS
implementation to drift against.

```
$ go list -m all | grep -iE 'refraction|uquic|quic'
github.com/bogdanfinn/quic-go-utls v1.0.9-utls => ./third_party/quic-go-utls
github.com/quic-go/qpack v0.6.0
```

## Why a patch at all

Upstream `quic-go` builds its ClientHello from `tls.Config` and picks its own Initial-packet shape.
Neither can be made to look like a specific browser, and every one of the following is **passively
observable** (QUIC Initial packets are decryptable by anyone who sees the Destination Connection ID —
RFC 9001 §5.2):

| Property | Upstream quic-go | Chrome 152 (measured) |
|---|---|---|
| ClientHello bytes | Go's, from `tls.Config` | fixed extension set/order → q-JA4 `q13d0312h3_55b375c5d22e_178839b6cec1` |
| `quic_transport_parameters` body | quic-go's `wire.TransportParameters.Marshal` | Chrome's set, incl. `google_connection_options` 0x3128 and a GREASE parameter, order shuffled per connection |
| Destination Connection ID length | random 8..20 | **8** |
| Source Connection ID length | 4 (default) | **0** |
| First Initial packet number / length | 0, always ≥ 2-byte field | **1**, in a **1-byte** field |
| Initial datagram size | `Config.InitialPacketSize` (1280 default) | **1250, every time** |
| Initial frame layout | one CRYPTO frame + trailing PADDING | "chaos protected": out-of-order CRYPTO fragments interleaved with PING and PADDING |

Ground truth for the right-hand column, decrypted from the genuine-Chrome oracle capture with the
`quicfp` decoder (`reversing/oracle_verify/quicfp`, `QUICFP_FRAMES=1`):

```
[pkt] dcid=5a632d0f45dbb050 scidlen=0 pn=1 pnLen=1 tokenLen=0 pktBytes=1250
[frames] payload=1215B layout=PINGx1 PADDINGx169 CRYPTO(off=1048,len=257) PADDINGx1
  CRYPTO(off=1305,len=641) PINGx1 PADDINGx3 CRYPTO(off=0,len=42) PINGx2 PADDINGx51 CRYPTO(off=42,len=31)
[pkt] dcid=5a632d0f45dbb050 scidlen=0 pn=2 pnLen=2 tokenLen=0 pktBytes=1250
[frames] payload=1214B layout=PINGx1 CRYPTO(off=979,len=54) ... CRYPTO(off=73,len=82) PINGx1
```

## What the patch is

**Two upstream files are touched, by one line and one declaration-kind change respectively.**
Everything else is new files.

### Modified upstream file (1 of 2)

`internal/handshake/crypto_setup.go` — the field

```go
conn *tls.QUICConn
```

is widened to the interface `conn tlsQUICConn` (declared in the new `u_crypto_setup.go`) so the same
crypto setup can drive either `*tls.QUICConn` (upstream, unchanged behaviour) or utls'
`*tls.UQUICConn`, which emits a ClientHello built from a `*tls.ClientHelloSpec`. `var _ tlsQUICConn =
(*tls.QUICConn)(nil)` keeps the upstream path type-checked.

### Modified upstream file (2 of 2)

`internal/protocol/params.go` — `DesiredReceiveBufferSize` and `DesiredSendBufferSize` change from
`const` to `var` (values unchanged). Upstream asks the kernel for 7 MB of SO_RCVBUF **and** 7 MB of
SO_SNDBUF on every QUIC socket; Chrome pins both, to different values:

| Option | Chrome 152 | source | stock quic-go |
|---|---|---|---|
| `SO_RCVBUF` | 1048576 | `kQuicSocketReceiveBufferSize`, `net/quic/quic_context.h:105`, applied `quic_session_pool.cc:1212/1327` | 7340032 |
| `SO_SNDBUF` | 29040 | `quic::kMaxOutgoingPacketSize * 20` = 1452*20, `quic_session_pool.cc:1237/1349` | 7340032 |

These are the only two UDP socket options an application chooses, so a browser parrot pins them to
the browser's values. Making the two targets settable is the minimal way to do that: `wrapConn()`
reads them once, and quic-go only ever RAISES a buffer, so they cannot be lowered from outside.
Guarded by `quich3.TestChromeUDPSocketBufferSizes`, which asserts the values by **getsockopt
readback** on the socket a real dial used.

### New files (7)

| File | Contents |
|---|---|
| `u_quic_spec.go` | `QUICSpec` / `InitialPacketSpec` — the parrot description (ClientHello spec, connection-ID lengths, first packet number + length, token, frame builder). |
| `u_quic_frames.go` | `QUICFrameBuilder` + `QUICRandomFrames`: lays one Initial packet's CRYPTO stream slices out as randomly split, shuffled CRYPTO frames interleaved with PING and PADDING, filling the packet **exactly**. |
| `u_packet_packer.go` | `uPacketPacker`: for an Initial carrying CRYPTO it emits a standalone datagram of exactly `Config.InitialPacketSize`, framed by the builder, with the spec's packet-number length. Every other packet is packed by upstream code. |
| `u_connection.go` | `newUClientConnection`: mirrors `newClientConnection`, but takes the local transport parameters from the ClientHello spec, installs the u crypto setup + u packer, and passes `uSendsECNMarks` (false) as the sent-packet handler's `enableECN` — see below. |
| `u_transport.go` | `UTransport`: mirrors `Transport.dial`/`doDial`, pinning the source/destination connection-ID lengths and the first Initial packet number. |
| `internal/handshake/u_crypto_setup.go` | `NewUCryptoSetupClient` — `tls.UQUICClient(...)` + `ApplyPreset(spec)`; the `tlsQUICConn` interface and the `*tls.UQUICConn` adapter. |
| `internal/wire/u_transport_parameters.go` | `TransportParameters.PopulateFromUQUIC` — derives quic-go's local flow-control view from the utls transport-parameter extension, so we police exactly what we advertised. |
| `u_conn_buffers.go` | `SetDesiredBufferSizes` / `DesiredBufferSizes` — pin the browser's SO_RCVBUF/SO_SNDBUF targets before a `Transport` is created. |

Nothing in the server path, the congestion controller, the streams layer, `http3`, or the frame
codecs is touched.

### One behavioural deviation, inside a new file: no ECN marking (parity round 5)

`u_connection.go` passes `uSendsECNMarks` (a `false` constant) where upstream passes
`s.conn.capabilities().ECN`. Upstream runs RFC-9000 §13.4.2 ECN validation on every connection, so
every one-RTT datagram carries an `IP_TOS` control message with ECT(0) and leaves the host with IP
TOS `0x02`. Chrome never marks:

| | Chrome 152 | upstream quic-go |
|---|---|---|
| outgoing IP TOS byte | `0x00` on **444/444** datagrams across 13 connections (`fingerprints/_login/quic_login.pcap`) | `0x02` from the first one-RTT packet |
| why | `QuicPacketWriterParams::ecn_codepoint` defaults to `ECN_NOT_ECT` (`quic_packet_writer.h:45`) and `QuicConnection::SetFromConfig` only overrides it when the congestion controller opts in (`quic_connection.cc:473-477`); **every** sender Chrome ships returns `false` from `EnableECT0()/EnableECT1()` (`bbr2_sender.h:101-102`, `bbr_sender.h:142-143`, `bbr3_sender.h:97-98`, `tcp_cubic_sender_bytes.h:79-80`) | `ecnTracker.Mode()` returns ECT(0) while testing/capable (`internal/ackhandler/ecn.go:122-139`) |

Only the SEND side is disabled. Reception is untouched — `oobConn` still sets `IP_RECVTOS` and
`receivedPacketTracker` still counts ECT0/ECT1/CE off the wire, so our ACKs report ECN counts if a
server ever marks. That is exactly Chrome's asymmetry: `socket->SetRecvTos()` and nothing else
(`net/quic/quic_session_pool.cc:1228`).

Proven and ablation-proven by `quich3.TestNoECNMarksOnAnyDatagram`, which records the real `sendmsg`
control buffers over a full loopback handshake; reverting the constant makes it fail on datagram #3
with `tos=0x02`.

## Command-proven effect

From `go/`:

```
$ go build ./... && go vet ./... && go test ./...          # green

$ QUICH3_EMIT_PCAP=1 QUICH3_PCAP_OUT=/tmp/our.pcap go test ./quich3/ -run TestEmitInitialPCAP
$ cd ../reversing/oracle_verify/quicfp && QUICFP_FRAMES=1 go run . /tmp/our.pcap
  [pkt] dcid=b46341bab507b07f scidlen=0 pn=1 pnLen=1 tokenLen=0 pktBytes=1250
  [frames] payload=1215B layout=PINGx2 PADDINGx1 CRYPTO(off=426,len=143) PINGx1 CRYPTO(off=1035,len=3) ...
  [pkt] dcid=b46341bab507b07f scidlen=0 pn=2 pnLen=2 tokenLen=0 pktBytes=1250
  q-JA4 : q13d0312h3_55b375c5d22e_178839b6cec1     <- byte-identical to genuine Chrome 152
```

and, hermetically in CI (no network), `go test ./quich3/ -run TestInitialPacketShapeMatchesChrome`
decrypts our own Initials and asserts the whole right-hand column of the table above.

## Residual (HR-7 — NOT claimed as parity)

QUICHE's exact chaos-protector sequencing (which stream ranges land in which packet, and where the
split points fall) is not reproduced; both stacks randomize per connection, so only the shape is
comparable. Packet timing (pacing, ACK cadence, PMTU probing, retransmit timing) is quic-go's.

---

## Fork housekeeping (module path, current Go, restored upstream tests)

Sightglass consumes this fork by plain `require` with no `replace`, so the module path is the fork's
own and the utls/fhttp dependencies point at our forks of those:

```
module github.com/bogdanfinn/quic-go-utls -> github.com/Berserk-Automation-Hub/quic-go-utls
       github.com/bogdanfinn/utls  v1.7.8-barnius -> .../utls  v1.7.8-sightglass.1
       github.com/bogdanfinn/fhttp v0.6.9         -> .../fhttp v0.6.9-sightglass.1
go 1.24.1 -> 1.27.0
```

Based on **v1.0.10-utls**, the latest upstream, not the v1.0.9-utls Sightglass pinned. The patch
cherry-picked clean.

### One real fix, found by restoring the tests the vendored copy dropped

The socket-buffer patch turned `protocol.DesiredReceiveBufferSize` / `DesiredSendBufferSize` from
`const int` into `func() int` (so the value can be per-Transport instead of a package global — that
global was both a data race and a cross-profile fingerprint bleed). Six call sites in
`integrationtests/tools/proxy/proxy.go` still used them as values:

```
integrationtests/tools/proxy/proxy.go:175:33: cannot use protocol.DesiredReceiveBufferSize
    (value of type func() int) as int value in argument to p.Conn.SetReadBuffer
```

The vendored tree had no `integrationtests/`, so this never compiled anywhere and nobody saw it.
All six now call the function.

### Verification, against a pristine v1.0.10-utls baseline

```
fork:     1 failing package    pristine: 10 failing packages
REGRESSIONS: none
```

Pristine's ten are all one cause — `internal/synctest` imports `testing/synctest`, which
`go 1.24.1` excludes; raising the directive to 1.27.0 fixes all ten.

### Residual (HR-7)

`integrationtests/self` does not build, **in this fork and in pristine upstream alike**:

```
integrationtests/self/self_go125_test.go:8:19: connState.CurveID undefined
    (type utls.ConnectionState has no field or method CurveID)
```

That test assumes the standard library's `tls.ConnectionState`, which gained `CurveID` in Go 1.25;
utls carries its own `ConnectionState` type and does not expose it. It is an upstream
quic-go-vs-utls mismatch, not a consequence of anything here, and it is not on any path Sightglass
uses. Closing it would mean adding a field to utls's public `ConnectionState`, which is a change to a
TLS library's API surface for the benefit of one integration test — deliberately not done, and
recorded rather than hidden.
