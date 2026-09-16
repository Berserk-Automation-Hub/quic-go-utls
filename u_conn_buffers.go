package quic

// U-LAYER (additive): browser-pinned UDP socket buffer sizes, owned by the Transport that owns the
// socket.
//
// Upstream quic-go asks the kernel for a 7 MB SO_RCVBUF and a 7 MB SO_SNDBUF on every QUIC socket
// (internal/protocol/params.go). Chrome does not: it pins both, to different values —
//
//	SO_RCVBUF = kQuicSocketReceiveBufferSize        = 1024*1024 = 1048576 bytes
//	            net/quic/quic_context.h:105, applied at net/quic/quic_session_pool.cc:1212/1327
//	SO_SNDBUF = quic::kMaxOutgoingPacketSize * 20   = 1452*20   =   29040 bytes
//	            net/quic/quic_session_pool.cc:1237/1349 (kMaxOutgoingPacketSize == kMaxV6PacketSize)
//
// These are the only two UDP socket options an application actually chooses (everything else about
// the datagram is the kernel's), so a byte-exact browser parrot pins them to the browser's values
// instead of inheriting the library's. The VALUES live in the profile, never here (HR-5): set them
// on Transport.UDesiredReceiveBufferSize / Transport.UDesiredSendBufferSize before the Transport is
// used, and the socket that Transport wraps gets those and no other socket does.
//
// THERE IS DELIBERATELY NO PACKAGE-LEVEL SETTER. An earlier revision of this file exported
// SetDesiredBufferSizes(receive, send int), which wrote two package globals in internal/protocol.
// That was wrong twice over: it was an unsynchronised write racing every concurrent dial's read, and
// — worse, because a race detector never sees it on a single-profile run — with two profiles in one
// process a connection could be wrapped with the OTHER profile's SO_RCVBUF/SO_SNDBUF. Per-session
// statelessness is not a preference here; it is the mandate. The values now travel on the Transport
// and nowhere else, which is why TestUTransportSocketBuffersAreNotProcessGlobal can exist at all.

// UDoNotSetSocketBuffer is the Transport.UDesiredReceiveBufferSize / UDesiredSendBufferSize value
// that means "this profile declares no socket buffer of its own".
//
// Sightglass expresses the two profile fields as *int, and an ABSENT field means the application
// made no choice — so the option must be left at the kernel default and no setsockopt issued at
// all. It is distinct from the zero value, which is the field's own absence and keeps upstream
// quic-go's 7 MB behaviour for a plain upstream Transport that has never heard of the u-layer.
// Substituting quic-go's 7 MB for a value the capture never showed would be exactly the kind of
// invented fingerprint HR-6 forbids.
const UDoNotSetSocketBuffer = -1
