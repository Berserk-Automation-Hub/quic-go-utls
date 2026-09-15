package quic

import "github.com/bogdanfinn/quic-go-utls/internal/protocol"

// U-LAYER (additive): browser-pinned UDP socket buffer sizes.
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
// instead of inheriting the library's. SetDesiredBufferSizes must be called BEFORE the Transport
// is created — wrapConn() reads the values once, when the connection is wrapped.
func SetDesiredBufferSizes(receive, send int) {
	if receive > 0 {
		protocol.SetDesiredReceiveBufferSize(receive)
	}
	if send > 0 {
		protocol.SetDesiredSendBufferSize(send)
	}
}

// DesiredBufferSizes returns the currently configured SO_RCVBUF / SO_SNDBUF targets.
func DesiredBufferSizes() (receive, send int) {
	return protocol.DesiredReceiveBufferSize(), protocol.DesiredSendBufferSize()
}
