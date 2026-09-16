package handshake

// [SIGHTGLASS U-LAYER] Tests for the spec-driven client crypto setup (u_crypto_setup.go).
//
// The point of this file in the library is that the ClientHello bytes come from a
// *tls.ClientHelloSpec instead of from tls.Config. These tests read the ClientHello the setup
// actually produced and check the spec is what shaped it — and that the two things the setup has to
// override on top of the spec (the local TLS version floor, and session events) are in place, both
// of which are invisible in the ClientHello and would otherwise fail much later and much less
// legibly.
//
// The spec here is synthetic and is NOT a browser (HR-1/HR-5): no value in this file is a captured
// fingerprint, and the fork must contain no engine identity.

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	tls "github.com/Berserk-Automation-Hub/utls"

	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/protocol"
	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/utils"
	"github.com/Berserk-Automation-Hub/quic-go-utls/internal/wire"
	"github.com/stretchr/testify/require"
)

func uTestSpecCipherSuites() []uint16 {
	return []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_AES_128_GCM_SHA256}
}

func uTestClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		CipherSuites:       uTestSpecCipherSuites(),
		CompressionMethods: []byte{0},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519}},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256, tls.PKCS1WithSHA256,
			}},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519}}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.ALPNExtension{AlpnProtocols: []string{"u-layer-test"}},
			&tls.QUICTransportParametersExtension{TransportParameters: tls.TransportParameters{
				tls.MaxIdleTimeout(30000),
				tls.InitialMaxData(1 << 20),
				tls.InitialSourceConnectionID{},
			}},
		},
	}
}

// uStartAndTakeClientHello starts the setup and returns the Initial CRYPTO data it emits, i.e. the
// TLS ClientHello handshake message.
func uStartAndTakeClientHello(t *testing.T, cs CryptoSetup) []byte {
	t.Helper()
	require.NoError(t, cs.StartHandshake(context.Background()))
	for {
		ev := cs.NextEvent()
		switch ev.Kind {
		case EventWriteInitialData:
			return ev.Data
		case EventNoEvent:
			t.Fatal("the crypto setup produced no Initial CRYPTO data")
			return nil
		}
	}
}

func uNewSetup(t *testing.T, conf *tls.Config, chs *tls.ClientHelloSpec) CryptoSetup {
	t.Helper()
	cs, err := NewUCryptoSetupClient(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		&wire.TransportParameters{},
		conf,
		false,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("client"),
		protocol.Version1,
		chs,
	)
	require.NoError(t, err)
	t.Cleanup(func() { cs.Close() })
	return cs
}

// TestUCryptoSetupClientHelloComesFromTheSpec: the cipher-suite list is in the ClientHello in clear
// text, in the order the spec gives, and in an order tls.Config can never produce (Go orders its own
// TLS 1.3 suites AES-128, AES-256, ChaCha20). Finding the spec's order on the wire proves
// ApplyPreset drove the hello rather than the Config.
func TestUCryptoSetupClientHelloComesFromTheSpec(t *testing.T) {
	cs := uNewSetup(t, &tls.Config{ServerName: "u-layer.invalid", InsecureSkipVerify: true, NextProtos: []string{"u-layer-test"}}, uTestClientHelloSpec())
	ch := uStartAndTakeClientHello(t, cs)

	require.Equal(t, byte(typeClientHello), ch[0], "the Initial CRYPTO data is not a ClientHello")
	// ClientHello: type(1) len(3) legacy_version(2) random(32) session_id_len(1) session_id
	// cipher_suites_len(2) cipher_suites...
	i := 4 + 2 + 32
	i += 1 + int(ch[i])
	n := int(binary.BigEndian.Uint16(ch[i : i+2]))
	i += 2
	var got []uint16
	for j := 0; j < n; j += 2 {
		got = append(got, binary.BigEndian.Uint16(ch[i+j:i+j+2]))
	}
	require.Equal(t, uTestSpecCipherSuites(), got,
		"the ClientHello's cipher suites are not the spec's, in the spec's order: the hello was built from tls.Config")
}

// TestUCryptoSetupPinsTLS13RegardlessOfTheConfig. RFC 9001 §4.2: QUIC is TLS 1.3 and nothing else.
//
// Two different things can lower the local floor, and the pin has to survive both. The caller's own
// tls.Config may say TLS 1.2 — and so may the SPEC, because utls' ApplyPreset writes a MinVersion
// derived from the spec's supported_versions onto the Config the setup just installed. A profile
// whose supported_versions lists TLS 1.2 alongside TLS 1.3 is an ordinary thing for a browser
// document to carry, and without the pin (or with it applied before ApplyPreset, where ApplyPreset
// overwrites it) the dial dies at StartHandshake with "tls: Config MinVersion must be at least
// TLS 1.13" — an error about a local policy nobody set, before a byte reaches the wire.
//
// The ClientHello bytes come from the spec either way, so the pin changes nothing observable.
func TestUCryptoSetupPinsTLS13RegardlessOfTheConfig(t *testing.T) {
	t.Run("the caller's Config says TLS 1.2", func(t *testing.T) {
		conf := &tls.Config{
			ServerName:         "u-layer.invalid",
			InsecureSkipVerify: true,
			NextProtos:         []string{"u-layer-test"},
			MinVersion:         tls.VersionTLS12,
		}
		cs := uNewSetup(t, conf, uTestClientHelloSpec())
		ch := uStartAndTakeClientHello(t, cs)
		require.Equal(t, byte(typeClientHello), ch[0])
		require.Equalf(t, uint16(tls.VersionTLS12), conf.MinVersion,
			"NewUCryptoSetupClient mutated the CALLER's tls.Config (MinVersion is now 0x%04x); it must clone it first", conf.MinVersion)
	})

	t.Run("the spec's supported_versions lists TLS 1.2", func(t *testing.T) {
		chs := uTestClientHelloSpec()
		var found bool
		for i, e := range chs.Extensions {
			if _, ok := e.(*tls.SupportedVersionsExtension); ok {
				chs.Extensions[i] = &tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}}
				found = true
			}
		}
		require.True(t, found, "the test spec carries no supported_versions extension to widen")

		cs := uNewSetup(t, &tls.Config{ServerName: "u-layer.invalid", InsecureSkipVerify: true, NextProtos: []string{"u-layer-test"}}, chs)
		ch := uStartAndTakeClientHello(t, cs)
		require.Equal(t, byte(typeClientHello), ch[0],
			"a spec whose supported_versions also lists TLS 1.2 produced no ClientHello")
	})
}

// TestUCryptoSetupLoudFailsOnAnUnusableSpec: HR-6. A spec utls cannot apply must produce an error
// from the constructor, not a connection that silently falls back to a Go-shaped ClientHello — which
// would put a fingerprint on the wire belonging to no browser, under a profile that named one.
func TestUCryptoSetupLoudFailsOnAnUnusableSpec(t *testing.T) {
	chs := uTestClientHelloSpec()
	for i, e := range chs.Extensions {
		if _, ok := e.(*tls.KeyShareExtension); ok {
			chs.Extensions[i] = &tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.CurveID(0x9999)}}}
		}
	}
	_, err := NewUCryptoSetupClient(
		protocol.ConnectionID{},
		&wire.TransportParameters{},
		&tls.Config{ServerName: "u-layer.invalid", InsecureSkipVerify: true, NextProtos: []string{"u-layer-test"}},
		false,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger,
		protocol.Version1,
		chs,
	)
	require.Error(t, err, "a ClientHelloSpec utls cannot apply was accepted; the dial would emit a hello the profile never described")
	require.Contains(t, err.Error(), "unsupported Curve in KeyShareExtension")
}

// TestUQUICConnSatisfiesTheSameInterfaceAsUpstream is the widening guard for the ONE upstream file
// this fork modifies: crypto_setup.go's `conn` field. Both the upstream *tls.QUICConn and utls'
// *tls.UQUICConn must satisfy it, or one of the two paths stops compiling.
func TestUQUICConnSatisfiesTheSameInterfaceAsUpstream(t *testing.T) {
	var _ tlsQUICConn = (*tls.QUICConn)(nil)
	var _ tlsQUICConn = uQUICConn{}
	require.NotNil(t, newCryptoSetup)
}

// TestUCryptoSetupStoresAResumptionTicket is the guard for the one QUICConfig flag this constructor
// sets on top of the preset: EnableSessionEvents.
//
// Without it utls fires no QUICStoreSession event, nothing ever reaches the ClientSessionCache, and
// a spec-driven QUIC client dials COLD for the rest of the process's life — which is not a missing
// optimisation but a fingerprint: a browser that has talked to an origin emits its RESUMPTION
// ClientHello (pre_shared_key + early_data) on the next connection, and a parrot that always sends
// the cold one is distinguishable from the browser on every visit after the first.
//
// It runs a real handshake between the spec-driven client and a stock quic-go server, then a second
// one, and checks that the second resumed.
func TestUCryptoSetupStoresAResumptionTicket(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	csc := newMockClientSessionCache()
	clientConf.ClientSessionCache = csc

	handshakeOnce := func(t *testing.T) (CryptoSetup, CryptoSetup) {
		t.Helper()
		chs := uTestClientHelloSpec()
		for i, e := range chs.Extensions {
			if _, ok := e.(*tls.ALPNExtension); ok {
				chs.Extensions[i] = &tls.ALPNExtension{AlpnProtocols: clientConf.NextProtos}
			}
		}
		client, err := NewUCryptoSetupClient(
			protocol.ConnectionID{},
			&wire.TransportParameters{ActiveConnectionIDLimit: 2},
			clientConf,
			false,
			utils.NewRTTStats(),
			nil,
			utils.DefaultLogger.WithPrefix("client"),
			protocol.Version1,
			chs,
		)
		require.NoError(t, err)
		var token protocol.StatelessResetToken
		server := NewCryptoSetupServer(
			protocol.ConnectionID{},
			&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
			&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
			&wire.TransportParameters{ActiveConnectionIDLimit: 2, StatelessResetToken: &token},
			serverConf,
			false,
			utils.NewRTTStats(),
			nil,
			utils.DefaultLogger.WithPrefix("server"),
			protocol.Version1,
		)
		_, clientErr, _, serverErr := handshake(t, client, server)
		require.NoError(t, clientErr)
		require.NoError(t, serverErr)
		return client, server
	}

	client, server := handshakeOnce(t)
	select {
	case st := <-csc.puts:
		require.NotNil(t, st, "a nil session state was cached")
		// The ticket must carry quic-go's own blob (the peer's QUIC transport parameters and RTT),
		// which only reaches it through the QUICStoreSession event. utls caches the TLS session
		// either way, so a ticket with no Extra looks stored and is useless: quic-go cannot send
		// 0-RTT without the peer parameters, and the parrot dials cold forever.
		_, state, err := st.ResumptionState()
		require.NoError(t, err)
		require.NotEmptyf(t, state.Extra,
			"the cached session carries no quic-go session data: no QUICStoreSession event fired, so 0-RTT is structurally impossible on this connection")
	case <-time.After(time.Second):
		t.Fatal("the spec-driven client never stored a session ticket: no QUICStoreSession event fired, so every future connection to this origin dials cold and emits the cold ClientHello a browser would only send once")
	}
	require.False(t, client.ConnectionState().DidResume, "the first handshake cannot have resumed anything")
	require.False(t, server.ConnectionState().DidResume)

	// OFFERING the stored ticket back is a property of the SPEC, not of this constructor: the
	// resumption ClientHello needs a pre_shared_key extension, which the profile puts in the
	// ClientHelloSpec (the synthetic spec here deliberately has none). What this constructor owns is
	// that there is a ticket to offer at all, which is what the assertion above measures. A second
	// handshake with this spec therefore still dials cold, and says so.
	client, _ = handshakeOnce(t)
	require.Falsef(t, client.ConnectionState().DidResume,
		"a spec with no pre_shared_key extension resumed; this test can no longer tell storing a ticket from offering one")
	select {
	case <-csc.puts:
	case <-time.After(time.Second):
		t.Fatal("the second spec-driven handshake stored no ticket either")
	}
}
