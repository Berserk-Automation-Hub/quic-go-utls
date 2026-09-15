module github.com/Berserk-Automation-Hub/quic-go-utls

go 1.27.0

require (
	github.com/Berserk-Automation-Hub/fhttp v0.6.9-sightglass.1
	github.com/Berserk-Automation-Hub/utls v1.7.8-sightglass.1
	github.com/quic-go/qpack v0.6.0
	github.com/stretchr/testify v1.12.1
	go.uber.org/mock v0.6.0
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	golang.org/x/sync v0.23.0
	golang.org/x/sys v0.48.0
)

require (
	github.com/andybalholm/brotli v1.2.4 // indirect
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/jordanlewis/gcassert v0.0.0-20260313214104-ad3fae17affe // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
)

tool (
	github.com/jordanlewis/gcassert/cmd/gcassert
	go.uber.org/mock/mockgen
)
